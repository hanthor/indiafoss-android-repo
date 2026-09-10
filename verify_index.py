"""Verify a generated F-Droid catalogue against the recorded repository fingerprint.

Given a `repo/` directory (from `build_catalogue.py`, a downloaded catalogue or
the artifact of the unsigned-catalogue job) this checks, in order:

* `entry.jar` carries exactly one signer certificate whose SHA-256 fingerprint
  equals `repository.fingerprint` in `apps.json`, and `jarsigner -strict -verify`
  accepts its JAR signature. `index-v1.jar` (and any other `*.jar`) must be
  signed by the same certificate; `index-v1.jar` is allowed the SHA-1 digest
  that fdroidserver still uses for old clients, `entry.jar` is not.
* The signed `entry.json`/`index-v1.json` inside the JARs are byte-identical to
  the plain files next to them, and `entry.json` names `index-v2.json` with its
  actual SHA-256 and size, so the whole chain from the signature to every APK
  hash is covered.
* Every version in `index-v2.json` (and `index-v1.json`) is an exact promotion
  record from `history.json` or `--record`, the file exists with those bytes,
  the APK signer is the policy certificate, version codes are distinct and
  increasing, and every promoted version of a published package is listed.

Without a recorded fingerprint the catalogue is reported as UNSIGNED and the
command fails, unless `--expect-unsigned` is given for a preview artifact, in
which case it must contain no signed index files. `--deployable` additionally
refuses `status/`, secret-looking files and anything outside the public set.
Read-only; never signs or deploys.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import zipfile

from verify_apk import Rejected, digest, require, validate_record

REPOSITORY_KEY = "repository"
SIGNATURE_BLOCK_SUFFIXES = (".RSA", ".EC", ".DSA")
SECRET_SUFFIXES = (".jks", ".p12", ".keystore", ".pem", ".key")
PUBLIC_FILES = {"entry.jar", "entry.json", "index-v2.json", "index-v1.jar", "index-v1.json",
                "index.jar", "index.xml", "index.html", "index.css", "index.png"}
PUBLIC_DIRECTORIES = re.compile(r"^icons(-\d+)?$")
PKCS7_SIGNED_DATA = bytes.fromhex("06092a864886f70d010702")
DEPRECATED_JAR_ALGORITHMS = "jdk.jar.disabledAlgorithms=MD2, RSA keySize < 1024"


class Unsigned(Exception):
    """The catalogue has no recorded repository fingerprint to verify against."""


def sha256_file(path):
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def repository_policy(policy):
    """Return (address, fingerprint) recorded in the policy; empty strings when absent."""
    repository = policy.get(REPOSITORY_KEY) or {}
    require(isinstance(repository, dict), "repository policy must be a mapping")
    address = repository.get("address") or ""
    fingerprint = repository.get("fingerprint") or ""
    require(isinstance(address, str) and isinstance(fingerprint, str),
            "repository address and fingerprint must be strings")
    require(fingerprint == "" or digest(fingerprint),
            "repository.fingerprint must be 64 lowercase hex characters or empty")
    return address, fingerprint


def packages_in(policy):
    return {name: entry for name, entry in policy.items() if name != REPOSITORY_KEY}


# --- JAR signature block parsing (DER) ------------------------------------

def _tlv(buffer, position):
    """Return (tag, content start, content length) of the DER element at position."""
    require(position + 2 <= len(buffer), "Truncated DER element")
    tag = buffer[position]
    length = buffer[position + 1]
    position += 2
    if length & 0x80:
        count = length & 0x7F
        require(0 < count <= 4 and position + count <= len(buffer), "Invalid DER length")
        length = int.from_bytes(buffer[position:position + count], "big")
        position += count
    require(position + length <= len(buffer), "DER element exceeds buffer")
    return tag, position, length


def _children(buffer, start, end):
    position = start
    while position < end:
        tag, content, length = _tlv(buffer, position)
        yield tag, position, content, length
        position = content + length
    require(position == end, "Malformed DER sequence")


def signer_certificates(block):
    """Return the DER certificates carried by a PKCS#7 SignedData signature block."""
    tag, content, length = _tlv(block, 0)
    require(tag == 0x30 and content + length == len(block), "Signature block is not a SEQUENCE")
    outer = list(_children(block, content, content + length))
    require(len(outer) == 2 and outer[0][0] == 0x06 and
            block[outer[0][1]:outer[0][2] + outer[0][3]] == PKCS7_SIGNED_DATA and
            outer[1][0] == 0xA0, "Signature block is not PKCS#7 signedData")
    signed_data_tag, signed_data, signed_data_length = _tlv(block, outer[1][2])
    require(signed_data_tag == 0x30, "Malformed SignedData")
    certificate_sets = [child for child in
                        _children(block, signed_data, signed_data + signed_data_length)
                        if child[0] == 0xA0]
    require(len(certificate_sets) == 1, "Signature block carries no certificate set")
    _, _, certificates, certificates_length = certificate_sets[0]
    found = []
    for tag, start, content, length in _children(block, certificates,
                                                 certificates + certificates_length):
        require(tag == 0x30, "Unsupported certificate encoding")
        found.append(block[start:content + length])
    return found


def parse_manifest(text):
    """Return {name: {attribute: value}} for the named sections of a JAR manifest."""
    sections = {}
    current = None
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    unfolded = []
    for line in lines:
        if line.startswith(" ") and unfolded:
            unfolded[-1] += line[1:]
        else:
            unfolded.append(line)
    for line in unfolded:
        if not line:
            current = None
            continue
        key, _, value = line.partition(": ")
        if key == "Name":
            current = sections.setdefault(value, {})
        elif current is not None:
            current[key] = value
    return sections


def inspect_jar(jar, payload):
    """Check the JAR's structure and return (payload bytes, signer certificate DER).

    Confirms there is exactly one signature (one .SF with its block), the manifest
    digest of `payload` matches its bytes, the signature file digests the
    manifest, and the signature block carries exactly one certificate. The
    cryptographic signature itself is checked separately by jarsigner.
    """
    require(zipfile.is_zipfile(jar), f"{jar.name} is not a JAR")
    with zipfile.ZipFile(jar) as archive:
        names = [name for name in archive.namelist() if not name.endswith("/")]
        require(names.count(payload) == 1, f"{jar.name} must contain exactly one {payload}")
        require("META-INF/MANIFEST.MF" in names, f"{jar.name} is not signed (no manifest)")
        signature_files = [name for name in names if name.startswith("META-INF/") and
                           name.endswith(".SF")]
        blocks = [name for name in names if name.startswith("META-INF/") and
                  name.endswith(SIGNATURE_BLOCK_SUFFIXES)]
        require(len(signature_files) == 1 and len(blocks) == 1 and
                signature_files[0].rsplit(".", 1)[0] == blocks[0].rsplit(".", 1)[0],
                f"{jar.name} must carry exactly one JAR signature")
        others = set(names) - {payload, "META-INF/MANIFEST.MF", signature_files[0], blocks[0]}
        require(not others, f"{jar.name} contains unexpected entries: {sorted(others)}")
        manifest_bytes = archive.read("META-INF/MANIFEST.MF")
        content = archive.read(payload)
        signature_file = parse_manifest(archive.read(signature_files[0]).decode("utf-8"))
        block = archive.read(blocks[0])
    manifest = parse_manifest(manifest_bytes.decode("utf-8"))
    entry = manifest.get(payload, {})
    algorithms = [(key, value) for key, value in entry.items() if key.endswith("-Digest")]
    require(algorithms, f"{jar.name} manifest does not digest {payload}")
    for key, value in algorithms:
        algorithm = key[:-len("-Digest")].replace("-", "").lower()
        require(algorithm in ("sha256", "sha1"), f"Unsupported manifest digest {key}")
        require(base64.b64decode(value) == hashlib.new(algorithm, content).digest(),
                f"{jar.name} manifest digest does not match {payload}")
    signed_entry = signature_file.get(payload, {})
    require(any(key.endswith("-Digest") for key in signed_entry),
            f"{jar.name} signature file does not cover {payload}")
    certificates = signer_certificates(block)
    require(len(certificates) == 1, f"{jar.name} must be signed by exactly one certificate")
    return content, certificates[0]


def jarsigner_verify(jarsigner, jar, allow_deprecated=False):
    """Run `jarsigner -strict -verify`; only exit status 4 means a verified self-signed JAR.

    jarsigner exits 0 for unsigned JARs, so 0 is a failure here. Index-v1 JARs
    are signed with SHA-1 by fdroidserver for old Android clients; verifying
    those needs the same java.security override fdroidserver uses.
    """
    with tempfile.TemporaryDirectory() as scratch:
        args = [jarsigner]
        if allow_deprecated:
            security = Path(scratch) / "java.security"
            security.write_text(DEPRECATED_JAR_ALGORITHMS + "\n")
            os.chmod(security, 0o400)
            args.append(f"-J-Djava.security.properties={security}")
        args += ["-strict", "-verify", str(jar)]
        completed = subprocess.run(args, capture_output=True, text=True, timeout=120)
    output = (completed.stdout + completed.stderr).strip()
    require(completed.returncode == 4 and "jar verified" in output,
            f"JAR signature failed to verify: {jar.name} (exit {completed.returncode})\n{output}")
    return output


# --- Catalogue content ----------------------------------------------------

def load_index(repo, name):
    path = repo / name
    require(path.is_file() and not path.is_symlink(), f"Missing {name}")
    return json.loads(path.read_text())


def promoted_versions(policy, history, records):
    """Return {(package, version_code): record} after validating history order."""
    packages = packages_in(policy)
    known = {}
    latest = {}
    for record in history:
        validate_record(record, packages, [])
        key = (record["package"], record["version_code"])
        require(key not in known, f"Duplicate history record for {key}")
        require(record["version_code"] > latest.get(record["package"], 0),
                f"History version codes are not increasing for {record['package']}")
        latest[record["package"]] = record["version_code"]
        known[key] = record
    for record in records:
        validate_record(record, packages, history)
        key = (record["package"], record["version_code"])
        require(key not in known or known[key]["sha256"] == record["sha256"],
                "Promotion record conflicts with history")
        known[key] = record
    return known


def check_versions(repo, index, policy, known):
    """Check every listed version of index-v2 against files, records and policy."""
    packages = packages_in(policy)
    listed = {}
    for package, data in index.get("packages", {}).items():
        require(packages.get(package, {}).get("published") is True,
                f"Index lists a package outside the published allowlist: {package}")
        versions = data.get("versions", {})
        require(versions, f"Index lists {package} without versions")
        codes = []
        for version_hash, version in versions.items():
            file = version.get("file", {})
            manifest = version.get("manifest", {})
            code = manifest.get("versionCode")
            require(type(code) is int, f"Missing versionCode for {package}")
            record = known.get((package, code))
            require(record is not None, f"No promotion record for {package} {code}")
            name = file.get("name", "")
            require(name == f"/{package}_{code}.apk", f"Unexpected file name {name}")
            path = repo / name.lstrip("/")
            require(path.is_file() and not path.is_symlink(), f"Listed APK is missing: {name}")
            actual = sha256_file(path)
            require(version_hash == file.get("sha256") == record["sha256"] == actual,
                    f"APK hash mismatch for {name}")
            require(file.get("size") == path.stat().st_size, f"APK size mismatch for {name}")
            require(manifest.get("signer", {}).get("sha256") ==
                    [packages[package]["certificate_sha256"]],
                    f"APK signer mismatch for {name}")
            codes.append(code)
            listed[(package, code)] = actual
        require(len(codes) == len(set(codes)), f"Duplicate version codes for {package}")
        promoted = {code for (name, code) in known if name == package}
        require(set(codes) == promoted,
                f"Index versions for {package} differ from promoted versions: "
                f"listed {sorted(codes)}, promoted {sorted(promoted)}")
    expected = {key for key in known if packages.get(key[0], {}).get("published") is True}
    require(set(listed) == expected, f"Promoted published versions missing from index: "
                                     f"{sorted(expected - set(listed))}")
    stray = sorted(apk.name for apk in repo.glob("*.apk")
                   if apk.name not in {f"{p}_{c}.apk" for p, c in listed})
    require(not stray, f"APKs in repo not listed in the index: {stray}")
    return listed


def check_index_v1(index, listed, packages):
    """index-v1.json must describe the same versions and hashes as index-v2."""
    seen = set()
    for package, versions in index.get("packages", {}).items():
        for entry in versions:
            key = (package, entry.get("versionCode"))
            require(key in listed and entry.get("hashType") == "sha256" and
                    entry.get("hash") == listed[key] and
                    entry.get("signer", "").lower() == packages[package]["certificate_sha256"],
                    f"index-v1 disagrees with index-v2 for {key}")
            seen.add(key)
    require(seen == set(listed), "index-v1 lists different versions than index-v2")
    apps = {app.get("packageName"): app for app in index.get("apps", [])}
    require(set(apps) == {package for package, _ in listed}, "index-v1 apps mismatch")
    for package, app in apps.items():
        suggested = app.get("suggestedVersionCode")
        require(suggested is not None and (package, int(suggested)) in listed,
                f"index-v1 suggests an unlisted version for {package}")


def check_public_files(repo, deployable):
    for path in repo.rglob("*"):
        require(not path.is_symlink(), f"Symlink in repo output: {path.name}")
        require(path.name != "config.yml" and path.suffix not in SECRET_SUFFIXES,
                f"Secret-looking file inside repo output: {path.name}")
    if not deployable:
        return
    for path in repo.iterdir():
        if path.is_dir():
            require(PUBLIC_DIRECTORIES.match(path.name), f"Not deployable: {path.name}/")
        else:
            require(path.name in PUBLIC_FILES or (path.suffix == ".apk" and "_" in path.stem),
                    f"Not deployable: {path.name}")


def verify_repo(repo, policy, history, records, jar_verifier, expect_unsigned=False,
                deployable=False):
    """Verify the catalogue in `repo`; return report lines or raise Rejected/Unsigned."""
    require(repo.is_dir(), f"Not a directory: {repo}")
    address, fingerprint = repository_policy(policy)
    known = promoted_versions(policy, history, records)
    entry = load_index(repo, "entry.json")
    index = load_index(repo, "index-v2.json")
    index_v1 = load_index(repo, "index-v1.json")
    require(entry.get("index", {}).get("name") == "/index-v2.json", "entry.json does not name index-v2.json")
    require(entry["index"].get("sha256") == sha256_file(repo / "index-v2.json") and
            entry["index"].get("size") == (repo / "index-v2.json").stat().st_size,
            "entry.json does not match index-v2.json")
    require(not address or index.get("repo", {}).get("address") == address,
            f"Index address {index.get('repo', {}).get('address')} is not the recorded {address}")
    listed = check_versions(repo, index, policy, known)
    check_index_v1(index_v1, listed, packages_in(policy))
    check_public_files(repo, deployable)
    jars = sorted(path for path in repo.glob("*.jar") if path.is_file())
    lines = [f"Address: {index.get('repo', {}).get('address')}",
             f"Versions: {', '.join(f'{p} {c}' for p, c in sorted(listed))}"]
    if not fingerprint:
        if not expect_unsigned:
            raise Unsigned("UNSIGNED CATALOGUE: apps.json records no repository.fingerprint, "
                           "so the index signature cannot be verified. Refusing to pass.")
        for jar in jars:
            with zipfile.ZipFile(jar) as archive:
                signed = [name for name in archive.namelist() if name.startswith("META-INF/") and
                          name.endswith((".SF",) + SIGNATURE_BLOCK_SUFFIXES)]
            require(jar.name == "index_unsigned.jar" and not signed,
                    f"Unsigned preview must not contain signed index files: {jar.name}")
        lines.append("UNSIGNED preview: no repository fingerprint recorded; content checks passed, "
                     "index signature NOT verified.")
        return lines
    require(not expect_unsigned, "A fingerprint is recorded; do not use --expect-unsigned")
    require((repo / "entry.jar").is_file(), "Signed catalogue is missing entry.jar")
    for jar in jars:
        payload = {"entry.jar": "entry.json", "index-v1.jar": "index-v1.json"}.get(jar.name)
        if payload is None:
            require(jar.name == "index.jar", f"Unexpected JAR in repo: {jar.name}")
            payload = "index.xml"
        content, certificate = inspect_jar(jar, payload)
        actual = hashlib.sha256(certificate).hexdigest()
        require(actual == fingerprint,
                f"{jar.name} is signed by {actual}, not the recorded fingerprint {fingerprint}")
        require(content == (repo / payload).read_bytes(),
                f"{payload} on disk differs from the signed copy in {jar.name}")
        if jar.name in ("entry.jar", "index-v1.jar"):
            jar_verifier(jar, jar.name == "index-v1.jar")
            lines.append(f"{jar.name}: signature verified, fingerprint {fingerprint}")
        else:
            lines.append(f"{jar.name}: legacy index, certificate matches fingerprint")
    lines.append(f"SIGNED catalogue verified against fingerprint {fingerprint}")
    return lines


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("repo", type=Path, help="Generated or downloaded repo/ directory")
    parser.add_argument("--policy", type=Path, default=Path(__file__).with_name("apps.json"))
    parser.add_argument("--history", type=Path, required=True)
    parser.add_argument("--record", type=Path, action="append", default=[],
                        help="Exact promotion record JSON not yet in history (repeatable)")
    parser.add_argument("--expect-unsigned", action="store_true",
                        help="Accept an unsigned preview (no fingerprint recorded, no JARs)")
    parser.add_argument("--deployable", action="store_true",
                        help="Also refuse files that must not reach GitHub Pages")
    parser.add_argument("--jarsigner", default="jarsigner")
    args = parser.parse_args()
    try:
        lines = verify_repo(args.repo, json.loads(args.policy.read_text()),
                            json.loads(args.history.read_text()),
                            [json.loads(path.read_text()) for path in args.record],
                            lambda jar, deprecated: jarsigner_verify(args.jarsigner, jar, deprecated),
                            args.expect_unsigned, args.deployable)
    except Unsigned as reason:
        print(reason)
        sys.exit(2)
    except Rejected as reason:
        print(f"REJECTED: {reason}")
        sys.exit(1)
    print("\n".join(lines))


if __name__ == "__main__":
    main()
