"""Generate and inspect an F-Droid catalogue from staged, verified APKs.

Copies staged APKs whose exact promotion records are known into a work
directory, runs pinned fdroidserver `fdroid update --pretty`, and checks the
resulting index against the records and the package policy. Without a signing
configuration the index is UNSIGNED and carries an ephemeral placeholder public
key; it is a preview artifact, never a deployable catalogue. Never deploys.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

from verify_apk import Rejected, require, validate_record

SIGNING_KEYS = ("repo_keyalias", "keystore", "keystorepass", "keypass")
SECRET_SUFFIXES = (".jks", ".p12", ".keystore", ".pem", ".key")


def command(*args, cwd=None, timeout=600):
    return subprocess.run(args, check=True, text=True, capture_output=True,
                          timeout=timeout, cwd=cwd).stdout


def load_config(path):
    import yaml  # provided by fdroidserver; only needed for signed builds
    config = yaml.safe_load(path.read_text())
    require(isinstance(config, dict), "config.yml must be a mapping")
    return config


def signing_mode(config, base):
    """Return True for a signed build, False for unsigned; fail closed on partial setup."""
    present = [key for key in SIGNING_KEYS if config.get(key)]
    if not present:
        return False
    missing = [key for key in SIGNING_KEYS if not config.get(key)]
    require(not missing, f"Incomplete signing configuration, missing {', '.join(missing)}")
    keystore = Path(config["keystore"])
    if not keystore.is_absolute():
        keystore = base / keystore
    require(keystore.is_file(), f"Configured keystore is missing: {config['keystore']}")
    config["keystore"] = str(keystore)
    return True


def ephemeral_pubkey(keytool, scratch):
    """Create a throwaway certificate so fdroidserver can emit an unsigned index.

    The private key is discarded with the scratch directory. The fingerprint that
    ends up in the unsigned index is NOT the repository key and must never be
    published as one.
    """
    store = scratch / "ephemeral-preview.p12"
    dname = "CN=UNSIGNED PREVIEW PLACEHOLDER - NOT THE REPOSITORY KEY"
    command(keytool, "-genkeypair", "-keystore", str(store), "-storetype", "PKCS12",
            "-storepass", "ephemeral", "-keypass", "ephemeral", "-alias", "preview",
            "-keyalg", "RSA", "-keysize", "2048", "-validity", "1", "-dname", dname)
    certificate = scratch / "ephemeral-preview.der"
    command(keytool, "-exportcert", "-keystore", str(store), "-storepass", "ephemeral",
            "-alias", "preview", "-file", str(certificate))
    return certificate.read_bytes().hex()


def dump_yaml(values):
    lines = []
    for key, value in values.items():
        if isinstance(value, bool):
            lines.append(f"{key}: {'true' if value else 'false'}")
        elif isinstance(value, int):
            lines.append(f"{key}: {value}")
        else:
            lines.append(f"{key}: {json.dumps(str(value))}")
    return "\n".join(lines) + "\n"


def match_records(staging, policy, history, records):
    """Map each staged APK to exactly one validated, publishable record."""
    known = {(r["package"], r["version_code"]): r for r in history}
    for record in records:
        key = (record["package"], record["version_code"])
        require(key not in known or known[key]["sha256"] == record["sha256"],
                "Promotion record conflicts with history")
        known[key] = record
    apks = sorted(p for p in staging.glob("*.apk") if not p.is_symlink())
    require(apks, "No staged APKs to catalogue")
    matched = []
    for apk in apks:
        package, _, version = apk.stem.rpartition("_")
        require(version.isdigit() and package, f"Unexpected staged file name: {apk.name}")
        record = known.get((package, int(version)))
        require(record is not None, f"No promotion record for {apk.name}")
        validate_record(record, policy, history)
        require(policy[package].get("published") is True,
                f"Package is not in the published allowlist: {package}")
        with apk.open("rb") as handle:
            digest = hashlib.file_digest(handle, "sha256").hexdigest()
        require(digest == record["sha256"], f"Staged APK hash mismatch: {apk.name}")
        matched.append((apk, record))
    return matched


def prepare_workdir(workdir, metadata, matched, config):
    require(not workdir.exists() or workdir.is_dir(), "Work directory is not a directory")
    repo = workdir / "repo"
    if repo.exists():
        for stale in repo.iterdir():
            if stale.is_file() and stale.suffix == ".apk" and stale.name not in {
                    apk.name for apk, _ in matched}:
                raise Rejected(f"Unexpected APK in work repo: {stale.name}")
    repo.mkdir(parents=True, exist_ok=True)
    for name, source in (("metadata", metadata), ("config", metadata.with_name("config"))):
        target = workdir / name
        if target.exists():
            shutil.rmtree(target)
        if source.is_dir():
            shutil.copytree(source, target)
    for apk, _ in matched:
        target = repo / apk.name
        if target.exists():
            with target.open("rb") as handle:
                require(hashlib.file_digest(handle, "sha256").hexdigest() ==
                        hashlib.sha256(apk.read_bytes()).hexdigest(),
                        f"Work repo already holds different bytes for {apk.name}")
        else:
            shutil.copyfile(apk, target)
    (workdir / "config.yml").write_text(dump_yaml(config))
    return repo


def inspect_index(repo, matched, policy, signed):
    index = json.loads((repo / "index-v1.json").read_text())
    expected = {(record["package"], record["version_code"]): (apk, record) for apk, record in matched}
    seen = set()
    for package, versions in index.get("packages", {}).items():
        require(policy.get(package, {}).get("published") is True,
                f"Index lists a package outside the published allowlist: {package}")
        for entry in versions:
            key = (entry["packageName"], entry["versionCode"])
            require(key in expected, f"Index lists an unexpected version: {key}")
            apk, record = expected[key]
            require(entry.get("hashType") == "sha256" and entry.get("hash") == record["sha256"],
                    f"Index hash mismatch for {apk.name}")
            require(entry.get("apkName") == apk.name, f"Index file name mismatch for {apk.name}")
            listed = repo / entry["apkName"]
            with listed.open("rb") as handle:
                require(hashlib.file_digest(handle, "sha256").hexdigest() == record["sha256"],
                        f"Indexed file bytes differ for {apk.name}")
            require(entry.get("signer", "").lower() == policy[package]["certificate_sha256"],
                    f"Index signer mismatch for {apk.name}")
            record["version_name"] = entry.get("versionName")
            seen.add(key)
    missing = set(expected) - seen
    require(not missing, f"Staged APKs missing from index: {sorted(missing)}")
    apps = {app["packageName"]: app for app in index.get("apps", [])}
    require(set(apps) == {package for package, _ in expected},
            "Index apps do not match the staged packages")
    for package, app in apps.items():
        suggested = app.get("suggestedVersionCode")
        require(suggested is not None and (package, int(suggested)) in expected,
                f"Suggested version for {package} is not a staged version")
    for path in repo.rglob("*"):
        require(path.name != "config.yml" and path.suffix not in SECRET_SUFFIXES,
                f"Secret-looking file inside repo output: {path.name}")
    for name in ("index-v1.json", "index-v2.json", "entry.json"):
        require((repo / name).is_file(), f"fdroid update did not produce {name}")
    jars = [repo / "index-v1.jar", repo / "entry.jar"]
    if signed:
        require(all(jar.is_file() for jar in jars), "Signed index files were not produced")
    else:
        require(not any(jar.exists() for jar in jars), "Unsigned build produced signed index files")
    return index, apps


def summary(index, apps, matched, signed):
    repo = index.get("repo", {})
    lines = [f"Catalogue: {repo.get('name')} ({'SIGNED' if signed else 'UNSIGNED preview'})",
             f"Address: {repo.get('address')}"]
    if not signed:
        lines.append("Index fingerprint is an ephemeral placeholder, not the repository key.")
    for package, app in sorted(apps.items()):
        lines.append(f"{package}: {app.get('name')} suggested {app.get('suggestedVersionCode')}")
        for apk, record in matched:
            if record["package"] == package:
                lines.append(f"  {apk.name} version {record.get('version_name')} "
                             f"sha256 {record['sha256']} commit {record['commit']}")
    return "\n".join(lines)


def build(staging, metadata, policy, history, records, workdir, config, fdroid="fdroid",
          keytool="keytool", runner=command):
    matched = match_records(staging, policy, history, records)
    config = dict(config)
    signed = signing_mode(config, Path.cwd())
    with tempfile.TemporaryDirectory() as scratch:
        if not signed:
            config["repo_pubkey"] = ephemeral_pubkey(keytool, Path(scratch))
        repo = prepare_workdir(workdir, metadata, matched, config)
        args = [fdroid, "update", "--pretty"] + ([] if signed else ["--nosign"])
        runner(*args, cwd=str(workdir))
    index, apps = inspect_index(repo, matched, policy, signed)
    return summary(index, apps, matched, signed), signed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--staging", type=Path, default=Path("staging"))
    parser.add_argument("--history", type=Path, required=True)
    parser.add_argument("--record", type=Path, action="append", default=[],
                        help="Exact promotion record JSON not yet in history (repeatable)")
    parser.add_argument("--policy", type=Path, default=Path(__file__).with_name("apps.json"))
    parser.add_argument("--metadata", type=Path, default=Path(__file__).with_name("metadata"))
    parser.add_argument("--workdir", type=Path, default=Path("build"))
    parser.add_argument("--config", type=Path,
                        help="Publisher config.yml; omit for an unsigned preview")
    parser.add_argument("--fdroid", default="fdroid")
    parser.add_argument("--keytool", default="keytool")
    args = parser.parse_args()
    if args.config:
        config = load_config(args.config)
        signing_mode(config, args.config.resolve().parent)
    else:
        config = load_config(Path(__file__).with_name("config.yml.example"))
        require(not any(config.get(key) for key in SIGNING_KEYS),
                "config.yml.example must not configure a key")
    result, signed = build(args.staging, args.metadata, json.loads(args.policy.read_text()),
                           json.loads(args.history.read_text()),
                           [json.loads(path.read_text()) for path in args.record],
                           args.workdir, config, args.fdroid, args.keytool)
    print(result)


if __name__ == "__main__":
    main()
