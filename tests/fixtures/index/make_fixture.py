"""Regenerate the signed catalogue fixture with a throwaway key (needs keytool and jarsigner).

Writes repo/ (entry.jar, entry.json, index-v2.json, index-v1.jar, index-v1.json),
other-entry.jar (signed by a second, discarded key) and policy.json carrying the
fixture key's fingerprint. Both keys are created in a temporary directory and
deleted; nothing here is an IndiaFOSS key. The "APKs" are the bytes returned by
`payload()`, which the tests recreate, never real Android packages.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import zipfile

HERE = Path(__file__).resolve().parent
PACKAGE = "org.example.app"
CERT = "a" * 64
VERSIONS = [(1, "1.0"), (2, "2.0")]
TIMESTAMP = 1789000000000
ADDRESS = "https://example.org/fdroid/repo"


def payload(package, code):
    return f"fixture APK bytes for {package} version {code}\n".encode()


def run(*args):
    subprocess.run(args, check=True, capture_output=True, text=True)


def keystore(scratch, name, dname):
    store = scratch / f"{name}.p12"
    run("keytool", "-genkeypair", "-keystore", str(store), "-storetype", "PKCS12",
        "-storepass", "fixture", "-keypass", "fixture", "-alias", name, "-keyalg", "RSA",
        "-keysize", "2048", "-validity", "36500", "-dname", dname)
    certificate = scratch / f"{name}.der"
    run("keytool", "-exportcert", "-keystore", str(store), "-storepass", "fixture",
        "-alias", name, "-file", str(certificate))
    return store, hashlib.sha256(certificate.read_bytes()).hexdigest()


def sign(store, alias, jar, payload_name, content, deprecated=False):
    jar.unlink(missing_ok=True)
    with zipfile.ZipFile(jar, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(zipfile.ZipInfo(payload_name, (2026, 1, 1, 0, 0, 0)), content)
    algorithms = ["-digestalg", "SHA1", "-sigalg", "SHA1withRSA"] if deprecated else \
        ["-digestalg", "SHA-256", "-sigalg", "SHA256withRSA"]
    run("jarsigner", "-keystore", str(store), "-storepass", "fixture", "-keypass", "fixture",
        *algorithms, str(jar), alias)


def main():
    repo = HERE / "repo"
    repo.mkdir(exist_ok=True)
    versions_v2, versions_v1 = {}, []
    for code, name in VERSIONS:
        content = payload(PACKAGE, code)
        digest = hashlib.sha256(content).hexdigest()
        file_name = f"{PACKAGE}_{code}.apk"
        versions_v2[digest] = {
            "added": TIMESTAMP,
            "file": {"name": f"/{file_name}", "sha256": digest, "size": len(content)},
            "manifest": {"versionName": name, "versionCode": code,
                         "signer": {"sha256": [CERT]}}}
        versions_v1.append({"added": TIMESTAMP, "apkName": file_name, "hash": digest,
                            "hashType": "sha256", "packageName": PACKAGE, "signer": CERT,
                            "size": len(content), "versionCode": code, "versionName": name})
    index_v2 = {
        "repo": {"name": {"en-US": "Fixture"}, "description": {"en-US": "Signed fixture"},
                 "address": ADDRESS, "timestamp": TIMESTAMP},
        "packages": {PACKAGE: {
            "metadata": {"added": TIMESTAMP, "lastUpdated": TIMESTAMP, "license": "Unlicense",
                         "name": {"en-US": "Fixture app"}, "preferredSigner": CERT},
            "versions": versions_v2}}}
    index_v1 = {
        "repo": {"name": "Fixture", "address": ADDRESS, "timestamp": TIMESTAMP, "version": 20002},
        "apps": [{"packageName": PACKAGE, "name": "Fixture app", "suggestedVersionCode": "2"}],
        "packages": {PACKAGE: list(reversed(versions_v1))}}
    v2_bytes = json.dumps(index_v2, indent=2, sort_keys=True).encode()
    v1_bytes = json.dumps(index_v1, indent=2, sort_keys=True).encode()
    entry = {"timestamp": TIMESTAMP, "version": 20002,
             "index": {"name": "/index-v2.json", "sha256": hashlib.sha256(v2_bytes).hexdigest(),
                       "size": len(v2_bytes), "numPackages": 1}, "diffs": {}}
    entry_bytes = json.dumps(entry, indent=2, sort_keys=True).encode()
    (repo / "index-v2.json").write_bytes(v2_bytes)
    (repo / "index-v1.json").write_bytes(v1_bytes)
    (repo / "entry.json").write_bytes(entry_bytes)
    with tempfile.TemporaryDirectory() as scratch:
        scratch = Path(scratch)
        store, fingerprint = keystore(scratch, "fixture", "CN=Throwaway fixture index key")
        other, _ = keystore(scratch, "other", "CN=Another throwaway key")
        sign(store, "fixture", repo / "entry.jar", "entry.json", entry_bytes)
        sign(store, "fixture", repo / "index-v1.jar", "index-v1.json", v1_bytes, deprecated=True)
        sign(other, "other", HERE / "other-entry.jar", "entry.json", entry_bytes)
    policy = {"repository": {"address": ADDRESS, "fingerprint": fingerprint},
              PACKAGE: {"source": "owner/app", "certificate_sha256": CERT,
                        "required_workflows": [".github/workflows/ci.yml"], "published": True}}
    (HERE / "policy.json").write_text(json.dumps(policy, indent=2) + "\n")
    history = [{"package": PACKAGE, "source": "owner/app", "commit": "b" * 40,
                "release_id": 10 * code, "asset_id": 20 * code, "version_code": code,
                "sha256": hashlib.sha256(payload(PACKAGE, code)).hexdigest()}
               for code, _ in VERSIONS]
    (HERE / "history.json").write_text(json.dumps(history, indent=2) + "\n")
    print(f"fixture fingerprint {fingerprint}")


if __name__ == "__main__":
    main()
