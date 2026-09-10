"""Check a local release APK before repository promotion. Does not publish or sign."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


class Rejected(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise Rejected(message)


def digest(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def validate_record(record, policy, history):
    package = record.get("package")
    require(isinstance(package, str) and package in policy and package != "repository",
            "Package is not allowed")
    require(record.get("source") == policy[package]["source"], "Wrong source repository")
    require(digest(record.get("sha256")), "Invalid APK SHA-256")
    require(digest(policy[package]["certificate_sha256"]), "Invalid certificate policy")
    require(isinstance(record.get("commit"), str) and
            re.fullmatch(r"[0-9a-f]{40}", record["commit"]) is not None,
            "An exact source commit is required")
    for field in ("version_code", "release_id", "asset_id"):
        require(type(record.get(field)) is int and record[field] > 0, f"Invalid {field}")
    version = record["version_code"]
    require(version <= 2100000000, "Version code exceeds Android limit")
    for prior in history:
        if prior["package"] != package:
            continue
        require(version >= prior["version_code"], "Version code regression")
        if version == prior["version_code"]:
            require(record["sha256"] == prior["sha256"], "Existing version has different bytes")
    return package


def command(*args):
    return subprocess.run(args, check=True, text=True, capture_output=True, timeout=60).stdout.strip()


def inspect_apk(path, apksigner, apkanalyzer):
    # A non-zero verification result is fatal, even if a certificate was printed.
    signatures = command(apksigner, "verify", "--print-certs", str(path))
    signers = re.findall(r"^Signer #\d+ certificate SHA-256 digest: ([0-9a-fA-F]{64})$",
                         signatures, re.MULTILINE)
    require(len(signers) == 1, "Expected exactly one verified APK signer")
    debug = command(apkanalyzer, "manifest", "debuggable", str(path))
    require(debug in ("true", "false"), "Unrecognised debuggable output")
    return {
        "package": command(apkanalyzer, "manifest", "application-id", str(path)),
        "version_code": int(command(apkanalyzer, "manifest", "version-code", str(path))),
        "debuggable": debug == "true",
        "certificate_sha256": signers[0].lower(),
    }


def verify(record, policy, history, path, inspector):
    package = validate_record(record, policy, history)
    require(path.is_file() and not path.is_symlink(), "APK must be a regular local file")
    with path.open("rb") as apk:
        actual_hash = hashlib.file_digest(apk, "sha256").hexdigest()
    require(actual_hash == record["sha256"], "APK hash mismatch")
    observed = inspector(path)
    require(observed["package"] == package, "APK package mismatch")
    require(observed["version_code"] == record["version_code"], "APK version mismatch")
    require(observed["debuggable"] is False, "Debuggable APK rejected")
    require(observed["certificate_sha256"] == policy[package]["certificate_sha256"],
            "APK signing certificate mismatch")
    # These observations validate only the APK; source CI and release provenance
    # must be independently verified by the future promotion workflow.
    return {**record, "certificate_sha256": observed["certificate_sha256"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("record", type=Path)
    parser.add_argument("apk", type=Path)
    parser.add_argument("--policy", type=Path, default=Path(__file__).with_name("apps.json"))
    parser.add_argument("--history", type=Path, required=True)
    parser.add_argument("--apksigner", default="apksigner")
    parser.add_argument("--apkanalyzer", default="apkanalyzer")
    args = parser.parse_args()
    result = verify(json.loads(args.record.read_text()), json.loads(args.policy.read_text()),
                    json.loads(args.history.read_text()), args.apk,
                    lambda path: inspect_apk(path, args.apksigner, args.apkanalyzer))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
