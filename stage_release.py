"""Read-only GitHub preflight and immutable local APK staging; never publishes."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
from urllib.request import urlopen

from verify_apk import inspect_apk, require, validate_record, verify

MAX_APK_BYTES = 256 * 1024 * 1024


def github(path, paginate=False):
    args = ["gh", "api", path]
    if paginate:
        args.extend(["--paginate", "--slurp"])
    return json.loads(subprocess.run(args, check=True, capture_output=True, text=True,
                                     timeout=120).stdout)


def preflight(record, policy, history, api=github):
    package = validate_record(record, policy, history)
    source = record["source"]
    commit = record["commit"]
    root = f"repos/{source}"
    resolved = api(f"{root}/commits/{commit}")
    require(resolved.get("sha") == commit, "Source commit mismatch")
    pages = api(f"{root}/actions/runs?head_sha={commit}&event=push&per_page=100", paginate=True)
    runs = [run for page in pages for run in page["workflow_runs"]]
    workflows = policy[package]["required_workflows"]
    require(bool(workflows), "No required source workflows configured")
    for workflow in workflows:
        matching = [run for run in runs if run.get("path") == workflow and
                    run.get("head_sha") == commit and run.get("event") == "push" and
                    run.get("head_branch") == "main"]
        require(bool(matching), f"Missing source CI: {workflow}")
        latest = max(matching, key=lambda run: (run["run_number"], run["run_attempt"], run["id"]))
        require(latest.get("status") == "completed" and latest.get("conclusion") == "success",
                f"Source CI is not green: {workflow}")
    release = api(f"{root}/releases/{record['release_id']}")
    require(release.get("id") == record["release_id"] and not release.get("draft") and
            bool(release.get("published_at")), "Release is not published")
    assets = [asset for asset in release.get("assets", []) if asset.get("id") == record["asset_id"]]
    require(len(assets) == 1, "Asset does not belong to the recorded release")
    asset = assets[0]
    require(asset.get("state") == "uploaded" and asset.get("name", "").endswith(".apk"),
            "Release asset is not an uploaded APK")
    require(type(asset.get("size")) is int and 0 < asset["size"] <= MAX_APK_BYTES,
            "Release APK exceeds size limit or is empty")
    url = asset.get("browser_download_url", "")
    require(url.startswith(f"https://github.com/{source}/releases/download/"),
            "Unexpected release download URL")
    if asset.get("digest") is not None:
        require(asset["digest"] == f"sha256:{record['sha256']}", "Release digest mismatch")
    return asset


def download(url, output, expected_size):
    received = 0
    with urlopen(url, timeout=30) as response:
        while chunk := response.read(1024 * 1024):
            received += len(chunk)
            require(received <= expected_size and received <= MAX_APK_BYTES, "Download exceeds expected size")
            output.write(chunk)
    require(received == expected_size, "Truncated APK download")


def stage(record, policy, history, destination, inspector, api=github, fetch=download):
    asset = preflight(record, policy, history, api)
    destination.mkdir(parents=True, exist_ok=True)
    target = destination / f"{record['package']}_{record['version_code']}.apk"
    if target.exists() or target.is_symlink():
        # Validate rather than silently overwriting a retained release.
        verify(record, policy, history, target, inspector)
        return target
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=destination, suffix=".apk", delete=False) as output:
            temporary = Path(output.name)
            fetch(asset["browser_download_url"], output, asset["size"])
        verify(record, policy, history, temporary, inspector)
        # A hard link creates the final name atomically and refuses to replace
        # an existing file, including one created by a concurrent promotion.
        os.link(temporary, target)
        return target
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("record", type=Path)
    parser.add_argument("--history", type=Path, required=True)
    parser.add_argument("--destination", type=Path, default=Path("staging"))
    parser.add_argument("--policy", type=Path, default=Path(__file__).with_name("apps.json"))
    parser.add_argument("--apksigner", default="apksigner")
    parser.add_argument("--apkanalyzer", default="apkanalyzer")
    args = parser.parse_args()
    path = stage(json.loads(args.record.read_text()), json.loads(args.policy.read_text()),
                 json.loads(args.history.read_text()), args.destination,
                 lambda apk: inspect_apk(apk, args.apksigner, args.apkanalyzer))
    print(path)


if __name__ == "__main__":
    main()
