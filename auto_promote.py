"""Choose which Companion builds the catalogue carries, from permanent releases.

The Companion's nightly workflow keeps every main build on its own
`android-<version>` release. This picks the newest few whose source CI is
green (the same preflight stage_release.py applies) and writes them as the
history the publish workflow signs, so a new build reaches the repository
without anyone writing a promotion record. It never goes below the committed
history.json or the version already live, and it reports whether anything
would change so an unchanged catalogue is not re-signed.
"""
import argparse
import json
from pathlib import Path
from urllib.request import urlopen

from stage_release import github, preflight
from verify_apk import require

PACKAGE = "org.indiafoss.companion.nativeapp"
TAG_PREFIX = "android-"
KEEP = 3


def fetch_json(url):
    with urlopen(url, timeout=60) as response:
        return json.loads(response.read(64 * 1024))


def record_for(release, policy, fetch=fetch_json):
    """The promotion record a kept release describes, or None when it is not one."""
    if release.get("draft") or not release.get("tag_name", "").startswith(TAG_PREFIX):
        return None
    assets = {asset.get("name"): asset for asset in release.get("assets", [])}
    apks = [asset for name, asset in assets.items() if name and name.endswith(".apk")]
    if len(apks) != 1:
        return None
    manifest = assets.get(f"{apks[0]['name']}.signing.json")
    if not manifest:
        return None
    signing = fetch(manifest["browser_download_url"])
    if signing.get("certificateSha256") != policy[PACKAGE]["certificate_sha256"]:
        return None
    return {
        "package": PACKAGE,
        "source": policy[PACKAGE]["source"],
        "commit": signing.get("sourceCommit"),
        "release_id": release["id"],
        "asset_id": apks[0]["id"],
        "version_code": int(signing.get("versionCode")),
        "sha256": signing.get("apkSha256"),
    }


def choose(releases, policy, committed, live_versions, api=github, fetch=fetch_json, keep=KEEP):
    """Return (history, changed): up to `keep` newest green builds, oldest first."""
    floor = max([r["version_code"] for r in committed if r["package"] == PACKAGE] +
                list(live_versions) + [0])
    candidates = []
    for release in releases:
        try:
            record = record_for(release, policy, fetch)
        except Exception:  # an unreadable signing manifest is not a kept build
            continue
        if record and record["version_code"] >= floor:
            candidates.append(record)
    chosen = []
    seen = set()
    for record in sorted(candidates, key=lambda r: r["version_code"], reverse=True):
        if record["version_code"] in seen:
            continue
        try:
            preflight(record, policy, [], api)
        except Exception as error:  # a red, missing or mismatched build is skipped, not fatal
            print(f"Skipping {record['version_code']}: {error}")
            continue
        chosen.append(record)
        seen.add(record["version_code"])
        if len(chosen) == keep:
            break
    history = sorted(chosen, key=lambda r: r["version_code"])
    changed = bool(history) and {r["version_code"] for r in history} != set(live_versions)
    return history, changed


def live_version_codes(url, fetch=fetch_json):
    try:
        index = fetch(url)
    except (OSError, ValueError):
        return set()
    versions = index.get("packages", {}).get(PACKAGE, {}).get("versions", {})
    return {v["manifest"]["versionCode"] for v in versions.values()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, default=Path("apps.json"))
    parser.add_argument("--history", type=Path, default=Path("history.json"))
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args()
    policy = json.loads(args.policy.read_text())
    committed = json.loads(args.history.read_text())
    live = live_version_codes(f"{policy['repository']['address']}/index-v2.json")
    source = policy[PACKAGE]["source"]
    pages = github(f"repos/{source}/releases?per_page=100", paginate=True)
    releases = [release for page in pages for release in page]
    history, changed = choose(releases, policy, committed, live)
    require(bool(history), "No green permanent Companion release to publish")
    args.out.write_text(json.dumps(history, indent=2) + "\n")
    print("Chosen:", [r["version_code"] for r in history], "live:", sorted(live), "changed:", changed)
    if args.github_output:
        with args.github_output.open("a") as out:
            out.write(f"changed={'true' if changed else 'false'}\n")


if __name__ == "__main__":
    main()
