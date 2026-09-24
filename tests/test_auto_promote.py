import unittest

from auto_promote import PACKAGE, choose, record_for

CERT = "c" * 64
POLICY = {PACKAGE: {"source": "owner/companion", "certificate_sha256": CERT,
                    "required_workflows": [".github/workflows/ci.yml"]}}


def release(version, *, tag=None, cert=CERT, draft=False):
    return {"id": 1000 + version, "tag_name": tag or f"android-2026.{version}-abc", "draft": draft,
            "published_at": "2026-09-24",
            "assets": [
                {"id": 2000 + version, "name": "companion.apk", "state": "uploaded", "size": 10,
                 "browser_download_url": f"https://github.com/owner/companion/releases/download/v{version}/companion.apk"},
                {"id": 3000 + version, "name": "companion.apk.signing.json",
                 "browser_download_url": f"manifest://{version}/{cert}"},
            ]}


def fetch(url):
    version, cert = url.removeprefix("manifest://").split("/")
    return {"certificateSha256": cert, "sourceCommit": f"{int(version):040d}",
            "apkSha256": f"{int(version):064d}", "versionCode": version}


class Api:
    """Source CI is green for every commit except those listed as red."""

    def __init__(self, red=()):
        self.red = {f"{v:040d}" for v in red}

    def __call__(self, path, paginate=False):
        if "/commits/" in path:
            return {"sha": path.rsplit("/", 1)[1]}
        if "/actions/runs" in path:
            sha = path.split("head_sha=")[1].split("&")[0]
            return [{"workflow_runs": [{
                "path": ".github/workflows/ci.yml", "head_sha": sha, "event": "push",
                "head_branch": "main", "run_number": 1, "run_attempt": 1, "id": 1,
                "status": "completed", "conclusion": "failure" if sha in self.red else "success"}]}]
        if "/releases/" in path:
            version = int(path.rsplit("/", 1)[1]) - 1000
            return release(version)
        raise AssertionError(path)


class ChooseTests(unittest.TestCase):
    def test_keeps_the_newest_green_builds_oldest_first(self):
        releases = [release(v) for v in (1250, 1261, 1262, 1263, 1264)]
        history, changed = choose(releases, POLICY, [], {1261}, api=Api(), fetch=fetch)
        self.assertEqual([r["version_code"] for r in history], [1262, 1263, 1264])
        self.assertTrue(changed)
        self.assertEqual(history[-1]["asset_id"], 3264)

    def test_a_build_whose_ci_is_not_green_waits(self):
        releases = [release(v) for v in (1261, 1262)]
        history, changed = choose(releases, POLICY, [], {1261}, api=Api(red={1262}), fetch=fetch)
        self.assertEqual([r["version_code"] for r in history], [1261])
        self.assertFalse(changed)

    def test_never_goes_below_what_is_live_or_committed(self):
        releases = [release(v) for v in (1255, 1258)]
        committed = [{"package": PACKAGE, "version_code": 1260}]
        history, changed = choose(releases, POLICY, committed, {1261}, api=Api(), fetch=fetch)
        self.assertEqual(history, [])
        self.assertFalse(changed)

    def test_ignores_the_rolling_nightly_drafts_and_other_certificates(self):
        releases = [release(1270, tag="nightly"), release(1271, draft=True),
                    release(1272, cert="d" * 64), release(1262)]
        history, _ = choose(releases, POLICY, [], set(), api=Api(), fetch=fetch)
        self.assertEqual([r["version_code"] for r in history], [1262])

    def test_record_carries_the_manifests_commit_and_checksum(self):
        record = record_for(release(1262), POLICY, fetch)
        self.assertEqual(record["commit"], f"{1262:040d}")
        self.assertEqual(record["sha256"], f"{1262:064d}")
        self.assertEqual(record["release_id"], 2262)
        self.assertEqual(record["source"], "owner/companion")


if __name__ == "__main__":
    unittest.main()
