import hashlib
from io import BytesIO
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from stage_release import MAX_APK_BYTES, download, preflight, stage
from verify_apk import Rejected


class StagingTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.destination = Path(self.directory.name) / "staging"
        self.payload = b"APK policy fixture, not a real APK"
        self.record = {"package": "org.example.app", "source": "owner/app", "commit": "b" * 40,
                       "version_code": 2, "release_id": 10, "asset_id": 20,
                       "sha256": hashlib.sha256(self.payload).hexdigest()}
        self.policy = {"org.example.app": {"source": "owner/app", "certificate_sha256": "a" * 64,
                                          "required_workflows": [".github/workflows/ci.yml"]}}
        self.run = {"path": ".github/workflows/ci.yml", "head_sha": "b" * 40,
                    "event": "push", "head_branch": "main", "run_number": 1,
                    "run_attempt": 1, "id": 30, "status": "completed", "conclusion": "success"}
        self.pages = [{"workflow_runs": [self.run]}]
        self.asset = {"id": 20, "state": "uploaded", "name": "app.apk", "size": len(self.payload),
                      "browser_download_url": "https://github.com/owner/app/releases/download/nightly/app.apk",
                      "digest": "sha256:" + self.record["sha256"]}
        self.release = {"id": 10, "draft": False, "published_at": "2026-09-09", "assets": [self.asset]}
        self.observed = {"package": "org.example.app", "version_code": 2,
                         "certificate_sha256": "a" * 64, "debuggable": False}

    def api(self, path, paginate=False):
        if "/commits/" in path:
            return {"sha": self.record["commit"]}
        if "/actions/runs?" in path:
            self.assertTrue(paginate)
            return self.pages
        self.assertEqual(path, "repos/owner/app/releases/10")
        return self.release

    def inspect(self, path):
        return self.observed

    def fetch(self, url, output, size):
        output.write(self.payload)

    def stage(self, fetch=None):
        return stage(self.record, self.policy, [], self.destination,
                     self.inspect, self.api, fetch or self.fetch)

    def test_stages_verified_bytes_and_rechecks_without_downloading(self):
        result = self.stage()
        self.assertEqual(result.read_bytes(), self.payload)
        self.assertEqual(result.name, "org.example.app_2.apk")
        self.assertEqual(list(self.destination.iterdir()), [result])
        def forbidden(*args):
            self.fail("Existing APK must not be downloaded again")
        self.assertEqual(self.stage(forbidden), result)

    def test_rejects_newer_failed_or_pending_run_even_with_older_success(self):
        for status, conclusion in [("completed", "failure"), ("in_progress", None)]:
            self.pages = [{"workflow_runs": [self.run]}, {"workflow_runs": [
                {**self.run, "run_attempt": 2, "status": status, "conclusion": conclusion}]}]
            with self.subTest(status=status), self.assertRaises(Rejected):
                self.stage()
            self.assertFalse(self.destination.exists())

    def test_wrong_commit_branch_or_workflow_is_not_evidence(self):
        for field, bad in [("head_sha", "c" * 40), ("head_branch", "feature"),
                           ("event", "pull_request"), ("path", "other.yml")]:
            original = self.run[field]
            self.run[field] = bad
            with self.subTest(field=field), self.assertRaises(Rejected):
                preflight(self.record, self.policy, [], self.api)
            self.run[field] = original

    def test_rejects_unpublished_release_or_asset_from_another_release(self):
        self.release["draft"] = True
        with self.assertRaises(Rejected):
            self.stage()
        self.release["draft"] = False
        self.release["assets"] = []
        with self.assertRaises(Rejected):
            self.stage()

    def test_rejects_bad_asset_metadata(self):
        for field, bad in [("size", MAX_APK_BYTES + 1), ("state", "new"), ("name", "source.zip"),
                           ("browser_download_url", "https://example.org/app.apk"),
                           ("digest", "sha256:" + "f" * 64)]:
            original = self.asset[field]
            self.asset[field] = bad
            with self.subTest(field=field), self.assertRaises(Rejected):
                self.stage()
            self.asset[field] = original

    def test_changed_download_and_inspection_failure_leave_no_staged_file(self):
        with self.assertRaises(Rejected):
            self.stage(lambda url, output, size: output.write(b"wrong bytes"))
        self.assertEqual(list(self.destination.iterdir()), [])
        self.observed["certificate_sha256"] = "f" * 64
        with self.assertRaises(Rejected):
            self.stage()
        self.assertEqual(list(self.destination.iterdir()), [])

    def test_existing_wrong_bytes_are_never_replaced(self):
        target = self.stage()
        target.write_bytes(b"keep these bytes for investigation")
        with self.assertRaises(Rejected):
            self.stage()
        self.assertEqual(target.read_bytes(), b"keep these bytes for investigation")

    @patch("stage_release.urlopen")
    def test_download_rejects_truncation_and_excess(self, opened):
        for payload in [b"a", b"abcd"]:
            opened.return_value = BytesIO(payload)
            with self.subTest(payload=payload), self.assertRaises(Rejected):
                download("https://github.com/test", BytesIO(), 3)
