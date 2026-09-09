import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from verify_apk import Rejected, inspect_apk, verify


class PromotionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.apk = Path(self.directory.name) / "test.apk"
        # Policy tests inject inspection results; these bytes are not an Android APK.
        self.apk.write_bytes(b"test fixture bytes")
        self.policy = {"org.example.app": {"source": "owner/app", "certificate_sha256": "a" * 64}}
        self.record = {"package": "org.example.app", "source": "owner/app", "commit": "b" * 40,
                       "version_code": 2, "release_id": 10, "asset_id": 20,
                       "sha256": hashlib.sha256(self.apk.read_bytes()).hexdigest()}
        self.observed = {"package": "org.example.app", "version_code": 2, "debuggable": False,
                         "certificate_sha256": "a" * 64}

    def check(self, history=None):
        return verify(self.record, self.policy, history or [], self.apk, lambda _: self.observed)

    def test_accepts_matching_release_and_idempotent_recheck(self):
        self.assertEqual(self.check()["package"], "org.example.app")
        self.check([dict(self.record)])

    def test_rejects_changed_bytes(self):
        self.apk.write_bytes(b"changed")
        with self.assertRaisesRegex(Rejected, "hash mismatch"):
            self.check()

    def test_rejects_wrong_apk_identity_and_debug(self):
        for field, bad in [("package", "another.app"), ("version_code", 3),
                           ("certificate_sha256", "c" * 64), ("debuggable", True)]:
            with self.subTest(field=field):
                original = self.observed[field]
                self.observed[field] = bad
                with self.assertRaises(Rejected):
                    self.check()
                self.observed[field] = original

    def test_rejects_downgrade_and_reused_version_with_changed_bytes(self):
        for prior in [{**self.record, "version_code": 3}, {**self.record, "sha256": "c" * 64}]:
            with self.subTest(prior=prior), self.assertRaises(Rejected):
                self.check([prior])

    def test_rejects_missing_or_invalid_provenance(self):
        for field, bad in [("package", "unknown"), ("source", "other/repo"), ("commit", "main"),
                           ("release_id", 0), ("asset_id", True), ("version_code", -1)]:
            with self.subTest(field=field):
                original = self.record[field]
                self.record[field] = bad
                with self.assertRaises(Rejected):
                    self.check()
                self.record[field] = original

    def test_rejects_symlink(self):
        link = self.apk.with_name("link.apk")
        link.symlink_to(self.apk)
        with self.assertRaises(Rejected):
            verify(self.record, self.policy, [], link, lambda _: self.observed)

    @patch("verify_apk.command")
    def test_tool_adapter_checks_signature_and_manifest(self, command):
        command.side_effect = ["Signer #1 certificate SHA-256 digest: " + "A" * 64,
                               "false", "org.example.app", "2"]
        self.assertEqual(inspect_apk(self.apk, "signer", "analyzer"), self.observed)
        self.assertEqual(command.call_args_list[0].args[:3], ("signer", "verify", "--print-certs"))

    @patch("verify_apk.command")
    def test_signature_tool_failure_is_fatal(self, command):
        command.side_effect = subprocess.CalledProcessError(1, "apksigner")
        with self.assertRaises(subprocess.CalledProcessError):
            inspect_apk(self.apk, "signer", "analyzer")

    @patch("verify_apk.command")
    def test_missing_and_multiple_signers_are_rejected(self, command):
        for output in ["", "\n".join(f"Signer #{i} certificate SHA-256 digest: " + "a" * 64 for i in [1, 2])]:
            command.return_value = output
            with self.assertRaises(Rejected):
                inspect_apk(self.apk, "signer", "analyzer")


if __name__ == "__main__":
    unittest.main()
