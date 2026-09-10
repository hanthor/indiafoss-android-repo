import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from build_catalogue import build, ephemeral_pubkey, signing_mode
from verify_apk import Rejected

PACKAGE = "org.example.app"


class CatalogueTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.staging = self.root / "staging"
        self.staging.mkdir()
        self.metadata = self.root / "metadata"
        self.metadata.mkdir()
        (self.metadata / f"{PACKAGE}.yml").write_text("Name: Example\n")
        self.workdir = self.root / "build"
        self.payload = b"APK policy fixture, not a real APK"
        self.apk = self.staging / f"{PACKAGE}_2.apk"
        self.apk.write_bytes(self.payload)
        self.record = {"package": PACKAGE, "source": "owner/app", "commit": "b" * 40,
                       "version_code": 2, "release_id": 10, "asset_id": 20,
                       "sha256": hashlib.sha256(self.payload).hexdigest()}
        self.policy = {PACKAGE: {"source": "owner/app", "certificate_sha256": "a" * 64,
                                 "required_workflows": [".github/workflows/ci.yml"],
                                 "published": True}}
        self.config = {"repo_url": "https://example.org/fdroid/repo", "repo_name": "Example"}
        self.calls = []
        # Injected fdroid result: what a real `fdroid update` would write for the staged APK.
        self.index_entry = {"packageName": PACKAGE, "versionCode": 2, "versionName": "2.0",
                            "apkName": self.apk.name, "hash": self.record["sha256"],
                            "hashType": "sha256", "signer": "A" * 64}
        self.index_apps = [{"packageName": PACKAGE, "name": "Example", "suggestedVersionCode": "2"}]
        self.pubkey = patch("build_catalogue.ephemeral_pubkey", return_value="30ab")
        self.pubkey.start()
        self.addCleanup(self.pubkey.stop)

    def fdroid(self, *args, cwd=None):
        self.calls.append(args)
        repo = Path(cwd) / "repo"
        index = {"repo": {"name": "Example", "address": self.config["repo_url"]},
                 "apps": self.index_apps, "packages": {PACKAGE: [self.index_entry]}}
        (repo / "index-v1.json").write_text(json.dumps(index))
        (repo / "index-v2.json").write_text("{}")
        (repo / "entry.json").write_text("{}")
        if "--nosign" not in args:
            (repo / "index-v1.jar").write_bytes(b"jar")
            (repo / "entry.jar").write_bytes(b"jar")
        return ""

    def build(self, history=None, records=None, config=None):
        return build(self.staging, self.metadata, self.policy, history or [],
                     records if records is not None else [self.record], self.workdir,
                     config or self.config, runner=self.fdroid)

    def test_unsigned_preview_copies_exact_bytes_and_checks_index(self):
        result, signed = self.build()
        self.assertFalse(signed)
        self.assertEqual(self.calls, [("fdroid", "update", "--pretty", "--nosign")])
        self.assertEqual((self.workdir / "repo" / self.apk.name).read_bytes(), self.payload)
        config = (self.workdir / "config.yml").read_text()
        self.assertIn('repo_pubkey: "30ab"', config)
        self.assertNotIn("keystore", config)
        self.assertIn("UNSIGNED", result)
        self.assertIn("ephemeral placeholder", result)
        self.assertIn(self.record["sha256"], result)
        self.assertIn("version 2.0", result)

    def test_unpublished_package_is_refused_even_with_valid_record(self):
        self.policy[PACKAGE]["published"] = False
        with self.assertRaisesRegex(Rejected, "published allowlist"):
            self.build()
        del self.policy[PACKAGE]["published"]
        with self.assertRaisesRegex(Rejected, "published allowlist"):
            self.build()
        self.assertEqual(self.calls, [])

    def test_staged_apk_needs_matching_record_and_bytes(self):
        with self.assertRaisesRegex(Rejected, "No promotion record"):
            self.build(records=[])
        self.build(history=[self.record], records=[])
        self.apk.write_bytes(b"changed")
        with self.assertRaisesRegex(Rejected, "hash mismatch"):
            self.build()
        self.apk.write_bytes(self.payload)
        with self.assertRaisesRegex(Rejected, "conflicts with history"):
            self.build(history=[{**self.record, "sha256": "c" * 64}])
        with self.assertRaisesRegex(Rejected, "regression"):
            self.build(history=[{**self.record, "version_code": 3, "sha256": "c" * 64}])

    def test_index_must_match_records_policy_and_files(self):
        for field, bad in [("hash", "c" * 64), ("signer", "c" * 64), ("versionCode", 3),
                           ("apkName", "other.apk")]:
            with self.subTest(field=field):
                original = self.index_entry[field]
                self.index_entry[field] = bad
                with self.assertRaises(Rejected):
                    self.build()
                self.index_entry[field] = original
        self.index_apps[0]["suggestedVersionCode"] = "9"
        with self.assertRaisesRegex(Rejected, "Suggested version"):
            self.build()
        self.index_apps[0]["suggestedVersionCode"] = "2"
        self.index_apps.append({"packageName": "other.app", "suggestedVersionCode": "1"})
        with self.assertRaisesRegex(Rejected, "do not match"):
            self.build()

    def test_unsigned_build_must_not_leave_signed_or_secret_files(self):
        def leaky(*args, cwd=None):
            self.fdroid(*args, cwd=cwd)
            (Path(cwd) / "repo" / "index-v1.jar").write_bytes(b"jar")
        with self.assertRaisesRegex(Rejected, "signed index files"):
            build(self.staging, self.metadata, self.policy, [], [self.record], self.workdir,
                  self.config, runner=leaky)
        def secret(*args, cwd=None):
            self.fdroid(*args, cwd=cwd)
            (Path(cwd) / "repo" / "keystore.p12").write_bytes(b"secret")
        with self.assertRaisesRegex(Rejected, "Secret-looking"):
            build(self.staging, self.metadata, self.policy, [], [self.record], self.workdir,
                  self.config, runner=secret)

    def test_signing_configuration_fails_closed(self):
        keystore = self.root / "index.p12"
        signed = {**self.config, "repo_keyalias": "index", "keystore": str(keystore),
                  "keystorepass": "x", "keypass": "y"}
        with self.assertRaisesRegex(Rejected, "keystore is missing"):
            self.build(config=signed)
        with self.assertRaisesRegex(Rejected, "Incomplete signing configuration"):
            self.build(config={**self.config, "repo_keyalias": "index"})
        self.assertEqual(self.calls, [])
        keystore.write_bytes(b"not a real keystore")
        result, is_signed = self.build(config=signed)
        self.assertTrue(is_signed)
        self.assertEqual(self.calls, [("fdroid", "update", "--pretty")])
        self.assertIn("SIGNED", result)
        self.assertNotIn("placeholder", result)
        self.assertNotIn("repo_pubkey", (self.workdir / "config.yml").read_text())
        self.assertTrue(signing_mode(dict(signed), self.root))

    def test_stale_apk_in_work_repo_is_rejected(self):
        (self.workdir / "repo").mkdir(parents=True)
        (self.workdir / "repo" / "old.app_1.apk").write_bytes(b"stale")
        with self.assertRaisesRegex(Rejected, "Unexpected APK"):
            self.build()

    @patch("build_catalogue.command")
    def test_keytool_adapter_exports_throwaway_certificate(self, command):
        self.pubkey.stop()
        self.addCleanup(self.pubkey.start)
        def run(*args, cwd=None, timeout=None):
            if "-exportcert" in args:
                Path(args[args.index("-file") + 1]).write_bytes(b"\x30\x82")
            return ""
        command.side_effect = run
        self.assertEqual(ephemeral_pubkey("keytool", self.root), "3082")
        self.assertEqual(command.call_args_list[0].args[:2], ("keytool", "-genkeypair"))
        self.assertIn("NOT THE REPOSITORY KEY", " ".join(command.call_args_list[0].args))
        self.assertEqual(command.call_args_list[1].args[:2], ("keytool", "-exportcert"))


if __name__ == "__main__":
    unittest.main()
