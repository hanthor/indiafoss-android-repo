import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from verify_apk import Rejected
from verify_index import (Unsigned, inspect_jar, jarsigner_verify, parse_manifest,
                          signer_certificates, verify_repo)

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "index"
PACKAGE = "org.example.app"


def payload(package, code):
    # Must match tests/fixtures/index/make_fixture.py; these bytes are not an APK.
    return f"fixture APK bytes for {package} version {code}\n".encode()


class FakeJarsigner:
    """Stands in for jarsigner; the fixture JARs are also checked with the real tool below."""

    def __init__(self):
        self.calls = []

    def __call__(self, jar, deprecated):
        self.calls.append((jar.name, deprecated))


class VerifyIndexTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.repo = Path(self.directory.name) / "repo"
        shutil.copytree(FIXTURE / "catalogue", self.repo)
        for code in (1, 2):
            (self.repo / f"{PACKAGE}_{code}.apk").write_bytes(payload(PACKAGE, code))
        self.policy = json.loads((FIXTURE / "policy.json").read_text())
        self.history = json.loads((FIXTURE / "history.json").read_text())
        self.jarsigner = FakeJarsigner()

    def verify(self, history=None, records=(), **options):
        return verify_repo(self.repo, self.policy,
                           self.history if history is None else history, list(records),
                           self.jarsigner, **options)

    def signature_names(self, jar):
        with zipfile.ZipFile(jar) as archive:
            names = sorted(name for name in archive.namelist()
                           if name.startswith("META-INF/") and name != "META-INF/MANIFEST.MF")
        self.assertEqual(len(names), 2)
        return names  # [.RSA, .SF] after sorting

    def rewrite_jar(self, name, drop=(), replace=None):
        source = self.repo / name
        entries = []
        with zipfile.ZipFile(source) as archive:
            for info in archive.infolist():
                if info.filename in drop:
                    continue
                data = archive.read(info.filename)
                if replace and info.filename in replace:
                    data = replace[info.filename]
                entries.append((info.filename, data))
        with zipfile.ZipFile(source, "w") as archive:
            for filename, data in entries:
                archive.writestr(filename, data)

    def test_signed_fixture_verifies_against_recorded_fingerprint(self):
        lines = self.verify(deployable=True)
        fingerprint = self.policy["repository"]["fingerprint"]
        self.assertIn(f"SIGNED catalogue verified against fingerprint {fingerprint}", lines)
        self.assertEqual(self.jarsigner.calls, [("entry.jar", False), ("index-v1.jar", True)])

    def test_missing_fingerprint_reports_unsigned_instead_of_passing(self):
        self.policy["repository"]["fingerprint"] = ""
        with self.assertRaisesRegex(Unsigned, "UNSIGNED CATALOGUE"):
            self.verify()
        del self.policy["repository"]
        with self.assertRaisesRegex(Unsigned, "UNSIGNED CATALOGUE"):
            self.verify()
        # A preview may be accepted explicitly, but only if nothing in it is signed.
        with self.assertRaisesRegex(Rejected, "must not contain signed index files"):
            self.verify(expect_unsigned=True)
        for jar in self.repo.glob("*.jar"):
            jar.unlink()
        lines = self.verify(expect_unsigned=True)
        self.assertTrue(any("UNSIGNED preview" in line for line in lines))
        self.assertEqual(self.jarsigner.calls, [])
        with zipfile.ZipFile(self.repo / "index_unsigned.jar", "w") as archive:
            archive.writestr("index.xml", b"<fdroid/>")
        self.verify(expect_unsigned=True)

    def test_expect_unsigned_is_refused_once_a_fingerprint_exists(self):
        with self.assertRaisesRegex(Rejected, "do not use --expect-unsigned"):
            self.verify(expect_unsigned=True)

    def test_wrong_or_malformed_fingerprint_is_rejected(self):
        self.policy["repository"]["fingerprint"] = "c" * 64
        with self.assertRaisesRegex(Rejected, "not the recorded fingerprint"):
            self.verify()
        self.assertEqual(self.jarsigner.calls, [])
        self.policy["repository"]["fingerprint"] = "AB:CD"
        with self.assertRaisesRegex(Rejected, "64 lowercase hex"):
            self.verify()

    def test_jar_signed_by_another_key_is_rejected(self):
        shutil.copyfile(FIXTURE / "other-entry.jar", self.repo / "entry.jar")
        with self.assertRaisesRegex(Rejected, "entry.jar is signed by"):
            self.verify()

    def test_unsigned_or_multiply_signed_jar_is_rejected(self):
        self.rewrite_jar("entry.jar", drop=self.signature_names(self.repo / "entry.jar"))
        with self.assertRaisesRegex(Rejected, "exactly one JAR signature"):
            self.verify()
        shutil.copyfile(FIXTURE / "catalogue" / "entry.jar", self.repo / "entry.jar")
        with zipfile.ZipFile(FIXTURE / "other-entry.jar") as other, \
                zipfile.ZipFile(self.repo / "entry.jar", "a") as archive:
            for name in self.signature_names(FIXTURE / "other-entry.jar"):
                archive.writestr(name, other.read(name))
        with self.assertRaisesRegex(Rejected, "exactly one JAR signature"):
            self.verify()

    def test_signed_payload_must_match_files_on_disk(self):
        entry = json.loads((self.repo / "entry.json").read_text())
        (self.repo / "entry.json").write_text(json.dumps(entry))
        with self.assertRaisesRegex(Rejected, "entry.json on disk differs"):
            self.verify()
        shutil.copyfile(FIXTURE / "catalogue" / "entry.json", self.repo / "entry.json")
        index = json.loads((self.repo / "index-v2.json").read_text())
        (self.repo / "index-v2.json").write_text(json.dumps(index))
        with self.assertRaisesRegex(Rejected, "entry.json does not match index-v2.json"):
            self.verify()

    def test_tampered_jar_manifest_is_rejected(self):
        with zipfile.ZipFile(self.repo / "entry.jar") as archive:
            manifest = archive.read("META-INF/MANIFEST.MF")
        tampered = manifest.replace(b"SHA-256-Digest: ", b"SHA-256-Digest: A")
        self.rewrite_jar("entry.jar", replace={"META-INF/MANIFEST.MF": tampered})
        with self.assertRaisesRegex(Rejected, "manifest digest does not match"):
            self.verify()

    def test_jarsigner_result_is_fatal(self):
        def failing(jar, deprecated):
            raise Rejected(f"JAR signature failed to verify: {jar.name}")
        with self.assertRaisesRegex(Rejected, "failed to verify: entry.jar"):
            verify_repo(self.repo, self.policy, self.history, [], failing)

    def test_apk_bytes_must_match_index_and_history(self):
        apk = self.repo / f"{PACKAGE}_2.apk"
        apk.write_bytes(b"different bytes")
        with self.assertRaisesRegex(Rejected, "hash mismatch"):
            self.verify()
        apk.unlink()
        with self.assertRaisesRegex(Rejected, "Listed APK is missing"):
            self.verify()
        apk.write_bytes(payload(PACKAGE, 2))
        changed = [dict(record) for record in self.history]
        changed[1]["sha256"] = "c" * 64
        with self.assertRaisesRegex(Rejected, "hash mismatch"):
            self.verify(history=changed)
        (self.repo / f"{PACKAGE}_3.apk").write_bytes(b"stray")
        with self.assertRaisesRegex(Rejected, "not listed in the index"):
            self.verify()

    def test_every_listed_version_needs_a_record_and_every_record_a_listing(self):
        with self.assertRaisesRegex(Rejected, "No promotion record"):
            self.verify(history=self.history[:1])
        # The newest record may be supplied separately, as build_catalogue.py does.
        self.verify(history=self.history[:1], records=self.history[1:])
        extra = {**self.history[1], "version_code": 3, "release_id": 30, "asset_id": 60,
                 "sha256": "d" * 64}
        with self.assertRaisesRegex(Rejected, "differ from promoted versions"):
            self.verify(history=self.history + [extra])

    def test_version_codes_must_be_increasing_and_distinct(self):
        with self.assertRaisesRegex(Rejected, "not increasing"):
            self.verify(history=list(reversed(self.history)))
        with self.assertRaisesRegex(Rejected, "Duplicate history record"):
            self.verify(history=self.history + [self.history[1]])
        index = json.loads((self.repo / "index-v2.json").read_text())
        versions = index["packages"][PACKAGE]["versions"]
        versions[hashlib.sha256(payload(PACKAGE, 1)).hexdigest()]["manifest"]["versionCode"] = 2
        (self.repo / "index-v2.json").write_text(json.dumps(index))
        entry = json.loads((self.repo / "entry.json").read_text())
        entry["index"]["sha256"] = hashlib.sha256((self.repo / "index-v2.json").read_bytes()).hexdigest()
        entry["index"]["size"] = (self.repo / "index-v2.json").stat().st_size
        (self.repo / "entry.json").write_text(json.dumps(entry))
        with self.assertRaisesRegex(Rejected, "Unexpected file name|Duplicate version codes"):
            self.verify(history=self.history)

    def test_index_v1_must_agree_with_index_v2(self):
        index = json.loads((self.repo / "index-v1.json").read_text())
        index["packages"][PACKAGE][0]["hash"] = "c" * 64
        (self.repo / "index-v1.json").write_text(json.dumps(index))
        with self.assertRaisesRegex(Rejected, "index-v1 disagrees"):
            self.verify()

    def test_policy_gates_signer_publication_and_address(self):
        self.policy[PACKAGE]["certificate_sha256"] = "c" * 64
        with self.assertRaisesRegex(Rejected, "signer mismatch"):
            self.verify()
        self.policy[PACKAGE]["certificate_sha256"] = "a" * 64
        self.policy[PACKAGE]["published"] = False
        with self.assertRaisesRegex(Rejected, "published allowlist"):
            self.verify()
        self.policy[PACKAGE]["published"] = True
        self.policy["repository"]["address"] = "https://elsewhere.example/repo"
        with self.assertRaisesRegex(Rejected, "not the recorded"):
            self.verify()

    def test_deployable_refuses_status_secrets_and_unknown_files(self):
        (self.repo / "status").mkdir()
        (self.repo / "status" / "update.json").write_text("{}")
        self.verify()
        with self.assertRaisesRegex(Rejected, "Not deployable: status/"):
            self.verify(deployable=True)
        shutil.rmtree(self.repo / "status")
        (self.repo / "config.yml").write_text("keystore: x")
        with self.assertRaisesRegex(Rejected, "Secret-looking"):
            self.verify()
        (self.repo / "config.yml").unlink()
        (self.repo / "index.p12").write_bytes(b"x")
        with self.assertRaisesRegex(Rejected, "Secret-looking"):
            self.verify()
        (self.repo / "index.p12").unlink()
        (self.repo / "notes.txt").write_text("x")
        with self.assertRaisesRegex(Rejected, "Not deployable: notes.txt"):
            self.verify(deployable=True)

    def test_signature_block_parser_and_manifest_parser(self):
        block_name, _ = self.signature_names(self.repo / "entry.jar")
        with zipfile.ZipFile(self.repo / "entry.jar") as archive:
            block = archive.read(block_name)
        certificates = signer_certificates(block)
        self.assertEqual(len(certificates), 1)
        self.assertEqual(hashlib.sha256(certificates[0]).hexdigest(),
                         self.policy["repository"]["fingerprint"])
        with self.assertRaises(Rejected):
            signer_certificates(b"\x30\x03\x02\x01\x00")
        with self.assertRaises(Rejected):
            signer_certificates(block[:-10])
        sections = parse_manifest("Manifest-Version: 1.0\r\n\r\nName: a-very-long-file-name-"
                                  "\r\n that-is-folded.json\r\nSHA-256-Digest: abc=\r\n\r\n")
        self.assertEqual(sections, {"a-very-long-file-name-that-is-folded.json":
                                    {"SHA-256-Digest": "abc="}})
        content, certificate = inspect_jar(self.repo / "entry.jar", "entry.json")
        self.assertEqual(content, (self.repo / "entry.json").read_bytes())
        self.assertEqual(certificate, certificates[0])
        with self.assertRaisesRegex(Rejected, "exactly one index-v1.json"):
            inspect_jar(self.repo / "entry.jar", "index-v1.json")

    @patch("verify_index.subprocess.run")
    def test_jarsigner_adapter_accepts_only_self_signed_verified(self, run):
        run.return_value = subprocess.CompletedProcess([], 4, "jar verified, with signer errors.", "")
        jarsigner_verify("jarsigner", self.repo / "entry.jar")
        args = run.call_args.args[0]
        self.assertEqual(args[0], "jarsigner")
        self.assertEqual(args[-3:], ["-strict", "-verify", str(self.repo / "entry.jar")])
        self.assertFalse(any(arg.startswith("-J-Djava.security.properties=") for arg in args))
        jarsigner_verify("jarsigner", self.repo / "index-v1.jar", allow_deprecated=True)
        args = run.call_args.args[0]
        self.assertTrue(any(arg.startswith("-J-Djava.security.properties=") for arg in args))
        for code, output in [(0, "jar is unsigned."), (16, "treated as unsigned"),
                             (4, "jar is unsigned."), (1, "")]:
            run.return_value = subprocess.CompletedProcess([], code, output, "")
            with self.subTest(code=code), self.assertRaisesRegex(Rejected, "failed to verify"):
                jarsigner_verify("jarsigner", self.repo / "entry.jar")

    @unittest.skipUnless(shutil.which("jarsigner"), "jarsigner (JDK) not installed")
    def test_real_jarsigner_verifies_fixture_and_rejects_tampering(self):
        verify_repo(self.repo, self.policy, self.history, [],
                    lambda jar, deprecated: jarsigner_verify("jarsigner", jar, deprecated))
        # index-v1.jar uses SHA-1 like fdroidserver; it must fail without the override.
        with self.assertRaisesRegex(Rejected, "failed to verify"):
            jarsigner_verify("jarsigner", self.repo / "index-v1.jar", allow_deprecated=False)
        _, signature_name = self.signature_names(self.repo / "entry.jar")
        with zipfile.ZipFile(self.repo / "entry.jar") as archive:
            signature = archive.read(signature_name)
        self.rewrite_jar("entry.jar", replace={signature_name: signature.replace(b"=", b"+", 1)})
        with self.assertRaisesRegex(Rejected, "failed to verify"):
            jarsigner_verify("jarsigner", self.repo / "entry.jar")


if __name__ == "__main__":
    unittest.main()


class PublishSiteTests(unittest.TestCase):
    def setUp(self):
        from publish_site import assemble
        self.assemble = assemble
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.repo = self.root / "repo"
        shutil.copytree(FIXTURE / "catalogue", self.repo)
        for code in (1, 2):
            (self.repo / f"{PACKAGE}_{code}.apk").write_bytes(payload(PACKAGE, code))
        (self.repo / "status").mkdir()
        (self.repo / "status" / "update.json").write_text("{}")
        (self.repo / "icons").mkdir()
        (self.repo / "icons" / "icon.png").write_bytes(b"png")
        (self.repo / "index_unsigned.jar").write_bytes(b"jar")
        (self.repo / "notes.txt").write_text("x")

    def test_only_public_files_are_copied_and_result_is_deployable(self):
        site = self.root / "site"
        copied = self.assemble(self.repo, site)
        target = site / "fdroid" / "repo"
        self.assertEqual(sorted(p.name for p in target.iterdir()),
                         sorted(["entry.jar", "entry.json", "index-v1.jar", "index-v1.json",
                                 "index-v2.json", f"{PACKAGE}_1.apk", f"{PACKAGE}_2.apk", "icons"]))
        self.assertEqual(sorted(copied), sorted(p.name for p in target.iterdir()))
        self.assertTrue((site / ".nojekyll").is_file())
        policy = json.loads((FIXTURE / "policy.json").read_text())
        history = json.loads((FIXTURE / "history.json").read_text())
        verify_repo(target, policy, history, [], FakeJarsigner(), deployable=True)
        with self.assertRaisesRegex(Rejected, "already exists"):
            self.assemble(self.repo, site)

    def test_secrets_and_unsigned_output_are_refused(self):
        (self.repo / "index.p12").write_bytes(b"secret")
        with self.assertRaisesRegex(Rejected, "Secret-looking"):
            self.assemble(self.repo, self.root / "site")
        (self.repo / "index.p12").unlink()
        (self.repo / "entry.jar").unlink()
        with self.assertRaisesRegex(Rejected, "Only a signed catalogue"):
            self.assemble(self.repo, self.root / "site2")
