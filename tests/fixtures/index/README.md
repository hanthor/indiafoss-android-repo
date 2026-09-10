# Signed catalogue fixture

`catalogue/` holds an F-Droid index-v2 catalogue for the synthetic package
`org.example.app` (version codes 1 and 2) signed by a throwaway key:
`entry.jar`/`entry.json`, `index-v2.json`, `index-v1.jar`/`index-v1.json`.
`policy.json` records that key's certificate fingerprint under
`repository.fingerprint`; `history.json` holds the matching promotion records.
`other-entry.jar` is the same `entry.json` signed by a second throwaway key.

The "APKs" are not Android packages: they are the bytes
`fixture APK bytes for org.example.app version <code>\n`, which the tests write
into a temporary copy of `catalogue/` (`*.apk` is git-ignored on purpose). Both keys
were generated in a temporary directory by `make_fixture.py` and deleted; no
IndiaFOSS key or app is involved. `entry.jar` is signed with SHA-256 and
`index-v1.jar` with SHA-1, mirroring fdroidserver 2.4.5, so the deprecated-
algorithm path of `verify_index.py` is exercised.

Regenerate with `python3 tests/fixtures/index/make_fixture.py` (needs `keytool`
and `jarsigner` from a JDK); the fingerprint in `policy.json` changes each time.
