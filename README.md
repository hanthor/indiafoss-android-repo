# IndiaFOSS Android repository

Work in progress: this repository does **not** serve an F-Droid catalogue yet.
It will distribute reviewed Companion and Chat APKs without changing their
application signing identities. The index will use a separate signing key.

[Implementation plan and acceptance criteria](https://github.com/hanthor/indiafoss-companion/blob/main/docs/tasks/own-fdroid-repository.md)
· [Tracking issue](https://github.com/hanthor/indiafoss-companion/issues/291)

## Implemented

`apps.json` records the allowed packages, source repositories and public APK
certificate fingerprints. `verify_apk.py` checks a local APK's hash, signature,
package, version and debuggable status against an exact promotion record and
previously promoted versions. It calls Android SDK `apksigner` and `apkanalyzer`;
missing tools or failed signature verification stop validation.

A record contains `package`, `source` (`owner/repository`), a 40-character
`commit`, numeric `release_id`, `asset_id`, `version_code`, and lowercase APK
`sha256`. History is a JSON list of previous records; use `[]` only for the first
promotion. The verifier is read-only and does not copy, sign or publish anything.

```sh
python3 -m unittest discover -s tests -v
python3 verify_apk.py promotion.json staging/app.apk --history history.json
```

Unit tests exercise policy decisions and the Android-tool adapter with injected
results. They do not demonstrate real APK signature verification, an F-Droid
index, or device upgrades.

`stage_release.py` checks the source commit's required push-to-main workflows,
using the newest attempt for each workflow. It checks release/asset ownership,
then downloads, verifies and stages an APK under its package/version filename.
An existing file is re-verified, never overwritten. Downloads are limited to
256 MiB and an incomplete or rejected download leaves no staged APK.

```sh
python3 stage_release.py promotion.json --history history.json --destination staging
```

This requires GitHub CLI read access and the Android SDK tools. The promotion
record's commit is a maintainer assertion: green CI and release ownership alone
do not cryptographically attest that the APK was built from that commit. Artifact
attestations or a verified build-to-release record are still needed before
unattended promotion. API, staging and adapter tests use fixtures; real release
integration remains pending.

## Next steps

1. Bind the APK to its declared build commit using verified release provenance.
2. Exercise fetching and immutable staging plus the verifier
   against real signed APKs with pinned Android SDK tools in CI.
3. Add app metadata and a pinned fdroidserver environment, then generate and
   inspect an unsigned catalogue.
4. Provision a recoverable index key and trusted publication workflow; publish
   only generated public files, never signing config or keys.
5. Verify the signed index and rehearse direct-APK-to-repository upgrades with
   attendee data retained. Add the fingerprint-bearing PWA link only afterwards.

Chat remains excluded from publication until a signed public release is verified.
The Companion APK is currently available from its GitHub nightly release.

Tool references: [APK Analyzer](https://developer.android.com/tools/apkanalyzer),
[apksigner](https://developer.android.com/tools/apksigner).

## Real APK integration

The manually triggered **Validate real release APK** workflow installs Android
Build Tools 36.0.0 and Command-Line Tools 19.0, then runs staging against the
provided exact promotion record. It uploads a short-lived validated input
artifact, not a public catalogue. It has no signing or deployment permissions.
`history.json` is empty because no versions have been promoted yet; update it
only as part of the future durable promotion transaction.
