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

Unit tests exercise policy decisions and the Android-tool and fdroid adapters
with injected results. They do not demonstrate real APK signature verification,
a signed F-Droid index, or device upgrades.

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

## Unsigned catalogue generation

`metadata/<package>.yml` holds fdroidserver app metadata (names, summaries,
descriptions, source, issue and changelog links, licence, categories) taken from
the source repositories. Companion is labelled a reviewed **Preview**. Chat has
metadata only: it is `Disabled` there and `"published": false` in `apps.json`,
so `fdroid update` omits it and `build_catalogue.py` refuses its APKs until its
signed public APK and upgrade path are verified. `config/categories.yml` defines
the categories the metadata uses.

`requirements-fdroidserver.txt` pins fdroidserver 2.4.5 with hashes for every
dependency; install it with `--require-hashes`. `config.yml.example` documents
the repository URL, name and description and the index-key settings that a
publisher would fill in. It contains no key and is the only config file that
may be committed.

`build_catalogue.py` takes staged APKs from `stage_release.py`'s destination,
matches each to an exact promotion record from `history.json` or `--record`,
re-validates the record and the bytes, refuses unpublished packages, copies the
APKs and metadata into a work directory, runs `fdroid update --pretty`, then
checks the generated index: every listed version must be a staged one with the
recorded SHA-256 and policy signer, every file must exist with those bytes, the
suggested version must be a staged one, and no signing material may be in the
output. Without `--config` the index is UNSIGNED and carries an ephemeral
placeholder key whose fingerprint must never be published. With a `--config`
that names `repo_keyalias`/`keystore`, the keystore and both passwords must be
present and `index-v1.jar`/`entry.jar` must be produced, otherwise it fails.

```sh
python3 -m pip install --require-hashes -r requirements-fdroidserver.txt
export PATH="$ANDROID_HOME/build-tools/36.0.0:$PATH"   # apksigner for fdroid update
python3 build_catalogue.py --staging staging --history history.json \
  --record promotion.json --workdir build
(cd build && fdroid lint)
```

`fdroid update` needs a JDK (`keytool`, `jar`) and `apksigner`. The **Repository
checks** workflow generates an unsigned catalogue from a fixture APK taken from
the hash-pinned fdroidserver source distribution (`tests/fixtures/catalogue/`)
and uploads it as an artifact only; the manual real-APK workflow does the same
with the staged Companion APK. Neither has keys or deployment permissions.
`.gitignore` and a CI check keep `*.apk`, keystores, `config.yml`, `repo/`,
`staging/` and `build/` out of git.

## Next steps

1. Bind the APK to its declared build commit using verified release provenance.
2. Exercise fetching and immutable staging plus the verifier
   against real signed APKs with pinned Android SDK tools in CI.
3. Provision a recoverable index key and trusted publication workflow; publish
   only generated public files, never signing config or keys. No key exists yet
   and nothing is deployed.
4. Verify the signed index against the separately recorded fingerprint and
   rehearse direct-APK-to-repository upgrades with attendee data retained. Add
   the fingerprint-bearing PWA link only afterwards.

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
