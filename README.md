# IndiaFOSS Android repository

Work in progress: this repository does **not** serve an F-Droid catalogue yet.
It will distribute reviewed Companion and Chat APKs without changing their
application signing identities. The index will use a separate signing key,
which has not been created; the publish workflow refuses to run until it is.

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
`staging/`, `build/` and `site/` out of git.

## Signed index verification

`apps.json` now has a `repository` entry with the public `address` and the
index key's certificate `fingerprint` (64 lowercase hex characters). The
fingerprint is **empty** because no index key exists yet.

`verify_index.py` takes a generated or downloaded `repo/` directory and checks
the whole chain from the signature to the APK bytes: `entry.jar` must carry
exactly one signer certificate whose SHA-256 equals the recorded fingerprint and
`jarsigner -strict -verify` must accept it (exit status 4, a verified
self-signed JAR, as fdroidserver itself requires); `index-v1.jar` must be signed
by the same certificate (SHA-1 digests are tolerated there only, with the same
`java.security` override fdroidserver uses); the `entry.json`/`index-v1.json`
inside the JARs must be byte-identical to the plain files; `entry.json` must name
`index-v2.json` with its real SHA-256 and size; every version in `index-v2.json`
and `index-v1.json` must be an exact promotion record from `history.json` (or
`--record`), exist as `<package>_<versionCode>.apk` with the recorded bytes, be
signed by the policy certificate, have distinct version codes that increase
through history, and every promoted version of a published package must be
listed. `--deployable` also refuses `status/`, secret-looking files and anything
outside the public file set.

With no fingerprint recorded the command prints `UNSIGNED CATALOGUE` and exits
with status 2 instead of passing. `--expect-unsigned` is only for preview
artifacts: it runs the content checks and requires that nothing in the output is
signed. Read-only; it never signs or deploys.

```sh
python3 verify_index.py build/repo --history history.json [--record promotion.json]
python3 verify_index.py build/repo --history history.json --record promotion.json --expect-unsigned
python3 publish_site.py build/repo site        # copies only public files to site/fdroid/repo/
python3 verify_index.py site/fdroid/repo --history history.json --deployable
```

`tests/fixtures/index/` holds a catalogue signed by a throwaway key (see its
README); the unit tests cover the fingerprint, signature-structure, hash,
history and version-code decisions with an injected jarsigner, and run the real
`jarsigner` when a JDK is present. The **Repository checks** workflow also
rehearses the complete signed path in CI with a throwaway key created and
destroyed on the runner: sign the fixture catalogue, verify against the
throwaway fingerprint, assemble the deploy set, verify again, and confirm a
wrong fingerprint is rejected. Nothing from that job is uploaded.

## Publication workflow (fail closed)

`.github/workflows/publish.yml` is manual only (`workflow_dispatch`) and does
nothing unless all of the following hold, in this order: the secrets
`FDROID_KEYSTORE_B64`, `FDROID_KEYSTORE_PASS` and `FDROID_KEY_ALIAS` exist
(none has been created), `apps.json` records a fingerprint, and the keystore in
the secret actually holds the key with that fingerprint. It then runs the unit
tests, re-downloads every APK in `history.json` (plus an optional
`promotion_record` input) from its immutable release asset through
`stage_release.py`, materialises the key under `$RUNNER_TEMP`, generates and
signs the index with `build_catalogue.py --config`, deletes the key material,
runs `verify_index.py`, copies only the public files with `publish_site.py` into
`site/fdroid/repo/`, verifies that tree again with `--deployable`, and only then
uploads it. The `dry_run` input (default **true**) stops there and uploads the
signed tree as a workflow artifact; a non-dry run from `main` deploys it to
GitHub Pages with `actions/deploy-pages`. Deployment needs Pages configured with
"GitHub Actions" as the source and a `github-pages` environment; neither exists
yet. No job has `contents: write`: `config.yml`, keystores and APKs never enter
git, and the top-level `permissions` is empty.

Dispatching the workflow today stops at the first gate with
"FDROID_KEYSTORE_B64, FDROID_KEYSTORE_PASS and FDROID_KEY_ALIAS are not all
configured … refusing to publish (fail closed)".

## Maintainer steps that remain

### 1. Provision the index key (once, on a trusted machine)

The index key is separate from both application signing keys and is never
regenerated on an ordinary build.

```sh
keytool -genkeypair -keystore indiafoss-preview-index.p12 -storetype PKCS12 \
  -alias indiafoss-preview-index -keyalg RSA -keysize 4096 -validity 10000 \
  -dname "CN=IndiaFOSS Preview repository index, O=IndiaFOSS Companion community"
keytool -exportcert -keystore indiafoss-preview-index.p12 \
  -alias indiafoss-preview-index -file indiafoss-preview-index.der
sha256sum indiafoss-preview-index.der      # -> repository.fingerprint (lowercase hex)
base64 -w0 indiafoss-preview-index.p12     # -> FDROID_KEYSTORE_B64 secret
```

Use one password for the PKCS#12 store and the key (keytool requires this for
PKCS#12); it becomes `FDROID_KEYSTORE_PASS`. `FDROID_KEY_ALIAS` is
`indiafoss-preview-index`. Make the key recoverable before anything is
published: put the `.p12` and its password in the maintainers' shared password
manager and on one offline copy, then prove the backup by running
`keytool -list -keystore <copy>` from it. Losing the key means every installed
client has to remove and re-add the repository. Never commit the `.p12`,
the password, or a filled-in `config.yml`; `.gitignore` and CI refuse them.

Record the fingerprint in `apps.json` (`repository.fingerprint`) in a pull
request. That commit is the trust anchor: `verify_index.py` and the publish
workflow compare the signed index and the secret keystore against it.

### 2. First signed publication

Enable GitHub Pages with source "GitHub Actions" and create the `github-pages`
environment restricted to `main`. Add the three secrets. Run **Publish signed
catalogue** with `dry_run` = true first and inspect the
`signed-catalogue-dry-run` artifact; then run it with `dry_run` = false from
`main`. The catalogue is served at `https://hanthor.github.io/indiafoss-android-repo/fdroid/repo/`.
`history.json` is still empty, so the first run also needs the first
`promotion_record` and, as part of the same promotion transaction, a pull
request that appends it to `history.json`.

### 3. "Add repository" link the PWA will show (only after step 4 passes)

Clients pin the repository by its fingerprint, shown as uppercase hex without
colons. The link, copyable URL and QR code carry the same value:

```
fdroidrepos://hanthor.github.io/indiafoss-android-repo/fdroid/repo?fingerprint=<FINGERPRINT>
https://hanthor.github.io/indiafoss-android-repo/fdroid/repo?fingerprint=<FINGERPRINT>
```

where `<FINGERPRINT>` is `repository.fingerprint` from `apps.json` in
uppercase. Publish the fingerprint alongside the link (and in the Companion
docs) so users can compare it with what their client shows; never publish the
placeholder fingerprint from an unsigned preview.

### 4. Device upgrade rehearsal (remaining acceptance)

On a real device, for Companion (and later Chat):

1. Install the current direct-download APK from the GitHub release, open the
   app, and create data that must survive: rate a few talks, build an itinerary,
   add a note and a contact, change a setting.
2. Add the repository in F-Droid using the fingerprint link and confirm the
   client shows the recorded fingerprint and lists the app as **installed**
   with an update available (or up to date) rather than as a different app.
3. Install the update from the repository. It must install in place (same
   package and same application signing certificate, no uninstall prompt) and
   all data from step 1 must still be there.
4. Repeat step 2–3 with a second compatible client (for example Droid-ify or
   Neo Store).
5. Repeat for the reverse path: installed from the repository, then sideload
   the next direct-download APK; data must again be retained.
6. Record the device, Android version, client versions, version codes and the
   outcome in the tracking issue. Only after this passes add the
   fingerprint-bearing link to the PWA.

## Next steps

1. Bind the APK to its declared build commit using verified release provenance.
2. Exercise fetching and immutable staging plus the verifier
   against real signed APKs with pinned Android SDK tools in CI.
3. Maintainer: provision the recoverable index key, record its fingerprint in
   `apps.json`, create the three secrets, enable Pages, and run the publish
   workflow (dry run, then real). No key exists yet and nothing is deployed.
4. Maintainer: run the device upgrade rehearsal above with attendee data
   retained. Add the fingerprint-bearing PWA link only afterwards.

Chat remains excluded from publication until a signed public release is verified.
The Companion APK is currently available from its GitHub nightly release.

Tool references: [APK Analyzer](https://developer.android.com/tools/apkanalyzer),
[apksigner](https://developer.android.com/tools/apksigner),
[F-Droid repository setup](https://f-droid.org/en/docs/Setup_an_F-Droid_App_Repo/),
[F-Droid signing process](https://f-droid.org/docs/Signing_Process/).

## Real APK integration

The manually triggered **Validate real release APK** workflow installs Android
Build Tools 36.0.0 and Command-Line Tools 19.0, then runs staging against the
provided exact promotion record. It uploads a short-lived validated input
artifact, not a public catalogue. It has no signing or deployment permissions.
`history.json` is empty because no versions have been promoted yet; update it
only as part of the future durable promotion transaction.
