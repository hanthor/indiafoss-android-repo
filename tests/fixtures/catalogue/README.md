# Catalogue CI fixture

`policy.json` and `record.json` describe `tests/repo/com.example.test.helloworld_1.apk`
from the fdroidserver 2.4.5 source distribution (sha256
`f9b52646264c732678e32e37e23a995db20cc61d45622dda5830ce23255547f4`, the hash pinned in
`requirements-fdroidserver.txt`). The workflow downloads that sdist, checks the hash,
extracts the APK into a staging directory and runs `build_catalogue.py` with this
fixture policy and metadata. The `commit`, `release_id` and `asset_id` values are
placeholders: no GitHub preflight runs on the fixture. Nothing here is an IndiaFOSS app.
