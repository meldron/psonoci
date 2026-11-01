# OpenSSL 3.5 LTS source override

This local Cargo patch keeps the published `openssl-sys` 0.9.117 bindings and
vendored build integration while updating the native library to OpenSSL 3.5.9
LTS. The registry's last compatible 300.x package contains OpenSSL 3.6.3; newer
400.x packages require an OpenSSL major-version migration.

`src/lib.rs` and both adapter license files are unmodified copies of the
checksum-verified `openssl-src` 300.6.1+3.6.3 crate. `upstream.json` records the
upstream commit, registry checksum and file checksums. The local package version
300.6.2+3.5.9 is unpublished; its increment allows Cargo to select this override.
The upstream OpenSSL version remains 3.5.9, as recorded in the SBOM.

OpenSSL itself is a Git submodule of the official repository, pinned to release
commit `45e844fa2a14ec92d146bd8f5778ac130b6625fb`. Its source and Apache-2.0 license
remain in that submodule. No OpenSSL source changes are made locally.

Initialize it before building:

```sh
git submodule update --init --depth 1 vendor/openssl-src/openssl
```

The evidence build helper rejects a changed adapter, wrong source version,
wrong source commit or dirty source checkout. CI checks out the direct submodule;
OpenSSL's optional test submodules are unnecessary.

For updates, select a maintained upstream 3.5 LTS release, update the gitlink and
`upstream.json`, and update this package's native-version build metadata. Verify
the official release signature, build every release target, test native TLS,
regenerate and verify the SBOMs, and re-scan the native identity. Remove this
override when compatible upstream source packages receive maintained updates.
