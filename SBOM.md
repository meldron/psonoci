# psonoci software bill of materials

Each release archive has a matching CycloneDX 1.6 software bill of materials,
or SBOM. The filenames identify the release and Rust target:

```text
psonoci-<release>-<rust-target>.cdx.json
psonoci-<release>-<rust-target>.cdx.json.asc  # GitHub
psonoci-<release>-<rust-target>.cdx.json.sig  # GitLab
```

The repository's SBOM checks are based on Regulation EU 2024/2847, the Cyber
Resilience Act, and BSI TR-03183-2 v2.1.0. Other CRA obligations include
vulnerability handling, reporting, support periods, and product requirements.
The SBOM alone does not establish CRA conformity.

## How it works

The release pipeline builds and checks each SBOM as follows:

1. `cargo-auditable` 0.7.5 builds the executable and embeds its resolved Cargo
   dependency graph in the binary.
2. Syft 1.50.0 scans the executable. Its
   `cargo-auditable-binary-cataloger` reads the embedded packages and dependency
   graph, then writes a CycloneDX 1.6 document.
3. `scripts/sbom.py` compares the scan with `cargo tree`. It excludes build-only
   crates and procedural macros. The scan must contain every runtime package
   and dependency relationship that Cargo reports. Syft may omit dependency
   records for packages with no dependencies and include additional
   relationships found in the binary.
4. The script checks the archive contents and executable format, calculates
   their hashes, records the target and commit, and adds vendored OpenSSL. It
   also checks the repository's required SBOM fields.
5. The pipeline signs the archive and SBOM. The official CycloneDX CLI checks
   the SBOM against the schema before publication.
6. The publish job verifies both signatures and checks the required SBOM
   fields again. It compares the archive and executable hashes with the SBOM.
   Every expected target must have exactly one archive, one SBOM, and both
   signatures. Missing targets and unexpected files stop publication.

New GitHub releases stay in draft during the build and checks. The workflow
uploads the files to the release's Assets section and checks that the uploaded
filenames match the validated set. It then publishes the release. Failed runs
of a new release leave its draft for inspection. The workflow refuses to modify published
releases except for the rolling `release-test` release, whose assets may be
replaced by later runs. It publishes `release-test` and release-candidate tags
as prereleases without marking them as the latest stable release.

## What is included

Each SBOM describes one target's release archive and includes:

- the archive and executable filenames and SHA-512 hashes;
- the executable's Rust target, checked against its architecture, and the hash
  of the matching executable in the archive;
- the release version, commit, timestamp, and tools used to generate the SBOM;
- all transitive runtime Rust packages found in the binary;
- dependency relationships, exact versions, Package URLs, SPDX license
  expressions, and creator or project identity;
- vendored OpenSSL as a native component, with the upstream version derived
  from the locked `openssl-src` package; and
- the BSI CycloneDX properties for executable, archive, structured-file,
  filename, and effective-license classification.

The SBOM excludes build tools, development dependencies, and procedural
macros. Build provenance should record those dependencies. It also excludes
runtime libraries supplied by the operating system outside the archive. The
CycloneDX composition is marked `incomplete` because the SBOM does not describe
the destination system.

For musl targets, the SBOM states that musl libc is statically linked and that
its exact version is unknown. The current tooling cannot determine that
version from the external Cross build image.

## Dependencies

`sbom/tool-versions.env` pins the SBOM tool versions. Generation requires:

- the repository's pinned Rust toolchain and Cargo;
- `cargo-auditable` 0.7.5 at build time;
- Syft 1.50.0 at generation time; and
- Python 3 for the psonoci adapter.

The Python script uses only the standard library and needs no package
installation or virtual environment. If it gains third-party dependencies,
add `pyproject.toml` and `uv.lock` in the same change and run it with `uv run`.

Docker runs the same official CycloneDX schema validator used in CI. The build
and SBOM scripts do not require it for native builds.

## Generate locally

Install the pinned build and scan tools once:

```sh
set -a
. sbom/tool-versions.env
set +a
cargo install --locked cargo-auditable --version "$CARGO_AUDITABLE_VERSION"

# Install "$SYFT_VERSION" using an official Anchore package or release archive,
# then confirm the version:
syft version
```

Build the executable with embedded dependency data. For a native Linux build:

```sh
cargo auditable build --locked --release
```

For a Cross target:

```sh
cross build --locked --release \
  --target x86_64-unknown-linux-musl
```

Cross does not forward arbitrary Cargo plugin subcommands into its container.
`Cross.toml` installs a Cargo wrapper that runs `cargo auditable build` when
Cross calls `cargo build`.

Cross installs the wrapper while it builds the custom image, before the build
container's environment variables are available. `Cross.toml` therefore repeats
the version pin from `sbom/tool-versions.env`. A unit test checks that the pins
match. A cache marker includes the tool version so a pin change triggers
reinstallation. The custom builder Dockerfiles also install the wrapper.

Create the release archive from that exact binary:

```sh
tar -czf psonoci-v0.6.0-x86_64-unknown-linux-musl.tar.gz \
  -C target/x86_64-unknown-linux-musl/release psonoci
```

Then run the wrapper:

```sh
scripts/generate-sbom.sh \
  x86_64-unknown-linux-musl \
  target/x86_64-unknown-linux-musl/release/psonoci \
  psonoci-v0.6.0-x86_64-unknown-linux-musl.tar.gz \
  psonoci-v0.6.0-x86_64-unknown-linux-musl.cdx.json \
  --commit "$(git rev-parse HEAD)" \
  --release-version v0.6.0
```

The wrapper creates a temporary Syft scan and passes it to the Python script
with the pinned cargo-auditable version. It uses `SOURCE_DATE_EPOCH` for the
SBOM timestamp. If that variable is unset, it uses the latest source commit's
timestamp. The commit, target, release version, binary hash, archive hash, and
timestamp determine the UUIDv5 serial number.

You can also run Syft and the Python script separately:

```sh
syft target/x86_64-unknown-linux-musl/release/psonoci \
  -o cyclonedx-json@1.6=raw-syft.cdx.json

python3 scripts/sbom.py generate \
  --target x86_64-unknown-linux-musl \
  --binary target/x86_64-unknown-linux-musl/release/psonoci \
  --artifact psonoci-v0.6.0-x86_64-unknown-linux-musl.tar.gz \
  --syft-input raw-syft.cdx.json \
  --commit "$(git rev-parse HEAD)" \
  --cargo-auditable-version 0.7.5 \
  --release-version v0.6.0 \
  --output psonoci-v0.6.0-x86_64-unknown-linux-musl.cdx.json
```

Generation stops if required data is missing, the tag and Cargo versions
disagree, or the archive contains a different binary. It also stops if Syft
misses a runtime package or dependency relationship reported by Cargo.
`sbom/overrides.json` supplies metadata that upstream packages lack. Review
these overrides when `Cargo.lock` changes.

## Validate and verify

Check the required SBOM fields:

```sh
python3 scripts/sbom.py validate \
  --input psonoci-v0.6.0-x86_64-unknown-linux-musl.cdx.json
```

Check that the archive and its executable match the hashes in the SBOM:

```sh
python3 scripts/sbom.py verify-release \
  --input psonoci-v0.6.0-x86_64-unknown-linux-musl.cdx.json \
  --artifact psonoci-v0.6.0-x86_64-unknown-linux-musl.tar.gz
```

Run the tests:

```sh
python3 -m unittest discover -s tests -p 'test_sbom.py' -v
```

Run the official schema check used by CI:

```sh
docker run --rm -v "$PWD:/work" \
  cyclonedx/cyclonedx-cli:0.33.1@sha256:252c2e26f468c25fea1e63ecde1bc3198ad6e9dbb57f5ed3236bddcb2281b3a7 \
  validate \
  --input-file /work/psonoci-v0.6.0-x86_64-unknown-linux-musl.cdx.json \
  --input-version v1_6 --fail-on-errors
```

Verify the detached signature with the psonoci release public key:

```sh
gpg --verify psonoci-v0.6.0-x86_64-unknown-linux-musl.cdx.json.asc \
  psonoci-v0.6.0-x86_64-unknown-linux-musl.cdx.json
```

GitHub downloads the pinned Syft release through Anchore's action. GitLab
downloads the Linux archive and checks its official SHA-256. Both pipelines
require the complete asset set, valid signatures, matching hashes, the
repository's required SBOM fields, and a valid CycloneDX 1.6 document before
publication.

The SBOM excludes vulnerability findings. BSI TR-03183-2 calls for separate
vulnerability information, for example through VEX or CSAF.
