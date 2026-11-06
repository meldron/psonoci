# psonoci software bill of materials

Starting with 0.7.0, each release archive has a matching CycloneDX 1.6 software bill of materials,
or SBOM.

The [primary GitLab releases](https://gitlab.com/esaqa/psono/psono-ci/-/releases)
publish archives, SBOMs and `.sig` signatures on `get.psono.com`.
[GitHub](https://github.com/meldron/psonoci) is the secondary repository; its
release builds use `.asc` signatures and include GitHub artifact attestations.

The filenames identify the release and Rust target:

```text
psonoci-<release>-<rust-target>.cdx.json
psonoci-<release>-<rust-target>.cdx.json.sig  # Primary GitLab release
psonoci-<release>-<rust-target>.cdx.json.asc  # Secondary GitHub release
```

The psonoci release SBOM policy implements selected fields and checks informed
by Regulation EU 2024/2847 (the Cyber Resilience Act) and BSI TR-03183-2 v2.1.0.
It is a project policy, not a complete CRA or BSI conformity validator. Other
CRA obligations include vulnerability handling, reporting, support periods,
and product requirements.

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
4. A final-link recorder captures the exact Rust and native library inputs in
   the build environment. A runtime collector hashes those inputs and reads
   the executable's ELF, Mach-O, or PE imports. It identifies bundled runtimes
   and direct external runtime dependencies; unresolved inputs stop the build.
5. The adapter checks the archive and executable hashes, target and commit,
   adds vendored OpenSSL and the runtime inventory, and applies the repository's
   required-field and coverage checks. Runtime evidence is embedded in the
   SBOM and covered by its detached signature.
6. The pipeline signs the archive and SBOM. The official CycloneDX CLI checks
   the SBOM against the schema before publication.
7. The publish job verifies both signatures and checks the required SBOM
   fields again. It compares the archive and executable hashes with the SBOM.
   It also reads imports from the archived executable and compares them with
   the runtime evidence. Every target must have one archive, one SBOM, and both
   signatures. Missing targets and unexpected files stop publication.

GitHub build jobs also produce GitHub artifact attestations for each archive
and SBOM, binding their digests to the workflow, runner and source commit.
The workflow commit identifies the collector and recorder implementation.
Release actions are pinned by commit and Cross by version. The captured image
digest identifies the Cross base image; pre-build hooks modify the effective
builder. Native runner and package installations are not hermetic. Attestations
authenticate build claims; they do not establish inventory completeness. GitLab
currently publishes detached signatures without this GitHub provenance layer.

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
  from the locked `openssl-src` package, the active `openssl-sys` vendored feature,
  and build-time guards rejecting environment overrides that disable vendoring
  or static linkage; and
- the BSI CycloneDX properties for executable, archive, structured-file,
  filename, and effective-license classification.

The SBOM excludes build tools, development dependencies, and procedural macros
from the delivered inventory. Direct external runtimes are identified, but
their own dependency subgraphs are not recursively inventoried. The composition
remains `incomplete`; this discloses the boundary and does not waive coverage
checks for the delivered software or its direct imports.

The Rust standard library is identified by its Rust distribution release and
source commit, with hashes of the linked sysroot libraries. Compiler builtins,
native LLVM libunwind and target startup objects are recorded separately when
linked. Their reviewed license sources and checksums are stored under
`sbom/toolchain-sources/<rust-release>/`: compiler builtins preserves its composite
SPDX expression, libunwind carries its complete notice, and startup objects use
the LLVM compiler-rt license. Toolchain upgrades require reviewing this catalog.
Distribution versions identify redistributed packages; they do not assert
registry-byte equivalence for in-tree compiler crates or resolve every upstream
source release inside the distribution.

For musl, the collector reads allocated version data in `version.lo` inside the
linked `libc.a`. It does not substitute the Cargo `libc` crate version or the
builder's installed libc version. A missing or ambiguous version stops generation.
GNU libc uses its captured release banner. GCC runtime identities require the
linked file to match the compiler's resolved runtime file by hash.
MinGW-w64 uses the runtime banner in the linked `libmingw32.a`, preserving any
snapshot qualifier. Its composite runtime and winpthreads license notices from
upstream v13.0.0 are retained in `sbom/licenses/mingw-w64-runtime-13.txt` and
embedded as a named license with full text. New runtime major versions require
reviewing their corresponding notices.

Native import archives shipped by Cargo packages are checked against their
registry file checksum or the cached `.crate` archive member. Their registry
package checksum must match `Cargo.lock`, and their owner must occur in the
runtime dependency graph. This avoids misclassifying package-owned native assets
as unidentified platform libraries.

External macOS system libraries carry their SDK link-interface versions from
Mach-O load commands, backed by linked SDK stubs. On native Windows, normal and
delay imports are resolved to build-host DLL files and file versions, including
API-set aliases. DLL entry points are not run. Version context is explicit:
neither SDK ABI versions nor build-host DLL versions establish minimum supported
deployment OS versions. Searched Windows SDK import libraries that do not
produce executable imports retain their SDK package identity and hashes, without
claiming a runtime DLL version. GNU shared-library aliases are matched to actual
executable imports using their ELF SONAME.
All SDK stubs consumed by the linker, including reexports, are identified. The
TBD v4 default interface version is 1.0 when `current-version` is omitted.
For compiler post-link Mach-O metadata processing, both original and final
binary hashes are recorded, and runtime sections, loader settings and dyld
payloads must remain identical. Code or dependency changes are rejected.

These checks do not constitute a full BSI conformity assessment. Source-level
attribution within toolchain distributions and the interpretation of external
platform version identifiers require review against the intended SBOM profile.

| Policy area | Implemented check | Remaining boundary |
| --- | --- | --- |
| Artifact binding | Full archive inventory, executable/ archive hashes, target checks, signatures | Current archives contain exactly one executable; adding files requires extending the inventory |
| Package identity | Runtime Cargo graph, reviewed native providers and exact sysroot archive hashes | Link inputs and Cargo resolution do not prove per-function retention or reachability |
| BSI properties | File classification and effective-license properties for delivered components | External runtime/interface components intentionally omit delivery-file classification; full taxonomy conformance is not claimed |
| Licensing | Manifest declarations, reviewed toolchain notices, hash-specific overrides | Declaration and nonempty fields do not establish legal applicability; some SDK labels require further review |
| Dependency completeness | Direct imports covered; unknown/partial runtime graphs scoped as incomplete | External transitive closure and exact std feature activation remain unresolved |
| Vulnerability handling | Cargo and reviewed native identity matching controls | Findings require triage; VEX/CSAF, deployment context and other CRA obligations are separate |

## Rust runtime registry packages

The shared build helper automatically expands registry crates supplied by Rust's
standard-library distribution into normal Cargo package identities for all seven
primary GitLab release targets and the additional ARMv7 musl target built by the
secondary GitHub workflow.

This runs in local builds and CI workflows that use
`scripts/build-with-runtime-evidence.py`. The helper installs the corresponding
host-side Rust target distribution and checks that its archives exactly match
the inputs captured inside Cross. Rust release and source commit must agree.
The resulting `psonoci.runtime.json` already contains the enrichment; the
normal SBOM generation command consumes it without additional flags.

Preparation downloads Rust's `library/Cargo.lock` at the captured source commit
and verifies each selected registry archive against its locked SHA-256. Package
versions, licenses, and repository URLs come from those verified manifests.
Catalogs are cached under `.sbom-tools/rust-runtime/<target>/`. A verified cache
avoids downloads, and `prepare --offline` requires all source metadata to be
cached. `prepare --refresh` explicitly replaces corrupt/stale entries. Downloads
are checksum-verified before atomic replacement. Enrichment is offline.
Ambiguous package versions, changed registry archives, and mismatching toolchain
inputs stop the build. The exact-commit HTTPS source-lock download is trusted
build input; its recorded checksum is an integrity check, not an upstream signature.

For a manual comparison using an existing capture, regenerate an unenriched
sidecar first, then prepare and enrich it. For example:

```sh
python3 scripts/runtime_evidence.py \
  --target x86_64-unknown-linux-musl \
  --binary target/x86_64-unknown-linux-musl/release/psonoci \
  --capture target/x86_64-unknown-linux-musl/release/runtime-capture \
  --output .sbom-tools/psonoci-unenriched.runtime.json

python3 scripts/enrich-rust-runtime.py prepare \
  --evidence .sbom-tools/psonoci-unenriched.runtime.json \
  --catalog .sbom-tools/rust-runtime/x86_64-unknown-linux-musl

python3 scripts/enrich-rust-runtime.py enrich \
  --evidence .sbom-tools/psonoci-unenriched.runtime.json \
  --catalog .sbom-tools/rust-runtime/x86_64-unknown-linux-musl \
  --sysroot "$(rustc --print sysroot)" \
  --output .sbom-tools/psonoci-enriched.runtime.json
```

Pass the selected sidecar with `--runtime-evidence` to the SBOM generator. Use
the same binary, archive, and Syft output for both documents. The adapter merges
shared application/sysroot package identities and retains their dependency
relationships and both sets of attribution evidence. The SBOM records the
runtime enricher's version and the verified source-lock and package checksums.

The scope is registry packages observed in supplied sysroot linker archives.
Internal Rust crates, compiler builtins, and native unwind code retain their
distribution identities. Archive input evidence does not establish retention of
every function or exploitability of a package advisory. Completeness remains
`incomplete`.

Registry edges come from the exact source lockfile and are restricted to observed
registry inputs; they do not prove feature-specific activation. Internal std
facades remain source declarations instead of backedges into the aggregate std
component. Unknown runtime subgraphs have no explicit empty dependency record;
partial graphs and their component scope remain marked incomplete.

Scanner results also depend on identifier support. Grype recognizes the Cargo
PURLs; generic native package PURLs alone may lack a supported matching identity.
The adapter emits reviewed upstream CPE mappings for musl and OpenSSL. It does
not guess CPEs for Rust/GCC distributions or build-host DLLs. CI runs isolated
positive controls for Cargo, musl and OpenSSL matching, plus a negative control.
Controls use intentionally old versions and are never added to release SBOMs.
An advisory match is a triage candidate, not proof of vulnerability reachability.

## Dependencies

Linux builds use a local Cargo override of `openssl-src` to consume the pinned
official OpenSSL 3.5.9 LTS source with the existing OpenSSL 3.x Rust bindings.
Initialize its direct source submodule with
`git submodule update --init --depth 1 vendor/openssl-src/openssl` before building.
The build helper checks the clean release commit, source version, and unchanged
upstream build adapter. The native SBOM identity includes the captured source
provenance and exact upstream Git commit. See
`vendor/openssl-src/README.psonoci.md` for maintenance instructions.

`sbom/tool-versions.env` pins the SBOM tool versions. Generation requires:

- the repository's pinned Rust toolchain and Cargo;
- `cargo-auditable` 0.7.5 at build time;
- Syft 1.50.0 at generation time; and
- Python 3.11 or newer for the psonoci adapter (GitHub uses 3.12; GitLab
  bootstraps a declared compatible interpreter on macOS and Windows).

Syft's generated tool metadata must identify the pinned version. The helper
checks cargo-auditable's Cargo installation record and records the result in
link evidence; `cargo auditable --version` forwards to Cargo and cannot verify
the plugin version. These are build checks, not executable-signature attestations.

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
python3 scripts/build-with-runtime-evidence.py --target x86_64-unknown-linux-gnu
```

For a Cross target:

```sh
python3 scripts/build-with-runtime-evidence.py \
  --target x86_64-unknown-linux-musl --cross \
  --image meldron/psonoci_builder:x86_64-unknown-linux-musl
```

Cross does not forward arbitrary Cargo plugin subcommands into its container.
`Cross.toml` installs a Cargo wrapper that runs `cargo auditable build` when
Cross calls `cargo build`.

Cross installs the wrapper while it builds the custom image, before the build
container's environment variables are available. `Cross.toml` therefore repeats
the version pin from `sbom/tool-versions.env`. A unit test checks that the pins
match. A cache marker includes the tool version so a pin change triggers
reinstallation. The custom builder Dockerfiles also install the wrapper.

The helper uses `cargo rustc` through cargo-auditable for the final application
link. It compiles a static host recorder for Cross, requiring no Python inside
the builder image. The Cross base image is resolved to an immutable digest/ID
for that build; Cross pre-build hooks still run on that base.

Raw input copies and traces are retained in
`target/<target>/release/runtime-capture/`. The collector writes
`psonoci.runtime.json` beside the executable. Generation requires that same
binary and evidence; `--runtime-evidence` can specify another evidence path.
Cargo's `--timings` report records individual build units, including the
`openssl-sys` build-script execution that compiles vendored OpenSSL. GitHub retains
these HTML reports in its diagnostic artifacts. The Linux x86_64 release job also
runs the final static executable against a disposable local HTTPS API, checking
native TLS 1.2/1.3, Rustls, and rejection of untrusted certificates/wrong hostnames.
GitLab transports this file with build artifacts. The public release asset set
stays at four files per target, because the evidence is embedded in the SBOM.
The temporary host recorder lives in the ignored `.sbom-tools/` directory so
remote Cross builds copy it with project sources. Remote builds must copy the
capture directory back as well; the helper enables full target-directory copy
for Cross versions that otherwise return only Cargo-declared artifacts.

Create the release archive from that exact binary:

```sh
tar -czf psonoci-v0.7.0-x86_64-unknown-linux-musl.tar.gz \
  -C target/x86_64-unknown-linux-musl/release psonoci
```

Then run the wrapper:

```sh
scripts/generate-sbom.sh \
  x86_64-unknown-linux-musl \
  target/x86_64-unknown-linux-musl/release/psonoci \
  psonoci-v0.7.0-x86_64-unknown-linux-musl.tar.gz \
  psonoci-v0.7.0-x86_64-unknown-linux-musl.cdx.json \
  --commit "$(git rev-parse HEAD)" \
  --release-version v0.7.0
```

The wrapper creates a temporary Syft scan and passes it to the Python script
with the pinned cargo-auditable version. It uses `SOURCE_DATE_EPOCH` for the
SBOM timestamp. If that variable is unset, it uses the latest source commit's
timestamp. The commit, target, release version, binary hash, archive hash,
timestamp, and digest of the complete runtime evidence determine the UUIDv5
serial number. Identical inputs including captured evidence reproduce the
document. A new capture records wall-clock time, absolute input paths and build
host details; identical binaries across builds need not produce identical SBOM
bytes or serials. A serial change alone does not establish a dependency change.

You can also run Syft and the Python script separately:

```sh
syft target/x86_64-unknown-linux-musl/release/psonoci \
  -o cyclonedx-json@1.6=raw-syft.cdx.json

python3 scripts/sbom.py generate \
  --target x86_64-unknown-linux-musl \
  --binary target/x86_64-unknown-linux-musl/release/psonoci \
  --artifact psonoci-v0.7.0-x86_64-unknown-linux-musl.tar.gz \
  --syft-input raw-syft.cdx.json \
  --commit "$(git rev-parse HEAD)" \
  --cargo-auditable-version 0.7.5 \
  --release-version v0.7.0 \
  --output psonoci-v0.7.0-x86_64-unknown-linux-musl.cdx.json
```

Generation stops if required data is missing, the tag and Cargo versions
disagree, or the archive contains a different binary. It also stops if Syft
misses a runtime package or dependency relationship reported by Cargo.
`sbom/overrides.json` supplies metadata that upstream packages lack. Review
these overrides when `Cargo.lock` changes.

## Unresolved runtime providers

Automatic identification is deliberately limited. An unrecognized native input
stops the build and produces `runtime-capture/unresolved-inputs.json`, listing
the original paths and SHA-512 hashes. Cross-built Windows binaries cannot use
native Windows DLL version discovery on a Linux build host. Their missing
runtime identities must be supplied using reviewed provider metadata, or the
build must run on a native Windows runner.

After verifying an input against its actual provider's source/build manifest,
add its exact hash to `sbom/runtime-providers.json`:

```json
{
  "format": 1,
  "bySha512": {
    "<128 lowercase hexadecimal characters>": {
      "name": "Actual provider component",
      "version": "1.2.3",
      "creator": "https://provider.example/",
      "license": "MIT",
      "source": "https://provider.example/releases/1.2.3",
      "method": "Verified provider build manifest and matching library checksum",
      "delivery": "bundled",
      "imports": []
    }
  }
}
```

Use `external` delivery with the exact executable import names when the provider
supplies an external runtime. First external components need identity metadata;
they are not falsely classified as non-executable delivered files. External
component licences may be omitted, while bundled runtimes require them.
Overrides do not match mutable paths, wildcard versions, or target names: an
input change requires a newly reviewed hash. Do not copy a version from an
unrelated host package or silently accept `unknown`.

## Validate and verify

Check the required SBOM fields:

```sh
python3 scripts/sbom.py validate \
  --input psonoci-v0.7.0-x86_64-unknown-linux-musl.cdx.json
```

Check that the archive and its executable match the hashes in the SBOM:

```sh
python3 scripts/sbom.py verify-release \
  --input psonoci-v0.7.0-x86_64-unknown-linux-musl.cdx.json \
  --artifact psonoci-v0.7.0-x86_64-unknown-linux-musl.tar.gz
```

Run the tests:

```sh
python3 -m unittest discover -s tests -p 'test_sbom*.py' -v
python3 scripts/test-sbom-linker.py
# Requires the pinned Grype and a current database. Add --offline to reuse one.
python3 scripts/test-sbom-scanner.py
```

Run the official schema check used by CI:

```sh
docker run --rm -v "$PWD:/work" \
  cyclonedx/cyclonedx-cli:0.33.1@sha256:252c2e26f468c25fea1e63ecde1bc3198ad6e9dbb57f5ed3236bddcb2281b3a7 \
  validate \
  --input-file /work/psonoci-v0.7.0-x86_64-unknown-linux-musl.cdx.json \
  --input-version v1_6 --fail-on-errors
```

Verify the detached signature with the psonoci release public key:

```sh
gpg --verify psonoci-v0.7.0-x86_64-unknown-linux-musl.cdx.json.sig \
  psonoci-v0.7.0-x86_64-unknown-linux-musl.cdx.json
```

For a secondary GitHub release, use its `.asc` signature instead, and verify
archive and SBOM provenance separately:

```sh
gh attestation verify psonoci-v0.7.0-x86_64-unknown-linux-musl.tar.gz --repo meldron/psonoci
gh attestation verify psonoci-v0.7.0-x86_64-unknown-linux-musl.cdx.json --repo meldron/psonoci
```

GitHub downloads the pinned Syft release through Anchore's action. GitLab
downloads the Linux archive and checks its official SHA-256. Both pipelines
require the complete asset set, valid signatures, matching hashes, the
repository's required SBOM fields, and a valid CycloneDX 1.6 document before
publication.

The SBOM excludes vulnerability findings. BSI TR-03183-2 calls for separate
vulnerability information, for example through VEX or CSAF.

## GitLab validation-only releases

The protected tags `gitlab-release-test-tag` and `gitlab-release-test-tag2`
build the existing seven GitLab targets, package and sign their archives and
SBOMs, and run the schema, signature, inventory, and static-binary TLS checks.
They do not upload to download storage or create GitLab Release entries.
Validation SBOMs omit download-server URLs because those files are not published.

Validation artifacts, including raw build outputs, are restricted to Maintainers
and Owners through GitLab's artifact download controls. Downstream CI jobs can
still fetch the artifacts through GitLab's job-token mechanisms. They expire
after one week, subject to the project's existing keep-latest setting, which can
retain the latest pipeline's artifacts longer. Cargo timing reports are retained
with the build artifacts. Production artifact access remains unchanged.

Before running a validation tag, edit the existing `GOOGLE_APPLICATION_CREDENTIALS`
variable in GitLab **Settings > CI/CD > Variables**. Change its environment scope
from `*` to `release-production`, preserving its value and protected status.
The two production upload jobs declare that environment; validation jobs do not.
A preflight job blocks validation if it receives the upload credential, lacks
the existing signing configuration, or cannot sign and verify a disposable message
with the repository's release key. Authentication and upload scripts also refuse
test tags before doing any external work.

Coordinate the setting change with the updated pipeline configuration: old
pipeline configurations without the environment declaration cannot obtain the
upload credential after its scope changes. Retrying an old job does not adopt
the new YAML. Use the updated configuration for subsequent production releases.

To recheck schemas after a validator change, run a pipeline on a branch with
`SBOM_SCHEMA_SOURCE_JOB_ID` set to the numeric ID of an existing successful
`collect-artifacts` job in this project. This selects only
`recheck-release-sbom-schemas`, downloads that job's SBOMs with the current CI job
token, and runs the same schema script and pinned validator as release pipelines.
The initiating user needs access to the source artifacts. A Maintainer-only
SHA-256 manifest identifies the exact documents checked; this does not rebuild
or re-sign binaries, or repeat the other release checks. Release tags always
run the complete pipeline, even if this variable is supplied.
