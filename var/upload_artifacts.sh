#!/bin/bash
set -euo pipefail

# Install necessary packages. git is a belt-and-braces fallback for deriving
# SOURCE_DATE_EPOCH when the CI commit timestamp is unavailable.
apt-get update
apt-get install -y git zip tar gnupg python3

# Deterministic SBOM timestamp. Prefer the CI commit time so generated SBOMs
# do not depend on the wall clock; fall back to the git log otherwise. Setting
# this here also means scripts/generate-sbom.sh never needs to invoke git.
if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
  if [ -n "${CI_COMMIT_TIMESTAMP:-}" ]; then
    SOURCE_DATE_EPOCH=$(date -d "$CI_COMMIT_TIMESTAMP" +%s)
  else
    SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)
  fi
  export SOURCE_DATE_EPOCH
fi

echo "Collecting binaries from build jobs and archiving them..."
mkdir -p collected_artifacts

# Import GPG private key from file
gpg --batch --yes --import "$GPG_PRIVATE_KEY"

# Define array of targets
TARGETS=(
  "x86_64-unknown-linux-musl"
  "armv7-unknown-linux-gnueabihf"
  "aarch64-unknown-linux-musl"
  "x86_64-apple-darwin"
  "aarch64-apple-darwin"
  "x86_64-pc-windows-gnu"
  "x86_64-pc-windows-msvc"
)

# Process all targets in a single loop
for TARGET in "${TARGETS[@]}"; do
  VERSION_ARGS=()
  if [[ "$CI_COMMIT_TAG" == v[0-9]* ]]; then
    VERSION_ARGS=(--release-version "$CI_COMMIT_TAG")
  fi
  if [[ "$TARGET" == *"windows"* ]]; then
    BINARY_NAME="psonoci.exe"
    BINARY_PATH="target/${TARGET}/release/${BINARY_NAME}"
    OUTPUT_FILE="collected_artifacts/psonoci-${CI_COMMIT_TAG}-${TARGET}.zip"
  else
    BINARY_NAME="psonoci"
    BINARY_PATH="target/${TARGET}/release/${BINARY_NAME}"
    OUTPUT_FILE="collected_artifacts/psonoci-${CI_COMMIT_TAG}-${TARGET}.tar.gz"
    # Ensure binary has correct permissions
    chmod 755 "$BINARY_PATH"
  fi
  SIGNATURE_FILE="${OUTPUT_FILE}.sig"
  SBOM_FILE="collected_artifacts/psonoci-${CI_COMMIT_TAG}-${TARGET}.cdx.json"
  SBOM_SIGNATURE_FILE="${SBOM_FILE}.sig"

  # Ensure binary exists
  if [[ ! -f "$BINARY_PATH" ]]; then
    echo "Binary not found: $BINARY_PATH"
    exit 1
  fi

  # Create archive
  if [[ "$TARGET" == *"windows"* ]]; then
    zip -j "$OUTPUT_FILE" "$BINARY_PATH"
  else
    tar -czf "$OUTPUT_FILE" -C "$(dirname "$BINARY_PATH")" "$(basename "$BINARY_PATH")"
  fi

  # Sign the archive
  echo "$GPG_PRIVATE_KEY_PASSPHRASE" | gpg --batch --yes --pinentry-mode loopback --passphrase-fd 0 \
    -o "$SIGNATURE_FILE" --detach-sign "$OUTPUT_FILE"

  # Syft extracts the graph embedded by cargo-auditable. The adapter adds the
  # release boundary and applies the repository's CRA/BSI policy.
  URL_ARGS=()
  if ! bash var/release-mode.sh validation; then
    URL_ARGS=(--artifact-url "https://get.psono.com/${CI_PROJECT_PATH}/${CI_COMMIT_TAG}/$(basename "$OUTPUT_FILE")")
  fi
  scripts/generate-sbom.sh \
    "$TARGET" "$BINARY_PATH" "$OUTPUT_FILE" "$SBOM_FILE" \
    "${URL_ARGS[@]}" \
    --commit "$CI_COMMIT_SHA" \
    "${VERSION_ARGS[@]}"
  echo "$GPG_PRIVATE_KEY_PASSPHRASE" | gpg --batch --yes --pinentry-mode loopback --passphrase-fd 0 \
    -o "$SBOM_SIGNATURE_FILE" --detach-sign "$SBOM_FILE"
done
