#!/bin/bash
set -euo pipefail

# Install necessary packages
apt-get update
apt-get install -y zip tar gnupg

# Authenticate with Google Cloud Storage
sh ./var/login_gcp.sh

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

  # Upload to Google Cloud Storage
  gsutil cp "$OUTPUT_FILE" "gs://get.psono.com/${CI_PROJECT_PATH}/${CI_COMMIT_TAG}/"
  gsutil cp "$SIGNATURE_FILE" "gs://get.psono.com/${CI_PROJECT_PATH}/${CI_COMMIT_TAG}/"
done