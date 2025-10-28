#!/bin/bash

set -e

OUTPUT_DIR="${1:-help_command_output}"
BINARY="${2:-target/debug/psonoci}"

mkdir -p "$OUTPUT_DIR"

echo "Capturing help output to $OUTPUT_DIR using $BINARY"

# Main help
$BINARY --help > "$OUTPUT_DIR/main.txt" 2>&1

# Secret command
$BINARY secret --help > "$OUTPUT_DIR/secret.txt" 2>&1
$BINARY secret get --help > "$OUTPUT_DIR/secret_get.txt" 2>&1
$BINARY secret set --help > "$OUTPUT_DIR/secret_set.txt" 2>&1

# ApiKey command
$BINARY api-key --help > "$OUTPUT_DIR/api-key.txt" 2>&1
$BINARY api-key info --help > "$OUTPUT_DIR/api-key_info.txt" 2>&1
$BINARY api-key secrets --help > "$OUTPUT_DIR/api-key_secrets.txt" 2>&1

# Config command
$BINARY config --help > "$OUTPUT_DIR/config.txt" 2>&1
$BINARY config pack --help > "$OUTPUT_DIR/config_pack.txt" 2>&1
$BINARY config save --help > "$OUTPUT_DIR/config_save.txt" 2>&1
$BINARY config show --help > "$OUTPUT_DIR/config_show.txt" 2>&1

# Run command
$BINARY run --help > "$OUTPUT_DIR/run.txt" 2>&1

# EnvVars command
$BINARY env-vars --help > "$OUTPUT_DIR/env-vars.txt" 2>&1
$BINARY env-vars get-or-create --help > "$OUTPUT_DIR/env-vars_get-or-create.txt" 2>&1
$BINARY env-vars update-or-create --help > "$OUTPUT_DIR/env-vars_update-or-create.txt" 2>&1

# Totp command
$BINARY totp --help > "$OUTPUT_DIR/totp.txt" 2>&1
$BINARY totp get-token --help > "$OUTPUT_DIR/totp_get-token.txt" 2>&1
$BINARY totp validate-token --help > "$OUTPUT_DIR/totp_validate-token.txt" 2>&1
$BINARY totp get-url --help > "$OUTPUT_DIR/totp_get-url.txt" 2>&1

# Ssh command (if on unix)
if [[ "$OSTYPE" != "msys" ]] && [[ "$OSTYPE" != "win32" ]]; then
    $BINARY ssh --help > "$OUTPUT_DIR/ssh.txt" 2>&1
    $BINARY ssh add --help > "$OUTPUT_DIR/ssh_add.txt" 2>&1
fi

# Gpg command
$BINARY gpg --help > "$OUTPUT_DIR/gpg.txt" 2>&1
$BINARY gpg sign --help > "$OUTPUT_DIR/gpg_sign.txt" 2>&1
$BINARY gpg verify --help > "$OUTPUT_DIR/gpg_verify.txt" 2>&1

# License command
$BINARY license --help > "$OUTPUT_DIR/license.txt" 2>&1

echo "Help output captured successfully!"
echo "Files saved to: $OUTPUT_DIR"
