#!/usr/bin/env bash
set -euo pipefail

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
bash "$script_dir/check_release_validation.sh"
signing_check=$(mktemp -d)
cleanup() {
  gpgconf --homedir "$signing_check/signer" --kill gpg-agent >/dev/null 2>&1 || true
  rm -rf -- "$signing_check"
}
trap cleanup EXIT
mkdir -m 700 "$signing_check/signer" "$signing_check/verifier"

# Exercise the existing signing configuration without retaining a private key
# or test signature in artifacts. Verify with the repository's public key.
gpg --homedir "$signing_check/signer" --batch --import "$GPG_PRIVATE_KEY"
printf '%s\n' 'psonoci validation signing preflight' > "$signing_check/message"
printf '%s\n' "$GPG_PRIVATE_KEY_PASSPHRASE" |
  gpg --homedir "$signing_check/signer" --batch --yes --pinentry-mode loopback \
    --passphrase-fd 0 --detach-sign --output "$signing_check/signature" "$signing_check/message"
gpg --homedir "$signing_check/verifier" --batch --import "$script_dir/../gpg/psonoci@dfjk.eu"
gpg --homedir "$signing_check/verifier" --batch --verify "$signing_check/signature" "$signing_check/message"
echo "Signing preflight passed against the repository release public key"
