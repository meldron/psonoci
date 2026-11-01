#!/usr/bin/env bash
set -euo pipefail

bash "$(dirname "$0")/release-mode.sh" validation
if [[ "${CI_COMMIT_REF_PROTECTED:-}" != true ]]; then
  echo "Release validation requires one of the protected test tags" >&2
  exit 1
fi
if [[ ${GOOGLE_APPLICATION_CREDENTIALS+x} ]]; then
  echo "Validation must not receive GOOGLE_APPLICATION_CREDENTIALS; restrict its GitLab environment scope to release-production" >&2
  exit 1
fi
if [[ ! -f "${GPG_PRIVATE_KEY:-}" || ${GPG_PRIVATE_KEY_PASSPHRASE+x} != x ]]; then
  echo "Validation requires the existing GPG key file and signing passphrase" >&2
  exit 1
fi
echo "Validation isolation checked: protected test tag, signing configured, no GCP upload credential"
