#!/bin/bash
set -euo pipefail

bash "$(dirname "$0")/release-mode.sh" production
sh ./var/login_gcp.sh

for artifact in collected_artifacts/*; do
  if [[ ! -f "$artifact" ]]; then
    echo "No collected release artifacts found" >&2
    exit 1
  fi
  gsutil cp "$artifact" "gs://get.psono.com/${CI_PROJECT_PATH}/${CI_COMMIT_TAG}/"
done
