#!/bin/sh
# Use the pinned CycloneDX CLI image in CI; keep argument boundaries explicit.
set -eu

directory=${1:?Usage: validate-sbom-schemas.sh DIRECTORY}
set -- "$directory"/*.cdx.json
if [ ! -f "$1" ]; then
    echo "No CycloneDX SBOMs found in $directory" >&2
    exit 1
fi

for sbom do
    echo "Validating $sbom"
    /cyclonedx validate \
        --input-file "$sbom" \
        --input-format json \
        --input-version v1_6 \
        --fail-on-errors
done
