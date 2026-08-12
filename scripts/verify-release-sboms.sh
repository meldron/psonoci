#!/bin/bash
set -euo pipefail

if [[ $# -lt 4 ]]; then
    echo "usage: $0 <release-directory> <signature-suffix> <release-tag> <target> [target ...]" >&2
    exit 2
fi

release_dir=$1
signature_suffix=$2
release_tag=$3
shift 3
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)

python3 "$script_dir/sbom.py" validate-release-set \
    --directory "$release_dir" --signature-suffix "$signature_suffix" \
    --release-tag "$release_tag" --targets "$@"

shopt -s nullglob
sboms=("$release_dir"/*.cdx.json)
if [[ ${#sboms[@]} -eq 0 ]]; then
    echo "No SBOMs found in $release_dir" >&2
    exit 1
fi

gpg --batch --import "$script_dir/../gpg/psonoci@dfjk.eu"

for sbom in "${sboms[@]}"; do
    base=${sbom%.cdx.json}
    archives=("$base.zip" "$base.tar.gz")
    artifact=
    for candidate in "${archives[@]}"; do
        if [[ -f "$candidate" ]]; then
            if [[ -n "$artifact" ]]; then
                echo "Multiple archives match $sbom" >&2
                exit 1
            fi
            artifact=$candidate
        fi
    done
    if [[ -z "$artifact" ]]; then
        echo "No release archive matches $sbom" >&2
        exit 1
    fi

    python3 "$script_dir/sbom.py" verify-release --input "$sbom" --artifact "$artifact"
    gpg --batch --verify "${sbom}${signature_suffix}" "$sbom"
    gpg --batch --verify "${artifact}${signature_suffix}" "$artifact"
done
