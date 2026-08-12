#!/bin/sh
set -eu

if [ "$#" -lt 4 ]; then
    echo "usage: $0 <target> <binary> <archive> <output.cdx.json> [adapter options]" >&2
    exit 2
fi

target=$1
binary=$2
archive=$3
output=$4
shift 4

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# Resolved relative to this script at runtime.
# shellcheck disable=SC1091
. "$script_dir/../sbom/tool-versions.env"

if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
    SOURCE_DATE_EPOCH=$(git -C "$script_dir/.." log -1 --format=%ct)
    export SOURCE_DATE_EPOCH
fi

syft_output=$(mktemp "${TMPDIR:-/tmp}/psonoci-syft.XXXXXX.json")
trap 'rm -f "$syft_output"' EXIT HUP INT TERM

SYFT_CHECK_FOR_APP_UPDATE=false SYFT_CACHE_DIR='' \
    "${SYFT:-syft}" "$binary" -o "cyclonedx-json@1.6=$syft_output"
python3 "$script_dir/sbom.py" generate \
    --target "$target" \
    --binary "$binary" \
    --artifact "$archive" \
    --syft-input "$syft_output" \
    --output "$output" \
    --cargo-auditable-version "$CARGO_AUDITABLE_VERSION" \
    "$@"
