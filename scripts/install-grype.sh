#!/bin/sh
# The scanner controls currently run on Linux x86_64 CI hosts only.
set -eu
if [ "$#" -ne 1 ] || [ "$(uname -s)" != Linux ] || [ "$(uname -m)" != x86_64 ]; then
    echo "usage: $0 <install-directory> (Linux x86_64 only)" >&2
    exit 2
fi
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
. "$script_dir/../sbom/tool-versions.env"
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT HUP INT TERM
curl --proto '=https' --tlsv1.2 -fsSL \
    "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_amd64.tar.gz" \
    -o "$temporary/grype.tar.gz"
printf '%s  %s\n' "$GRYPE_LINUX_AMD64_SHA256" "$temporary/grype.tar.gz" | sha256sum -c -
mkdir -p "$1"
tar -xzf "$temporary/grype.tar.gz" -C "$1" grype
"$1/grype" version
