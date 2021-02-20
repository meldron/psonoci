#!/bin/bash

set -eu

TARGETS=(
    "aarch64-unknown-linux-musl"
    "armv7-unknown-linux-musleabihf"
    "x86_64-unknown-linux-musl"
    "armv7-unknown-linux-gnueabihf"
)

cd "$(dirname "$0")"

for target in ${TARGETS[*]}; do
    image_name="meldron/psonoci_builder:$target"
    echo "Building ${image_name}"
    docker build -f "Dockerfile-$target" -t "$image_name" .
    docker push "$image_name"
done
