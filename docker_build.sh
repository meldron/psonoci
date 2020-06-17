#!/bin/bash

set -e

CACHE_DIR=docker_cache
BUILD_DIR=build
IMAGE_NAME=psonoci-builder

cd "$(dirname "$0")"

mkdir -p "${CACHE_DIR}/cargo-registry"
mkdir -p "${CACHE_DIR}/git"
mkdir -p "${CACHE_DIR}/target"

mkdir -p "${BUILD_DIR}"

sudo docker build . -t "$IMAGE_NAME"

sudo docker run --rm -it \
    -v "$(pwd)/${CACHE_DIR}/git:/home/rust/.cargo/git" \
    -v "$(pwd)/${CACHE_DIR}/cargo-registry":/home/rust/.cargo/registry \
    -v "$(pwd)/${CACHE_DIR}/target:/home/rust/src/target" \
    "$IMAGE_NAME" cargo build --release

cp "${CACHE_DIR}/target/x86_64-unknown-linux-musl/release/psoco" "${BUILD_DIR}"
strip "${BUILD_DIR}/psoco"