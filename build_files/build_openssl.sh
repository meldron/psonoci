#!/bin/bash
# script by https://github.com/vimmerru

set -ex

main() {
    local version=1.1.1l
    local os=$1 \
          triple=$2

    local dependencies=(
        ca-certificates
        curl
        m4
        make
        perl
    )

    # NOTE cross toolchain must be already installed
    apt-get update
    local purge_list=()
    for dep in "${dependencies[@]}"; do
        if ! dpkg -L "$dep"; then
            apt-get install --no-install-recommends -y "$dep"
            purge_list+=( "$dep" )
        fi
    done

    td=$(mktemp -d)

    local disable_secure_memory=""

    if [ -n "$NO_SECURE_MEMORY" ]
    then
        disable_secure_memory="-DOPENSSL_NO_SECURE_MEMORY"
    fi

    pushd "$td"
    curl https://www.openssl.org/source/openssl-$version.tar.gz | \
        tar --strip-components=1 -xz
    AR=${triple}ar CC=${triple}gcc ./Configure \
      shared \
      --prefix=/openssl \
      no-dso \
      "$os" \
      -fPIC $disable_secure_memory \
      "${@:3}"
    nice make -j"$(nproc)"
    make install_sw

    # clean up
    apt-get purge --auto-remove -y "${purge_list[@]}"

    popd

    rm -rf "$td"
    rm "$0"
}

main "${@}"