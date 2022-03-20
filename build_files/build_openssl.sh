#!/bin/bash
# script by https://github.com/vimmerru

set -ex

main() {
    local version=1.1.1n
    local os=$1 \
          triple=$2

    local openssl_file="openssl-$version.tar.gz"
    local openssl_size=9850712
    local openssl_file_sha256='40dceb51a4f6a5275bde0e6bf20ef4b91bfc32ed57c0552e2e8e15463372b17a'

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

    # fix for broken certs in armv7 cross image
    curl -k --max-filesize ${openssl_size} --max-time 600 "https://www.openssl.org/source/${openssl_file}" -o "$openssl_file"
    echo "${openssl_file_sha256} ${openssl_file}" | sha256sum -c
    tar --strip-components=1 -xzf "$openssl_file"
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