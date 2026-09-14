#!/bin/sh
set -eu

# GitHub Ubuntu runners also carry unrelated browser/vendor repositories.
# Native build dependencies use only the runner's signed Ubuntu sources;
# source files and APT signature/hash verification remain unchanged.
if [ "$#" -eq 0 ]; then
    echo "Usage: ci-install-ubuntu-deps.sh package..." >&2
    exit 2
fi

ubuntu_apt() {
    sudo apt-get \
        -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/ubuntu.sources \
        -o Dir::Etc::sourceparts=/dev/null \
        "$@"
}

ubuntu_apt update
ubuntu_apt install -y "$@"
