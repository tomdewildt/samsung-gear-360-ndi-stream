#!/bin/bash
set -euo pipefail

# Usage
usage() {
    echo "Usage: $0 [-h]"
    echo ""
    echo "Download the musl ARM cross-compiler used to build the WSM tools,"
    echo "extracted into arm-linux-musleabi-cross/ (not committed). Equivalent to"
    echo "'make init'."
    echo ""
    echo "Examples:"
    echo "  $(basename "$0")   # fetch the toolchain if missing"
    exit 1
}
if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    usage
fi

cd "$(dirname "$0")/.." || exit 1   # run from the project root

if [ -x arm-linux-musleabi-cross/bin/arm-linux-musleabi-gcc ]; then
    echo "✓ toolchain already present"
    exit 0
fi

echo "Downloading arm-linux-musleabi cross toolchain (musl.cc) ..."
curl -fL "https://musl.cc/arm-linux-musleabi-cross.tgz" -o toolchain.tgz
tar -xzf toolchain.tgz
rm toolchain.tgz
echo "✓ extracted arm-linux-musleabi-cross/"
