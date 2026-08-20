#!/bin/bash
set -euo pipefail

# Usage
usage() {
    echo "Usage: $0 [-h]"
    echo ""
    echo "Download jadx (if needed) and decompile the APKs from apks/ into"
    echo "sources/. Resources are kept so the native libwsm.so ends up in"
    echo "sources/samsung-accessory-service/resources/lib/armeabi/. jadx and the"
    echo "decompiled output are not committed."
    echo ""
    echo "Examples:"
    echo "  $(basename "$0")   # decompile apks/*.apk into sources/"
    exit 1
}
if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    usage
fi

cd "$(dirname "$0")/.." || exit 1   # run from the project root
JADX_VERSION="1.5.1"

if [ ! -x jadx/bin/jadx ]; then
    echo "Downloading jadx $JADX_VERSION ..."
    mkdir -p jadx
    curl -fL "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip" -o jadx.zip
    unzip -oq jadx.zip -d jadx
    rm jadx.zip
fi

decompile() {
    local name="$1"
    if [ ! -f "apks/$name.apk" ]; then
        echo "✗ apks/$name.apk not found — run scripts/download.sh first"
        exit 1
    fi
    echo "Decompiling apks/$name.apk -> sources/$name ..."
    jadx/bin/jadx -d "sources/$name" "apks/$name.apk"
}

decompile samsung-gear-360-manager
decompile samsung-accessory-service
