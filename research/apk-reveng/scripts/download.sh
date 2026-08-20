#!/bin/bash
set -euo pipefail

# Usage
usage() {
    echo "Usage: $0 [-h]"
    echo ""
    echo "Fetch + verify the two Android APKs the protocol was reverse-engineered"
    echo "from, into apks/. The mirrors serve token'd download pages (not"
    echo "hotlinkable), so download from the printed page and save the file into"
    echo "apks/, or pass a direct URL via an env var. The pinned sha256 sums are of"
    echo "the exact files this project used."
    echo ""
    echo "Examples:"
    echo "  $(basename "$0")                              # verify apks/, or print where to download"
    echo "  MANAGER_APK_URL=https://... $(basename "$0")   # download the manager APK directly"
    echo ""
    echo "Environment:"
    echo "  MANAGER_APK_URL     Direct URL for samsung-gear-360-manager.apk"
    echo "  ACCESSORY_APK_URL   Direct URL for samsung-accessory-service.apk"
    exit 1
}
if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    usage
fi

cd "$(dirname "$0")/.." || exit 1   # run from the project root
mkdir -p apks

sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    else
        shasum -a 256 "$1" | cut -d' ' -f1
    fi
}

fetch() {
    local name="$1" url_var="$2" want="$3" src="$4" url got
    if [ ! -f "apks/$name" ]; then
        url="${!url_var:-}"
        if [ -n "$url" ]; then
            echo "Downloading $name ..."
            curl -fL "$url" -o "apks/$name"
        else
            echo "✗ MISSING apks/$name — download it and save it there:"
            echo "    $src"
            echo "  (or set $url_var=<direct-url> and re-run)"
            return
        fi
    fi
    got="$(sha256 "apks/$name")"
    if [ "$got" = "$want" ]; then
        echo "✓ $name verified"
    else
        echo "⚠ $name sha256 mismatch (different build than this project used)"
        echo "    expected $want"
        echo "    actual   $got"
    fi
}

# Gear 360 Manager v1.0.4 (code 25) — the original Gear 360 (SM-C200) release.
fetch samsung-gear-360-manager.apk MANAGER_APK_URL 1eace97f852cfa7ba3835cd6313e5e5b80a44daae13f1161d24601c5f7e43c53 "https://www.apkmirror.com/apk/samsung-electronics-co-ltd/samsung-gear-360-manager/samsung-gear-360-manager-1-0-4-release/"

# Samsung Accessory Service v3.0.16_160502 (code 366).
fetch samsung-accessory-service.apk ACCESSORY_APK_URL bac2e304d109b1f47fb54e677e8ed86f58d3f6beb45fe89aa1459a4e78a31109 "https://www.apkmirror.com/apk/samsung-electronics-co-ltd/samsung-accessory-service/samsung-accessory-service-3-0-16_160502-release/"
