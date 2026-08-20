#!/bin/bash
set -euo pipefail

# Usage
usage() {
    echo "Usage: $0 [-h]"
    echo ""
    echo "Build, assemble, and ad-hoc-sign macos-bluetooth-poc.app. macOS only"
    echo "grants the Bluetooth entitlement to a signed bundle whose Info.plist"
    echo "declares NSBluetoothAlwaysUsageDescription, so a raw 'cargo run' can"
    echo "never reach the camera. The .app is a generated artifact (not"
    echo "committed); this script is its source of truth."
    echo ""
    echo "Examples:"
    echo "  $(basename "$0")   # build and sign macos-bluetooth-poc.app"
    exit 1
}
if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    usage
fi

cd "$(dirname "$0")/.." || exit 1   # run from the project root

echo "Building release binary ..."
cargo build --release

echo "Assembling macos-bluetooth-poc.app ..."
mkdir -p macos-bluetooth-poc.app/Contents/MacOS
cp target/release/macos-bluetooth-poc macos-bluetooth-poc.app/Contents/MacOS/macos-bluetooth-poc
cat >macos-bluetooth-poc.app/Contents/Info.plist <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key><string>macos-bluetooth-poc</string>
    <key>CFBundleIdentifier</key><string>com.gear360.macos-bluetooth-poc</string>
    <key>CFBundleName</key><string>macos-bluetooth-poc</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleShortVersionString</key><string>0.1</string>
    <key>NSBluetoothAlwaysUsageDescription</key><string>Connect to the Gear 360 camera.</string>
</dict>
</plist>
PLIST

echo "Signing (ad-hoc) ..."
codesign --force --sign - macos-bluetooth-poc.app
echo "✓ built and signed macos-bluetooth-poc.app"
