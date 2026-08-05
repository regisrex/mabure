#!/bin/bash
# Builds mabured (root daemon) and Mabure (menu bar agent) as universal2
# binaries using swiftc directly — no Xcode project, no SPM package
# resolution, so this works offline with just the Command Line Tools.
set -euo pipefail

cd "$(dirname "$0")"

SDK_PATH="$(xcrun --sdk macosx --show-sdk-path 2>/dev/null)" || {
    echo "ERROR: no macOS SDK resolvable via xcrun. Install/select Xcode Command Line Tools" >&2
    echo "       (xcode-select --install), then re-run." >&2
    exit 1
}

mkdir -p build/arm64 build/x86_64

for ARCH in arm64 x86_64; do
    echo "==> Building mabured (${ARCH})"
    swiftc Sources/mabured/*.swift \
        -target "${ARCH}-apple-macos13.0" \
        -sdk "$SDK_PATH" \
        -O \
        -import-objc-header Sources/mabured/DaemonShim.h \
        -o "build/${ARCH}/mabured"

    echo "==> Building Mabure (${ARCH})"
    swiftc Sources/Mabure/*.swift \
        -target "${ARCH}-apple-macos13.0" \
        -sdk "$SDK_PATH" \
        -O \
        -framework AppKit -framework UserNotifications \
        -o "build/${ARCH}/Mabure"
done

echo "==> Creating universal2 binaries via lipo"
lipo -create -output build/mabured build/arm64/mabured build/x86_64/mabured
lipo -create -output build/Mabure  build/arm64/Mabure  build/x86_64/Mabure
lipo -info build/mabured build/Mabure

echo "==> Assembling Mabure.app bundle"
APP="build/Mabure.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp Resources/Info.plist "$APP/Contents/Info.plist"
cp build/Mabure "$APP/Contents/MacOS/Mabure"
cp Resources/AppIcon.icns "$APP/Contents/Resources/AppIcon.icns"
# Menu bar glyphs are loose PNGs (name + @2x) directly in Resources/, which is
# how NSImage(named:) resolves Retina variants without an asset catalog.
cp Resources/MenuBarIcons/*.png "$APP/Contents/Resources/"

echo "==> Build complete: build/mabured, build/Mabure.app"
