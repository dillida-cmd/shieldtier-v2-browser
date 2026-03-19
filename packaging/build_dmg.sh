#!/bin/bash
# =============================================================================
# ShieldTier V2 — macOS DMG Builder
# Usage: ./packaging/build_dmg.sh [Release|Debug]
# Output: packaging/dist/ShieldTier-2.0.0-macos-<arch>.dmg
# =============================================================================

set -e

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_TYPE="${1:-Release}"
VERSION="2.0.0"
ARCH="$(uname -m)"  # arm64 or x86_64
if [ "$ARCH" = "x86_64" ]; then ARCH_LABEL="x64"; else ARCH_LABEL="$ARCH"; fi

APP_NAME="ShieldTier"
APP_BUNDLE="$ROOT/build/src/native/shieldtier.app"
DMG_NAME="${APP_NAME}-${VERSION}-macos-${ARCH_LABEL}"
DIST_DIR="$ROOT/packaging/dist"
STAGING="$ROOT/packaging/staging"

echo "═══════════════════════════════════════"
echo " ShieldTier DMG Builder"
echo " Version: $VERSION"
echo " Arch:    $ARCH ($ARCH_LABEL)"
echo " Build:   $BUILD_TYPE"
echo "═══════════════════════════════════════"

# 1. Build if needed
if [ ! -d "$APP_BUNDLE" ]; then
    echo "[1/5] Building..."
    cd "$ROOT/build"
    cmake .. -DCMAKE_BUILD_TYPE=$BUILD_TYPE -DNDEBUG=1
    ninja -j$(sysctl -n hw.ncpu)
else
    echo "[1/5] App bundle exists, skipping build"
fi

# 2. Strip debug symbols for release
echo "[2/5] Stripping debug symbols..."
BINARY="$APP_BUNDLE/Contents/MacOS/shieldtier"
if [ -f "$BINARY" ]; then
    strip -x "$BINARY" 2>/dev/null || true
fi
# Strip helper binaries too
for helper in "$APP_BUNDLE/Contents/Frameworks/"*"/Contents/MacOS/"*; do
    [ -f "$helper" ] && strip -x "$helper" 2>/dev/null || true
done

# 3. Sign (ad-hoc if no Developer ID)
echo "[3/5] Signing..."
SIGN_IDENTITY="${CODESIGN_IDENTITY:--}"
codesign --force --deep --sign "$SIGN_IDENTITY" "$APP_BUNDLE" 2>/dev/null || {
    echo "  Ad-hoc signing (no Developer ID certificate found)"
    codesign --force --deep --sign - "$APP_BUNDLE"
}

# 4. Create DMG
echo "[4/5] Creating DMG..."
mkdir -p "$DIST_DIR" "$STAGING"
rm -rf "$STAGING/"*

# Copy app to staging
cp -R "$APP_BUNDLE" "$STAGING/${APP_NAME}.app"

# Create symlink to /Applications for drag-install
ln -sf /Applications "$STAGING/Applications"

# Create DMG
rm -f "$DIST_DIR/${DMG_NAME}.dmg"
hdiutil create \
    -volname "$APP_NAME" \
    -srcfolder "$STAGING" \
    -ov -format UDBZ \
    "$DIST_DIR/${DMG_NAME}.dmg"

# 5. Cleanup
echo "[5/5] Cleanup..."
rm -rf "$STAGING"

DMG_SIZE=$(du -h "$DIST_DIR/${DMG_NAME}.dmg" | cut -f1)
echo ""
echo "═══════════════════════════════════════"
echo " DMG created: $DIST_DIR/${DMG_NAME}.dmg"
echo " Size: $DMG_SIZE"
echo "═══════════════════════════════════════"
echo ""
echo " To notarize (requires Apple Developer ID):"
echo "   xcrun notarytool submit $DIST_DIR/${DMG_NAME}.dmg --apple-id YOUR_ID --password APP_PASSWORD --team-id TEAM_ID"
