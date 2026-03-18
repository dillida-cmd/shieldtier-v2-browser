#!/bin/bash
# =============================================================================
# ShieldTier V2 — macOS/Linux Dependency Setup
# Run: chmod +x setup_deps.sh && ./setup_deps.sh
# =============================================================================

set -e
ROOT="$(cd "$(dirname "$0")" && pwd)"
THIRD_PARTY="$ROOT/third_party"
mkdir -p "$THIRD_PARTY"

echo "========================================"
echo " ShieldTier V2 — Dependency Setup"
echo "========================================"
echo ""

# Detect platform
if [[ "$(uname)" == "Darwin" ]]; then
    if [[ "$(uname -m)" == "arm64" ]]; then
        CEF_PLATFORM="macosarm64"
    else
        CEF_PLATFORM="macosx64"
    fi
elif [[ "$(uname)" == "Linux" ]]; then
    CEF_PLATFORM="linux64"
else
    echo "Unsupported platform: $(uname)"
    exit 1
fi

# ---------------------------------------------------------------------------
# CEF SDK
# ---------------------------------------------------------------------------
CEF_DIR="$THIRD_PARTY/cef"
CEF_VERSION="145.0.27%2Bg4ddda2e%2Bchromium-145.0.7632.117"
CEF_URL="https://cef-builds.spotifycdn.com/cef_binary_${CEF_VERSION}_${CEF_PLATFORM}.tar.bz2"

if [ ! -d "$CEF_DIR/include" ]; then
    echo "[1/7] Downloading CEF SDK for $CEF_PLATFORM (~300MB)..."
    curl -L -o "$THIRD_PARTY/cef.tar.bz2" "$CEF_URL" || {
        echo "       Download failed. Get it manually from: https://cef-builds.spotifycdn.com/index.html"
        echo "       Version: 145.0.27, Platform: $CEF_PLATFORM, Standard Distribution"
        echo "       Extract to: $CEF_DIR"
    }
    if [ -f "$THIRD_PARTY/cef.tar.bz2" ]; then
        echo "       Extracting..."
        tar xjf "$THIRD_PARTY/cef.tar.bz2" -C "$THIRD_PARTY"
        mv "$THIRD_PARTY"/cef_binary_* "$CEF_DIR" 2>/dev/null || true
        rm -f "$THIRD_PARTY/cef.tar.bz2"
        echo "       Done."
    fi
else
    echo "[1/7] CEF SDK — already present"
fi

# ---------------------------------------------------------------------------
# nlohmann/json
# ---------------------------------------------------------------------------
if [ ! -d "$THIRD_PARTY/nlohmann_json/include" ]; then
    echo "[2/7] Cloning nlohmann/json..."
    git clone --depth 1 --branch v3.11.3 https://github.com/nlohmann/json.git "$THIRD_PARTY/nlohmann_json"
else
    echo "[2/7] nlohmann/json — already present"
fi

# ---------------------------------------------------------------------------
# pe-parse
# ---------------------------------------------------------------------------
if [ ! -f "$THIRD_PARTY/pe-parse/CMakeLists.txt" ]; then
    echo "[3/7] Cloning pe-parse..."
    git clone --depth 1 https://github.com/trailofbits/pe-parse.git "$THIRD_PARTY/pe-parse"
else
    echo "[3/7] pe-parse — already present"
fi

# ---------------------------------------------------------------------------
# curl
# ---------------------------------------------------------------------------
if [ ! -f "$THIRD_PARTY/curl/CMakeLists.txt" ]; then
    echo "[4/7] Cloning curl..."
    git clone --depth 1 --branch curl-8_11_1 https://github.com/curl/curl.git "$THIRD_PARTY/curl"
else
    echo "[4/7] curl — already present"
fi

# ---------------------------------------------------------------------------
# libarchive
# ---------------------------------------------------------------------------
if [ ! -f "$THIRD_PARTY/libarchive/CMakeLists.txt" ]; then
    echo "[5/7] Cloning libarchive..."
    git clone --depth 1 --branch v3.7.7 https://github.com/libarchive/libarchive.git "$THIRD_PARTY/libarchive"
else
    echo "[5/7] libarchive — already present"
fi

# ---------------------------------------------------------------------------
# libsodium
# ---------------------------------------------------------------------------
if [ ! -f "$THIRD_PARTY/libsodium/configure" ] && [ ! -f "$THIRD_PARTY/libsodium/CMakeLists.txt" ]; then
    echo "[6/7] Cloning libsodium..."
    git clone --depth 1 --branch 1.0.20-RELEASE https://github.com/jedisct1/libsodium.git "$THIRD_PARTY/libsodium"
else
    echo "[6/7] libsodium — already present"
fi

# ---------------------------------------------------------------------------
# wabt
# ---------------------------------------------------------------------------
if [ ! -f "$THIRD_PARTY/wabt/CMakeLists.txt" ]; then
    echo "[7/7] Cloning wabt..."
    git clone --depth 1 --recurse-submodules https://github.com/WebAssembly/wabt.git "$THIRD_PARTY/wabt"
else
    echo "[7/7] wabt — already present"
fi

# ---------------------------------------------------------------------------
# Renderer npm install
# ---------------------------------------------------------------------------
if [ ! -d "$ROOT/src/renderer/node_modules" ]; then
    echo ""
    echo "[+] Installing renderer npm dependencies..."
    cd "$ROOT/src/renderer" && npm install
fi

echo ""
echo "========================================"
echo " Setup Complete!"
echo "========================================"
echo ""
echo " Next steps:"
echo "   mkdir build && cd build"
echo "   cmake .. -G Ninja     # or: cmake .. -G 'Unix Makefiles'"
echo "   ninja -j\$(nproc)      # or: make -j\$(nproc)"
echo ""
