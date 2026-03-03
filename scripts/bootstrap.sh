#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
THIRD_PARTY="$PROJECT_ROOT/third_party"

CEF_VERSION="145.0.27+g4ddda2e+chromium-145.0.7632.117"
CEF_VERSION_URL="145.0.27%2Bg4ddda2e%2Bchromium-145.0.7632.117"

log()  { printf "\033[1;34m==>\033[0m %s\n" "$1"; }
ok()   { printf "\033[1;32m  ✓\033[0m %s\n" "$1"; }
err()  { printf "\033[1;31m  ✗\033[0m %s\n" "$1" >&2; }

# ---------------------------------------------------------------------------
# Detect platform
# ---------------------------------------------------------------------------
detect_platform() {
    local os arch
    os="$(uname -s)"
    arch="$(uname -m)"

    case "$os" in
        Darwin)
            case "$arch" in
                arm64)  echo "macosarm64" ;;
                x86_64) echo "macosx64"   ;;
                *)      err "Unsupported macOS arch: $arch"; exit 1 ;;
            esac
            ;;
        Linux)
            case "$arch" in
                x86_64)  echo "linux64"    ;;
                aarch64) echo "linuxarm64" ;;
                *)       err "Unsupported Linux arch: $arch"; exit 1 ;;
            esac
            ;;
        MINGW*|MSYS*|CYGWIN*)
            echo "windows64"
            ;;
        *)
            err "Unsupported OS: $os"; exit 1
            ;;
    esac
}

# ---------------------------------------------------------------------------
# Install build tools
# ---------------------------------------------------------------------------
ensure_build_tools() {
    log "Checking build tools..."
    local os
    os="$(uname -s)"

    local build_tools=(cmake ninja)
    local autotools=(autoconf automake libtool pkg-config)

    case "$os" in
        Darwin)
            if ! command -v brew &>/dev/null; then
                err "Homebrew not found — install from https://brew.sh"; exit 1
            fi
            for tool in "${build_tools[@]}" "${autotools[@]}"; do
                if ! command -v "$tool" &>/dev/null; then
                    log "Installing $tool via Homebrew..."
                    brew install "$tool"
                fi
                ok "$tool $(command -v "$tool")"
            done
            ;;
        Linux)
            for tool in "${build_tools[@]}" "${autotools[@]}"; do
                if ! command -v "$tool" &>/dev/null; then
                    err "$tool not found — install via your distro's package manager"
                    exit 1
                fi
                ok "$tool $(command -v "$tool")"
            done
            ;;
        MINGW*|MSYS*|CYGWIN*)
            for tool in "${build_tools[@]}"; do
                if ! command -v "$tool" &>/dev/null; then
                    err "$tool not found — install manually on Windows"; exit 1
                fi
                ok "$tool $(command -v "$tool")"
            done
            ;;
    esac
}

# ---------------------------------------------------------------------------
# Download and extract CEF SDK
# ---------------------------------------------------------------------------
fetch_cef() {
    local platform="$1"
    local cef_dir="$THIRD_PARTY/cef"

    if [[ -d "$cef_dir" && -f "$cef_dir/cmake/FindCEF.cmake" ]]; then
        ok "CEF SDK already present"
        return
    fi

    log "Downloading CEF $CEF_VERSION for $platform..."

    local dist_name="cef_binary_${CEF_VERSION_URL}_${platform}_minimal"
    local url="https://cef-builds.spotifycdn.com/${dist_name}.tar.bz2"
    local archive="$THIRD_PARTY/${dist_name}.tar.bz2"

    if [[ ! -f "$archive" ]]; then
        curl -L --fail --retry 3 --retry-delay 5 --progress-bar -o "$archive" "$url"
    fi

    log "Extracting CEF SDK..."
    tar xjf "$archive" -C "$THIRD_PARTY"

    # The archive extracts to a directory with + signs (not URL-encoded)
    local extracted_name="cef_binary_${CEF_VERSION}_${platform}_minimal"
    rm -rf "$cef_dir"
    mv "$THIRD_PARTY/$extracted_name" "$cef_dir"

    rm -f "$archive"
    ok "CEF SDK extracted to $cef_dir"
}

# ---------------------------------------------------------------------------
# Clone a git dependency (shallow, pinned tag)
# ---------------------------------------------------------------------------
clone_dep() {
    local repo="$1"
    local tag="$2"
    local dest="$3"

    if [[ -d "$dest" ]]; then
        ok "$(basename "$dest") already present"
        return
    fi

    log "Cloning $repo @ $tag..."
    git clone --depth 1 --branch "$tag" "https://github.com/${repo}.git" "$dest" --quiet
    ok "$(basename "$dest")"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    log "ShieldTier V2 — Bootstrap"
    echo ""

    local platform
    platform="$(detect_platform)"
    ok "Platform: $platform"
    echo ""

    ensure_build_tools
    echo ""

    mkdir -p "$THIRD_PARTY"

    fetch_cef "$platform"
    echo ""

    log "Cloning third-party dependencies..."
    clone_dep "nlohmann/json"            "v3.11.3"          "$THIRD_PARTY/nlohmann_json"
    clone_dep "trailofbits/pe-parse"     "v2.1.1"           "$THIRD_PARTY/pe-parse"
    clone_dep "libarchive/libarchive"    "v3.7.7"           "$THIRD_PARTY/libarchive"
    clone_dep "WebAssembly/wabt"         "1.0.36"           "$THIRD_PARTY/wabt"
    clone_dep "VirusTotal/yara"          "v4.5.2"           "$THIRD_PARTY/yara"
    clone_dep "jedisct1/libsodium"       "1.0.20-RELEASE"   "$THIRD_PARTY/libsodium"
    clone_dep "curl/curl"                "curl-8_11_1"      "$THIRD_PARTY/curl"
    echo ""

    log "Bootstrap complete!"
    echo ""
    echo "  Next steps:"
    echo "    mkdir -p build && cd build"
    echo "    cmake -G Ninja -DCEF_ROOT=$THIRD_PARTY/cef .."
    echo "    ninja"
    echo ""
}

main "$@"
