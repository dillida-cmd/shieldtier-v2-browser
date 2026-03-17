#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# ShieldTier V2 — Unified build script
# Builds renderer (Vite) + native binary (CMake+Ninja) in one command.
#
# Usage:
#   ./scripts/build.sh              # Debug build
#   ./scripts/build.sh release      # Release build (enables obfuscation/VMProtect if configured)
#   ./scripts/build.sh clean        # Clean build directory
#   ./scripts/build.sh renderer     # Rebuild renderer only
#   ./scripts/build.sh native       # Rebuild native only (skips renderer)
#   ./scripts/build.sh test         # Build and run tests
# ---------------------------------------------------------------------------
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build"
RENDERER_DIR="${ROOT_DIR}/src/renderer"
BUILD_TYPE="Debug"
BUILD_TARGET="all"

# Parse arguments
for arg in "$@"; do
    case "$arg" in
        release|Release)
            BUILD_TYPE="Release"
            ;;
        clean)
            echo "==> Cleaning build directory"
            rm -rf "${BUILD_DIR}"
            echo "    Done."
            exit 0
            ;;
        renderer)
            BUILD_TARGET="renderer"
            ;;
        native)
            BUILD_TARGET="native"
            ;;
        test)
            BUILD_TARGET="test"
            ;;
        *)
            echo "Unknown argument: $arg"
            echo "Usage: $0 [release|clean|renderer|native|test]"
            exit 1
            ;;
    esac
done

echo "==> ShieldTier V2 Build"
echo "    Build type: ${BUILD_TYPE}"
echo "    Target:     ${BUILD_TARGET}"
echo ""

# ---------------------------------------------------------------------------
# Step 1: Build renderer (Vite)
# ---------------------------------------------------------------------------
build_renderer() {
    echo "==> Building renderer (Vite)..."
    cd "${RENDERER_DIR}"

    if [ ! -d "node_modules" ]; then
        echo "    Installing npm dependencies..."
        npm ci
    fi

    npm run build
    echo "    Renderer built: ${RENDERER_DIR}/dist/"
}

# ---------------------------------------------------------------------------
# Step 2: Configure + build native (CMake + Ninja)
# ---------------------------------------------------------------------------
build_native() {
    echo "==> Configuring native build (CMake)..."
    mkdir -p "${BUILD_DIR}"

    local cmake_args=(
        -G "Ninja"
        -DCMAKE_BUILD_TYPE="${BUILD_TYPE}"
        -DCEF_ROOT="${ROOT_DIR}/third_party/cef"
    )

    if [ "${BUILD_TYPE}" = "Release" ]; then
        cmake_args+=(-DENABLE_OBFUSCATION=ON -DENABLE_VMPROTECT=ON)
    fi

    cmake -S "${ROOT_DIR}" -B "${BUILD_DIR}" "${cmake_args[@]}"

    echo "==> Building native binary (Ninja)..."
    cmake --build "${BUILD_DIR}" --target shieldtier -- -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)"
    echo "    Native build complete."
}

# ---------------------------------------------------------------------------
# Step 3: Build and run tests
# ---------------------------------------------------------------------------
build_and_run_tests() {
    echo "==> Building tests..."
    mkdir -p "${BUILD_DIR}"

    cmake -S "${ROOT_DIR}" -B "${BUILD_DIR}" \
        -G "Ninja" \
        -DCMAKE_BUILD_TYPE=Debug \
        -DCEF_ROOT="${ROOT_DIR}/third_party/cef" \
        -DSHIELDTIER_BUILD_TESTS=ON

    cmake --build "${BUILD_DIR}" --target shieldtier_tests -- -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)"

    echo "==> Running tests..."
    cd "${BUILD_DIR}"
    ctest --output-on-failure
}

# ---------------------------------------------------------------------------
# Execute
# ---------------------------------------------------------------------------
case "${BUILD_TARGET}" in
    all)
        build_renderer
        echo ""
        build_native
        ;;
    renderer)
        build_renderer
        ;;
    native)
        build_native
        ;;
    test)
        build_renderer
        build_native
        build_and_run_tests
        ;;
esac

echo ""
echo "==> Build complete!"

if [ "${BUILD_TARGET}" = "all" ] || [ "${BUILD_TARGET}" = "native" ]; then
    if [ "$(uname)" = "Darwin" ]; then
        echo "    App bundle: ${BUILD_DIR}/src/native/shieldtier.app"
    else
        echo "    Binary: ${BUILD_DIR}/src/native/shieldtier"
    fi
fi
