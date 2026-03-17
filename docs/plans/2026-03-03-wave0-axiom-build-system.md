# Wave 0 — Axiom: Build System Foundation

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Bootstrap the ShieldTier V2 build system so `scripts/bootstrap.sh && cmake -G Ninja -B build && ninja -C build` compiles an empty CEF app that opens a blank window on macOS/Linux/Windows.

**Architecture:** CMake 3.22+ with Ninja generator. CEF 145 SDK downloaded via bootstrap script. Third-party deps (libyara, libsodium, curl, pe-parse, libarchive, nlohmann_json, wabt) fetched by bootstrap script into `third_party/`. ExternalProject for autotools deps, FetchContent for CMake-native deps. Single native binary target linking CEF + all deps.

**Tech Stack:** C++20, CMake, Ninja, CEF 145 (Chromium 145.0.7632.117), clang++/MSVC

**CEF Version:** `145.0.27+g4ddda2e+chromium-145.0.7632.117`

---

## Task 1: Bootstrap Script

**Files:**
- Create: `scripts/bootstrap.sh`

**Step 1: Create the bootstrap script**

```bash
#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
THIRD_PARTY="$ROOT_DIR/third_party"

# --- Build tools ---
check_tool() {
    if ! command -v "$1" &>/dev/null; then
        echo "Installing $1..."
        if command -v brew &>/dev/null; then
            brew install "$1"
        elif command -v apt-get &>/dev/null; then
            sudo apt-get install -y "$1"
        else
            echo "ERROR: $1 not found. Install it manually."
            exit 1
        fi
    fi
}

check_tool cmake
check_tool ninja

mkdir -p "$THIRD_PARTY"

# --- CEF SDK ---
CEF_VERSION="145.0.27+g4ddda2e+chromium-145.0.7632.117"
CEF_DIR="$THIRD_PARTY/cef"

if [ ! -f "$CEF_DIR/include/cef_version.h" ]; then
    case "$(uname -s)-$(uname -m)" in
        Darwin-arm64)  PLATFORM="macosarm64" ;;
        Darwin-x86_64) PLATFORM="macosx64"   ;;
        Linux-x86_64)  PLATFORM="linux64"    ;;
        Linux-aarch64) PLATFORM="linuxarm64" ;;
        MINGW*|MSYS*)  PLATFORM="windows64"  ;;
        *)             echo "Unsupported platform: $(uname -s)-$(uname -m)"; exit 1 ;;
    esac

    CEF_URL_VERSION=$(echo "$CEF_VERSION" | sed 's/+/%2B/g')
    CEF_URL="https://cef-builds.spotifycdn.com/cef_binary_${CEF_URL_VERSION}_${PLATFORM}_minimal.tar.bz2"
    ARCHIVE="/tmp/cef_sdk.tar.bz2"

    echo "Downloading CEF SDK ($PLATFORM)..."
    curl -L --progress-bar -o "$ARCHIVE" "$CEF_URL"

    echo "Extracting CEF SDK..."
    mkdir -p "$CEF_DIR"
    tar xjf "$ARCHIVE" --strip-components=1 -C "$CEF_DIR"
    rm -f "$ARCHIVE"
    echo "CEF SDK ready at $CEF_DIR"
else
    echo "CEF SDK already present"
fi

# --- nlohmann/json (header-only) ---
JSON_DIR="$THIRD_PARTY/nlohmann_json"
if [ ! -f "$JSON_DIR/include/nlohmann/json.hpp" ]; then
    echo "Downloading nlohmann/json..."
    git clone --depth 1 --branch v3.11.3 \
        https://github.com/nlohmann/json.git "$JSON_DIR"
else
    echo "nlohmann/json already present"
fi

# --- pe-parse ---
PEPARSE_DIR="$THIRD_PARTY/pe-parse"
if [ ! -d "$PEPARSE_DIR/cmake" ]; then
    echo "Downloading pe-parse..."
    git clone --depth 1 --branch v2.1.1 \
        https://github.com/trailofbits/pe-parse.git "$PEPARSE_DIR"
else
    echo "pe-parse already present"
fi

# --- libarchive ---
LIBARCHIVE_DIR="$THIRD_PARTY/libarchive"
if [ ! -f "$LIBARCHIVE_DIR/CMakeLists.txt" ]; then
    echo "Downloading libarchive..."
    git clone --depth 1 --branch v3.7.7 \
        https://github.com/libarchive/libarchive.git "$LIBARCHIVE_DIR"
else
    echo "libarchive already present"
fi

# --- wabt ---
WABT_DIR="$THIRD_PARTY/wabt"
if [ ! -f "$WABT_DIR/CMakeLists.txt" ]; then
    echo "Downloading wabt..."
    git clone --depth 1 --branch 1.0.36 \
        https://github.com/WebAssembly/wabt.git "$WABT_DIR"
else
    echo "wabt already present"
fi

# --- libyara (autotools) ---
YARA_DIR="$THIRD_PARTY/yara"
if [ ! -f "$YARA_DIR/libyara/include/yara.h" ]; then
    echo "Downloading libyara..."
    git clone --depth 1 --branch v4.5.2 \
        https://github.com/VirusTotal/yara.git "$YARA_DIR"
else
    echo "libyara already present"
fi

# --- libsodium (autotools) ---
SODIUM_DIR="$THIRD_PARTY/libsodium"
if [ ! -f "$SODIUM_DIR/src/libsodium/include/sodium.h" ]; then
    echo "Downloading libsodium..."
    git clone --depth 1 --branch 1.0.20-RELEASE \
        https://github.com/jedisct1/libsodium.git "$SODIUM_DIR"
else
    echo "libsodium already present"
fi

# --- libcurl ---
CURL_DIR="$THIRD_PARTY/curl"
if [ ! -f "$CURL_DIR/CMakeLists.txt" ]; then
    echo "Downloading libcurl..."
    git clone --depth 1 --branch curl-8_11_1 \
        https://github.com/curl/curl.git "$CURL_DIR"
else
    echo "libcurl already present"
fi

echo ""
echo "All dependencies ready. Run:"
echo "  cmake -G Ninja -B build"
echo "  ninja -C build"
```

**Step 2: Make executable and test**

Run: `chmod +x scripts/bootstrap.sh`

**Step 3: Commit**

```
feat(axiom): add bootstrap script — downloads CEF 145 + all deps
```

---

## Task 2: CMake Foundation

**Files:**
- Create: `CMakeLists.txt`
- Create: `cmake/FindCEF.cmake`
- Create: `cmake/ObfuscationPasses.cmake` (stub)
- Create: `cmake/VMProtect.cmake` (stub)

**Step 1: Create cmake/FindCEF.cmake**

Locates CEF SDK in `third_party/cef`, builds `libcef_dll_wrapper`, exports `CEF_INCLUDE_DIRS`, `CEF_LIBRARIES`, `CEF_RESOURCES_DIR`. Handles macOS framework, Linux .so, Windows .lib paths.

**Step 2: Create cmake/ObfuscationPasses.cmake**

Stub with `ENABLE_OBFUSCATION` option — no-op, Obsidian fills in later.

**Step 3: Create cmake/VMProtect.cmake**

Stub with `ENABLE_VMPROTECT` option and empty `vmprotect_post_link()` function.

**Step 4: Create top-level CMakeLists.txt**

- `cmake_minimum_required(VERSION 3.22)`
- Project `ShieldTier 2.0.0`, C++20
- Platform detection (APPLE/WIN32/UNIX)
- `CEF_ROOT` defaults to `third_party/cef`
- `find_package(CEF REQUIRED)`
- `add_subdirectory` for third-party CMake deps (nlohmann_json, pe-parse, libarchive, curl, wabt)
- `ExternalProject_Add` for autotools deps (libyara, libsodium)
- `add_subdirectory(src/native)`

**Step 5: Commit**

```
feat(axiom): add CMake build system with CEF 145 + dep integration
```

---

## Task 3: Shared Headers

**Files:**
- Create: `src/native/common/types.h`
- Create: `src/native/common/result.h`
- Create: `src/native/common/json.h`

**Step 1: Create src/native/common/types.h**

Core types used by every agent:
- `enum class Tier { kFree, kPro, kTeam, kEnterprise }`
- `enum class Verdict { kClean, kSuspicious, kMalicious, kUnknown }`
- `enum class AnalysisEngine { kYara, kFileAnalysis, kSandbox, ... }`
- `struct FileBuffer { vector<uint8_t> data; string filename, mime_type, sha256; }`
- `struct Finding { string title, description, severity, engine; json metadata; }`
- `struct AnalysisEngineResult { AnalysisEngine engine; bool success; vector<Finding> findings; }`
- `struct ThreatVerdict { Verdict verdict; double confidence; int threat_score; ... }`
- nlohmann JSON serialization macros

**Step 2: Create src/native/common/result.h**

`Result<T>` type using `std::variant<T, Error>` with `.ok()`, `.value()`, `.error()`, `.map()`.

**Step 3: Create src/native/common/json.h**

`using json = nlohmann::json` alias + `parse_json_safe()` helper.

**Step 4: Commit**

```
feat(axiom): add shared types, Result<T>, and JSON helpers
```

---

## Task 4: Empty CEF App (macOS/Linux/Windows)

**Files:**
- Create: `src/native/CMakeLists.txt`
- Create: `src/native/app/main.cpp`
- Create: `src/native/app/shieldtier_app.h`
- Create: `src/native/app/shieldtier_app.cpp`
- Create: `src/native/app/shieldtier_client.h`
- Create: `src/native/app/shieldtier_client.cpp`

**Step 1: Create src/native/CMakeLists.txt**

Define `shieldtier` executable target:
- Source files: `app/main.cpp`, `app/shieldtier_app.cpp`, `app/shieldtier_client.cpp`
- Link: `${CEF_LIBRARIES}`, `nlohmann_json::nlohmann_json`
- macOS: `MACOSX_BUNDLE`, copy CEF framework + helper into bundle
- Linux: set RPATH, copy libcef.so + resources to build dir
- Windows: copy libcef.dll + resources to output dir

**Step 2: Create src/native/app/shieldtier_app.h/.cpp**

- Inherits `CefApp`, `CefBrowserProcessHandler`
- `OnContextInitialized()`: creates the main browser window via `CefBrowserHost::CreateBrowser`
- Opens `about:blank` (placeholder — Chrono fills in renderer loading)

**Step 3: Create src/native/app/shieldtier_client.h/.cpp**

- Inherits `CefClient`, `CefLifeSpanHandler`, `CefDisplayHandler`
- `OnAfterCreated()`: stores browser reference
- `DoClose()` / `OnBeforeClose()`: proper shutdown
- `OnTitleChange()`: updates native window title

**Step 4: Create src/native/app/main.cpp**

- Platform entry point: `main()` on macOS/Linux, `wWinMain()` on Windows
- `CefExecuteProcess()` for subprocess handling
- `CefSettings` with `no_sandbox = true`, `multi_threaded_message_loop = false`
- `CefInitialize()` → `CefRunMessageLoop()` → `CefShutdown()`

**Step 5: Commit**

```
feat(axiom): empty CEF 145 app — opens blank window on all platforms
```

---

## Task 5: Project Config Files

**Files:**
- Create: `.clang-format`
- Update: `.gitignore` (add build artifacts, third_party)

**Step 1: Create .clang-format**

Google style base, 4-space indent, 100 col limit.

**Step 2: Update .gitignore**

Add `build/`, `third_party/`, `compile_commands.json`, object files, IDE dirs.

**Step 3: Commit**

```
feat(axiom): add clang-format and update gitignore
```

---

## Task 6: Build Verification

**Step 1: Run bootstrap**

```bash
scripts/bootstrap.sh
```

Expected: All deps downloaded to `third_party/`, cmake + ninja installed.

**Step 2: Configure**

```bash
cmake -G Ninja -B build
```

Expected: Configures successfully, finds CEF, builds libcef_dll_wrapper.

**Step 3: Build**

```bash
ninja -C build
```

Expected: Compiles `shieldtier` binary (or `ShieldTier.app` on macOS).

**Step 4: Run**

```bash
# macOS
open build/ShieldTier.app
# or
./build/ShieldTier.app/Contents/MacOS/ShieldTier
```

Expected: Window opens showing blank page. Close window exits cleanly.

---

## Execution Order

```
Task 1 (bootstrap.sh)
  → Task 2 (CMake)
    → Task 3 (shared headers)
      → Task 4 (CEF app)
        → Task 5 (config files)
          → Task 6 (verify build)
```

All tasks are sequential — each builds on the previous.
