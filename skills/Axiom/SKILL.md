---
name: Axiom
description: Use when bootstrapping the ShieldTier V2 build system — CMake, CEF SDK, third-party dependencies, shared types, and project scaffolding
---

# S0 — Axiom: Build System Foundation

## Overview

Bootstrap the entire V2 build infrastructure. Every other agent depends on this. Deliverables: CMakeLists.txt, CEF SDK integration, third-party dependency management, shared C++ headers, and a compiling empty CEF app.

## File Ownership

```
CMakeLists.txt
cmake/
  FindCEF.cmake
  ObfuscationPasses.cmake      (stub — S13 fills in)
  VMProtect.cmake              (stub — S13 fills in)
scripts/
  download-cef.sh
third_party/                   (FetchContent manifests)
src/native/common/
  types.h
  result.h
  json.h
.clang-format
.gitignore
```

## Exit Criteria

`cmake -G Ninja -B build && ninja -C build` compiles an empty CEF app that opens a blank window on the host platform.

---

## Deliverable 1: Top-Level CMakeLists.txt

```cmake
cmake_minimum_required(VERSION 3.22)
project(ShieldTier VERSION 2.0.0 LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Platform detection
if(APPLE)
    set(OS_MACOS TRUE)
elseif(WIN32)
    set(OS_WINDOWS TRUE)
elseif(UNIX)
    set(OS_LINUX TRUE)
endif()

# CEF SDK
set(CEF_ROOT "" CACHE PATH "CEF binary distribution root")
if(NOT CEF_ROOT)
    message(STATUS "CEF_ROOT not set — running download script")
    execute_process(
        COMMAND ${CMAKE_SOURCE_DIR}/scripts/download-cef.sh
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        RESULT_VARIABLE CEF_DL_RESULT
    )
    if(NOT CEF_DL_RESULT EQUAL 0)
        message(FATAL_ERROR "CEF download failed")
    endif()
    set(CEF_ROOT "${CMAKE_SOURCE_DIR}/third_party/cef")
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
find_package(CEF REQUIRED)

# Third-party dependencies
include(FetchContent)

FetchContent_Declare(yara
    GIT_REPOSITORY https://github.com/VirusTotal/yara.git
    GIT_TAG        v4.5.2
)

FetchContent_Declare(libsodium
    GIT_REPOSITORY https://github.com/jedisct1/libsodium.git
    GIT_TAG        1.0.20-RELEASE
)

FetchContent_Declare(curl
    GIT_REPOSITORY https://github.com/curl/curl.git
    GIT_TAG        curl-8_11_1
    CMAKE_ARGS     -DBUILD_SHARED_LIBS=OFF -DCURL_USE_OPENSSL=OFF -DCURL_USE_MBEDTLS=OFF
)

FetchContent_Declare(pe-parse
    GIT_REPOSITORY https://github.com/trailofbits/pe-parse.git
    GIT_TAG        v2.1.1
)

FetchContent_Declare(libarchive
    GIT_REPOSITORY https://github.com/libarchive/libarchive.git
    GIT_TAG        v3.7.7
    CMAKE_ARGS     -DENABLE_TEST=OFF -DENABLE_TAR=OFF -DENABLE_CPIO=OFF -DENABLE_CAT=OFF
)

FetchContent_Declare(nlohmann_json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG        v3.11.3
)

FetchContent_Declare(wabt
    GIT_REPOSITORY https://github.com/WebAssembly/wabt.git
    GIT_TAG        1.0.36
    CMAKE_ARGS     -DBUILD_TESTS=OFF -DBUILD_TOOLS=OFF -DBUILD_LIBWASM=OFF
)

FetchContent_MakeAvailable(nlohmann_json pe-parse libarchive)
# yara, libsodium, curl, wabt may need ExternalProject_Add due to non-CMake builds

# Obfuscation passes (stub — S13 fills in)
include(ObfuscationPasses OPTIONAL)

# VMProtect post-link (stub — S13 fills in)
include(VMProtect OPTIONAL)

# Native binary
add_subdirectory(src/native)
```

### Key decisions:
- **nlohmann/json** for JSON (header-only, zero friction, industry standard)
- **FetchContent** for CMake-native deps, **ExternalProject_Add** for autotools-based deps (libyara, libsodium)
- **C++20** — std::span, std::expected (C++23 if compiler supports), concepts, ranges
- **Ninja** generator for fast incremental builds

---

## Deliverable 2: cmake/FindCEF.cmake

```cmake
# FindCEF.cmake — Locate CEF binary distribution
# Sets: CEF_INCLUDE_DIRS, CEF_LIBRARIES, CEF_RESOURCES_DIR, CEF_LOCALES_DIR

if(NOT CEF_ROOT)
    message(FATAL_ERROR "CEF_ROOT must be set to the CEF binary distribution path")
endif()

set(CEF_INCLUDE_DIRS
    "${CEF_ROOT}"
    "${CEF_ROOT}/include"
)

# Build the libcef_dll_wrapper static library
if(NOT TARGET libcef_dll_wrapper)
    add_subdirectory("${CEF_ROOT}/libcef_dll" "${CMAKE_BINARY_DIR}/libcef_dll_wrapper")
endif()

# Platform-specific framework/library paths
if(OS_MACOS)
    set(CEF_FRAMEWORK_DIR "${CEF_ROOT}/Release/Chromium Embedded Framework.framework")
    set(CEF_LIBRARIES
        libcef_dll_wrapper
        "${CEF_FRAMEWORK_DIR}/Chromium Embedded Framework"
    )
    set(CEF_RESOURCES_DIR "${CEF_FRAMEWORK_DIR}/Resources")
elseif(OS_LINUX)
    set(CEF_LIBRARIES
        libcef_dll_wrapper
        "${CEF_ROOT}/Release/libcef.so"
    )
    set(CEF_RESOURCES_DIR "${CEF_ROOT}/Resources")
elseif(OS_WINDOWS)
    set(CEF_LIBRARIES
        libcef_dll_wrapper
        "${CEF_ROOT}/Release/libcef.lib"
    )
    set(CEF_RESOURCES_DIR "${CEF_ROOT}/Resources")
endif()

set(CEF_LOCALES_DIR "${CEF_RESOURCES_DIR}/locales")

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(CEF DEFAULT_MSG CEF_LIBRARIES CEF_INCLUDE_DIRS)
```

---

## Deliverable 3: cmake/ObfuscationPasses.cmake (Stub)

```cmake
# ObfuscationPasses.cmake — LLVM obfuscation flags (S13 fills this in)
#
# When activated, sets compiler to obfuscator-clang++ and adds:
#   -mllvm -fla   (control flow flattening)
#   -mllvm -mba   (mixed boolean arithmetic)
#   -mllvm -bcf   (bogus control flow)
#   -mllvm -sobf  (string obfuscation)
#   -mllvm -sub   (instruction substitution)
#
# Usage: target_link_libraries(mytarget PRIVATE obfuscation_flags)

option(ENABLE_OBFUSCATION "Enable LLVM obfuscation passes" OFF)

if(ENABLE_OBFUSCATION)
    message(STATUS "LLVM obfuscation: ENABLED (S13 must configure)")
endif()
```

---

## Deliverable 4: cmake/VMProtect.cmake (Stub)

```cmake
# VMProtect.cmake — Post-link VMProtect processing (S13 fills this in)
#
# Virtualizes functions marked with VMProtectBeginUltra()/VMProtectEnd()
# Applied after linking, before code signing
#
# Usage: vmprotect_post_link(TARGET shieldtier)

option(ENABLE_VMPROTECT "Enable VMProtect post-link processing" OFF)

function(vmprotect_post_link)
    if(NOT ENABLE_VMPROTECT)
        return()
    endif()
    message(STATUS "VMProtect: ENABLED (S13 must configure)")
endfunction()
```

---

## Deliverable 5: scripts/download-cef.sh

```bash
#!/usr/bin/env bash
set -euo pipefail

# CEF version — pin to exact build for reproducibility
CEF_VERSION="130.1.16+g5765c7a+chromium-130.0.6723.117"
CEF_DIR="third_party/cef"

if [ -d "$CEF_DIR" ] && [ -f "$CEF_DIR/include/cef_version.h" ]; then
    echo "CEF SDK already present at $CEF_DIR"
    exit 0
fi

# Detect platform
case "$(uname -s)-$(uname -m)" in
    Darwin-arm64)  PLATFORM="macosarm64" ;;
    Darwin-x86_64) PLATFORM="macosx64"   ;;
    Linux-x86_64)  PLATFORM="linux64"    ;;
    Linux-aarch64) PLATFORM="linuxarm64" ;;
    MINGW*|MSYS*)  PLATFORM="windows64"  ;;
    *)             echo "Unsupported platform"; exit 1 ;;
esac

CEF_URL="https://cef-builds.spotifycdn.com/cef_binary_${CEF_VERSION}_${PLATFORM}_minimal.tar.bz2"
ARCHIVE="/tmp/cef_sdk.tar.bz2"

echo "Downloading CEF SDK for ${PLATFORM}..."
curl -L -o "$ARCHIVE" "$CEF_URL"

echo "Extracting..."
mkdir -p "$CEF_DIR"
tar xjf "$ARCHIVE" --strip-components=1 -C "$CEF_DIR"

echo "CEF SDK ready at $CEF_DIR"
rm -f "$ARCHIVE"
```

---

## Deliverable 6: Shared Headers

### src/native/common/types.h

```cpp
#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <optional>
#include <variant>
#include <nlohmann/json.hpp>

namespace shieldtier {

enum class Tier { kFree, kPro, kTeam, kEnterprise };

enum class Verdict { kClean, kSuspicious, kMalicious, kUnknown };

enum class AnalysisEngine {
    kYara, kFileAnalysis, kSandbox, kAdvanced,
    kEnrichment, kEmail, kContent, kLogAnalysis,
    kThreatFeed, kScoring, kVmSandbox
};

struct FileBuffer {
    std::vector<uint8_t> data;
    std::string filename;
    std::string mime_type;
    std::string sha256;
    size_t size() const { return data.size(); }
    const uint8_t* ptr() const { return data.data(); }
};

struct Finding {
    std::string title;
    std::string description;
    std::string severity;       // "critical", "high", "medium", "low", "info"
    std::string engine;
    nlohmann::json metadata;
};

struct AnalysisEngineResult {
    AnalysisEngine engine;
    bool success;
    std::string error;
    std::vector<Finding> findings;
    nlohmann::json raw_output;
    double duration_ms;
};

struct ThreatVerdict {
    Verdict verdict;
    double confidence;          // 0.0 - 1.0
    int threat_score;           // 0 - 100
    std::string risk_level;     // "critical", "high", "medium", "low", "none"
    std::vector<Finding> findings;
    std::vector<std::string> mitre_techniques;
    nlohmann::json details;
};

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(Finding, title, description, severity, engine, metadata)
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(ThreatVerdict, verdict, confidence, threat_score, risk_level, findings, mitre_techniques, details)

} // namespace shieldtier
```

### src/native/common/result.h

```cpp
#pragma once

#include <variant>
#include <string>
#include <stdexcept>

namespace shieldtier {

struct Error {
    std::string message;
    std::string code;
    Error(std::string msg, std::string c = "") : message(std::move(msg)), code(std::move(c)) {}
};

template<typename T>
class Result {
    std::variant<T, Error> value_;
public:
    Result(T val) : value_(std::move(val)) {}
    Result(Error err) : value_(std::move(err)) {}

    bool ok() const { return std::holds_alternative<T>(value_); }
    const T& value() const { return std::get<T>(value_); }
    T& value() { return std::get<T>(value_); }
    const Error& error() const { return std::get<Error>(value_); }

    template<typename F>
    auto map(F&& f) const -> Result<decltype(f(std::declval<T>()))> {
        if (ok()) return f(value());
        return error();
    }
};

} // namespace shieldtier
```

### src/native/common/json.h

```cpp
#pragma once

#include <nlohmann/json.hpp>

namespace shieldtier {

using json = nlohmann::json;

inline json parse_json_safe(const std::string& input) {
    try {
        return json::parse(input);
    } catch (const json::parse_error&) {
        return json{{"error", "invalid_json"}};
    }
}

} // namespace shieldtier
```

---

## Deliverable 7: .clang-format

```yaml
BasedOnStyle: Google
IndentWidth: 4
ColumnLimit: 100
BreakBeforeBraces: Attach
AllowShortFunctionsOnASingleLine: Inline
PointerAlignment: Left
NamespaceIndentation: None
IncludeBlocks: Regroup
SortIncludes: CaseInsensitive
```

---

## Deliverable 8: .gitignore

```gitignore
build/
third_party/cef/
.cache/
compile_commands.json
*.o
*.a
*.so
*.dylib
*.dll
*.exe
.DS_Store
*.dSYM/
```

---

## Deliverable 9: src/native/CMakeLists.txt

```cmake
# Native binary — all C++ compiles to single executable
set(SHIELDTIER_SOURCES
    app/main.cpp
    app/app_handler.cpp
    app/browser_handler.cpp
)

add_executable(shieldtier ${SHIELDTIER_SOURCES})

target_include_directories(shieldtier PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/src/native/common
    ${CEF_INCLUDE_DIRS}
)

target_link_libraries(shieldtier PRIVATE
    ${CEF_LIBRARIES}
    nlohmann_json::nlohmann_json
)

# Platform-specific
if(OS_MACOS)
    set_target_properties(shieldtier PROPERTIES
        MACOSX_BUNDLE TRUE
        MACOSX_BUNDLE_GUI_IDENTIFIER "com.shieldtier.browser"
        MACOSX_BUNDLE_BUNDLE_NAME "ShieldTier"
    )
    # Copy CEF framework into app bundle
    add_custom_command(TARGET shieldtier POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
            "${CEF_FRAMEWORK_DIR}"
            "$<TARGET_BUNDLE_DIR:shieldtier>/Contents/Frameworks/Chromium Embedded Framework.framework"
    )
endif()
```

---

## libyara Build Integration (ExternalProject)

libyara uses autotools, not CMake. Use ExternalProject_Add:

```cmake
include(ExternalProject)

ExternalProject_Add(yara_ext
    GIT_REPOSITORY https://github.com/VirusTotal/yara.git
    GIT_TAG        v4.5.2
    CONFIGURE_COMMAND <SOURCE_DIR>/bootstrap.sh && <SOURCE_DIR>/configure
        --prefix=<INSTALL_DIR>
        --disable-shared
        --enable-static
        --without-crypto
    BUILD_COMMAND make -j${NPROC}
    INSTALL_COMMAND make install
    BUILD_IN_SOURCE TRUE
)

ExternalProject_Get_Property(yara_ext INSTALL_DIR)
set(YARA_INCLUDE_DIR "${INSTALL_DIR}/include")
set(YARA_LIBRARY "${INSTALL_DIR}/lib/libyara.a")

add_library(yara STATIC IMPORTED GLOBAL)
set_target_properties(yara PROPERTIES
    IMPORTED_LOCATION "${YARA_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${YARA_INCLUDE_DIR}"
)
add_dependencies(yara yara_ext)
```

## libsodium Build Integration

```cmake
ExternalProject_Add(sodium_ext
    GIT_REPOSITORY https://github.com/jedisct1/libsodium.git
    GIT_TAG        1.0.20-RELEASE
    CONFIGURE_COMMAND <SOURCE_DIR>/configure
        --prefix=<INSTALL_DIR>
        --disable-shared
        --enable-static
    BUILD_COMMAND make -j${NPROC}
    INSTALL_COMMAND make install
    BUILD_IN_SOURCE TRUE
)

ExternalProject_Get_Property(sodium_ext INSTALL_DIR)
set(SODIUM_INCLUDE_DIR "${INSTALL_DIR}/include")
set(SODIUM_LIBRARY "${INSTALL_DIR}/lib/libsodium.a")

add_library(sodium STATIC IMPORTED GLOBAL)
set_target_properties(sodium PROPERTIES
    IMPORTED_LOCATION "${SODIUM_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${SODIUM_INCLUDE_DIR}"
)
add_dependencies(sodium sodium_ext)
```

---

## Common Mistakes

| Mistake | Fix |
|---------|-----|
| Using FetchContent for autotools projects | Use ExternalProject_Add for libyara, libsodium |
| Not pinning CEF version | Always pin exact CEF build hash in download script |
| Forgetting libcef_dll_wrapper | Must build the C++ wrapper library from CEF SDK |
| Missing CEF subprocess helper | CEF multi-process requires a helper executable on macOS |
| Not copying CEF resources | CEF needs icudtl.dat, v8 snapshot, locales at runtime |
