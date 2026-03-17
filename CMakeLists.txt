cmake_minimum_required(VERSION 3.22)
cmake_policy(SET CMP0077 NEW)
set(CMAKE_POLICY_VERSION_MINIMUM 3.5 CACHE STRING "Allow older third-party cmake_minimum_required")
project(ShieldTier VERSION 2.0.0 LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------
if(APPLE)
    enable_language(OBJCXX)
    set(OS_MACOS TRUE)
    set(OS_MAC TRUE)
    set(SHIELDTIER_PLATFORM "macos")
    add_compile_definitions(OS_MAC=1 OS_MACOS=1)
elseif(WIN32)
    set(OS_WINDOWS TRUE)
    set(SHIELDTIER_PLATFORM "windows")
    add_compile_definitions(OS_WIN=1 OS_WINDOWS=1)
elseif(UNIX AND NOT APPLE)
    set(OS_LINUX TRUE)
    set(SHIELDTIER_PLATFORM "linux")
    add_compile_definitions(OS_LINUX=1)
else()
    message(FATAL_ERROR "Unsupported platform")
endif()

message(STATUS "ShieldTier V2 — platform: ${SHIELDTIER_PLATFORM}")

# ---------------------------------------------------------------------------
# CEF SDK
# ---------------------------------------------------------------------------
set(CEF_ROOT "${CMAKE_SOURCE_DIR}/third_party/cef" CACHE PATH "Path to CEF SDK root")

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

find_package(CEF REQUIRED)

# ---------------------------------------------------------------------------
# CMake-native third-party dependencies
# ---------------------------------------------------------------------------
set(JSON_BuildTests OFF CACHE INTERNAL "")
add_subdirectory(third_party/nlohmann_json)

set(BUILD_TESTS OFF CACHE INTERNAL "")
set(BUILD_COMMAND_LINE_TOOLS OFF CACHE INTERNAL "")
add_subdirectory(third_party/pe-parse EXCLUDE_FROM_ALL)
# pe-parse uses -Werror but has deprecated C++ codecvt usage
if(TARGET pe-parse)
    target_compile_options(pe-parse PRIVATE -Wno-deprecated-declarations -Wno-error)
endif()

set(BUILD_SHARED_LIBS OFF CACHE INTERNAL "")
if(OS_MACOS)
    set(CURL_USE_SECTRANSPORT ON CACHE INTERNAL "")
elseif(OS_WINDOWS)
    set(CURL_USE_SCHANNEL ON CACHE INTERNAL "")
else()
    set(CURL_USE_OPENSSL ON CACHE INTERNAL "")
endif()
set(BUILD_CURL_EXE OFF CACHE INTERNAL "")
set(BUILD_TESTING OFF CACHE INTERNAL "")
add_subdirectory(third_party/curl)

set(ENABLE_TEST OFF CACHE INTERNAL "")
set(ENABLE_TAR OFF CACHE INTERNAL "")
set(ENABLE_CPIO OFF CACHE INTERNAL "")
set(ENABLE_CAT OFF CACHE INTERNAL "")
add_subdirectory(third_party/libarchive)

# ---------------------------------------------------------------------------
# OpenSSL — required on Linux for SHA-256 in hardware_fingerprint,
#            response_filter, etc. macOS uses CommonCrypto. Windows uses BCrypt.
# ---------------------------------------------------------------------------
if(OS_LINUX)
    find_package(OpenSSL REQUIRED)
endif()

# ---------------------------------------------------------------------------
# Renderer build (Vite) — runs npm build to produce dist/ before linking
# ---------------------------------------------------------------------------
set(RENDERER_DIR "${CMAKE_SOURCE_DIR}/src/renderer")
set(RENDERER_DIST "${RENDERER_DIR}/dist")

find_program(NPM_EXECUTABLE npm)
if(NPM_EXECUTABLE)
    add_custom_target(renderer_build
        COMMAND ${NPM_EXECUTABLE} run build
        WORKING_DIRECTORY "${RENDERER_DIR}"
        COMMENT "Building React renderer (Vite)"
        BYPRODUCTS "${RENDERER_DIST}/index.html"
    )
else()
    message(WARNING "npm not found — renderer will not be auto-built. Pre-build with: cd src/renderer && npm run build")
    add_custom_target(renderer_build)
endif()

# ---------------------------------------------------------------------------
# yara + libsodium — platform-specific build strategies
# Unix: autotools via ExternalProject (./configure && make)
# Windows: vcpkg or pre-built, with stub fallback
# ---------------------------------------------------------------------------
include(ExternalProject)
include(ProcessorCount)
ProcessorCount(NPROC)
if(NOT NPROC OR NPROC EQUAL 0)
    set(NPROC 4)
endif()

if(OS_WINDOWS)
    # -----------------------------------------------------------------------
    # Windows: Use vcpkg if available, otherwise build libsodium with CMake
    # and provide a yara stub (YARA scanning disabled on Windows for now).
    #
    # To enable full YARA on Windows, install via vcpkg:
    #   vcpkg install yara:x64-windows libsodium:x64-windows
    #   cmake -DCMAKE_TOOLCHAIN_FILE=<vcpkg>/scripts/buildsystems/vcpkg.cmake ..
    # -----------------------------------------------------------------------

    # Try finding pre-installed packages first (vcpkg, manual install, etc.)
    find_library(YARA_LIBRARY NAMES yara yara64 libyara PATHS
        "${CMAKE_SOURCE_DIR}/third_party/yara/windows/vs2019/x64/Release"
        "$ENV{VCPKG_ROOT}/installed/x64-windows/lib"
    )
    find_path(YARA_INCLUDE_DIR NAMES yara.h PATHS
        "${CMAKE_SOURCE_DIR}/third_party/yara/libyara/include"
        "$ENV{VCPKG_ROOT}/installed/x64-windows/include"
    )

    if(YARA_LIBRARY AND YARA_INCLUDE_DIR)
        message(STATUS "Found YARA: ${YARA_LIBRARY}")
        add_library(yara STATIC IMPORTED GLOBAL)
        set_target_properties(yara PROPERTIES
            IMPORTED_LOCATION "${YARA_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${YARA_INCLUDE_DIR}"
        )
    else()
        message(WARNING "YARA not found on Windows — YARA scanning will be stubbed. "
                        "Install via: vcpkg install yara:x64-windows")
        # Create a stub target so the build doesn't fail
        add_library(yara INTERFACE)
        target_compile_definitions(yara INTERFACE SHIELDTIER_NO_YARA=1)
    endif()

    # libsodium — try vcpkg or pre-built
    find_library(SODIUM_LIBRARY NAMES sodium libsodium PATHS
        "$ENV{VCPKG_ROOT}/installed/x64-windows/lib"
        "${CMAKE_SOURCE_DIR}/third_party/libsodium/bin/x64/Release/v143"
    )
    find_path(SODIUM_INCLUDE_DIR NAMES sodium.h PATHS
        "$ENV{VCPKG_ROOT}/installed/x64-windows/include"
        "${CMAKE_SOURCE_DIR}/third_party/libsodium/src/libsodium/include"
    )

    if(SODIUM_LIBRARY AND SODIUM_INCLUDE_DIR)
        message(STATUS "Found libsodium: ${SODIUM_LIBRARY}")
        add_library(sodium STATIC IMPORTED GLOBAL)
        set_target_properties(sodium PROPERTIES
            IMPORTED_LOCATION "${SODIUM_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${SODIUM_INCLUDE_DIR}"
        )
    else()
        message(WARNING "libsodium not found on Windows — chat encryption will be stubbed. "
                        "Install via: vcpkg install libsodium:x64-windows")
        add_library(sodium INTERFACE)
        target_compile_definitions(sodium INTERFACE SHIELDTIER_NO_SODIUM=1)
    endif()

else()
    # -----------------------------------------------------------------------
    # Unix (macOS, Linux): Build via autotools
    # -----------------------------------------------------------------------
    ExternalProject_Add(yara_ext
        SOURCE_DIR "${CMAKE_SOURCE_DIR}/third_party/yara"
        CONFIGURE_COMMAND sh -c "cd <SOURCE_DIR> && ./bootstrap.sh && ./configure --prefix=<INSTALL_DIR> --disable-shared --enable-static --without-crypto"
        BUILD_COMMAND make -j${NPROC}
        INSTALL_COMMAND make install
        BUILD_IN_SOURCE TRUE
        BUILD_BYPRODUCTS "<INSTALL_DIR>/lib/libyara.a"
    )

    ExternalProject_Get_Property(yara_ext INSTALL_DIR)
    set(YARA_INSTALL_DIR "${INSTALL_DIR}")

    add_library(yara STATIC IMPORTED GLOBAL)
    set_target_properties(yara PROPERTIES
        IMPORTED_LOCATION "${YARA_INSTALL_DIR}/lib/libyara.a"
        INTERFACE_INCLUDE_DIRECTORIES "${YARA_INSTALL_DIR}/include"
    )
    add_dependencies(yara yara_ext)

    ExternalProject_Add(libsodium_ext
        SOURCE_DIR "${CMAKE_SOURCE_DIR}/third_party/libsodium"
        CONFIGURE_COMMAND sh -c "cd <SOURCE_DIR> && ./autogen.sh && ./configure --prefix=<INSTALL_DIR> --disable-shared --enable-static"
        BUILD_COMMAND make -j${NPROC}
        INSTALL_COMMAND make install
        BUILD_IN_SOURCE TRUE
        BUILD_BYPRODUCTS "<INSTALL_DIR>/lib/libsodium.a"
    )

    ExternalProject_Get_Property(libsodium_ext INSTALL_DIR)
    set(SODIUM_INSTALL_DIR "${INSTALL_DIR}")

    add_library(sodium STATIC IMPORTED GLOBAL)
    set_target_properties(sodium PROPERTIES
        IMPORTED_LOCATION "${SODIUM_INSTALL_DIR}/lib/libsodium.a"
        INTERFACE_INCLUDE_DIRECTORIES "${SODIUM_INSTALL_DIR}/include"
    )
    add_dependencies(sodium libsodium_ext)
endif()

# ---------------------------------------------------------------------------
# Optional protection passes (stubs until phases C/D)
# ---------------------------------------------------------------------------
include(ObfuscationPasses OPTIONAL)
include(VMProtect OPTIONAL)

# ---------------------------------------------------------------------------
# Native source tree
# ---------------------------------------------------------------------------
add_subdirectory(src/native)

# ---------------------------------------------------------------------------
# Tests (opt-in via -DSHIELDTIER_BUILD_TESTS=ON)
# ---------------------------------------------------------------------------
option(SHIELDTIER_BUILD_TESTS "Build unit tests" OFF)
if(SHIELDTIER_BUILD_TESTS)
    add_subdirectory(tests)
endif()
