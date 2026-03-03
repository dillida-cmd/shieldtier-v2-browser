cmake_minimum_required(VERSION 3.22)
project(ShieldTier VERSION 2.0.0 LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------
if(APPLE)
    set(OS_MACOS TRUE)
    set(SHIELDTIER_PLATFORM "macos")
elseif(WIN32)
    set(OS_WINDOWS TRUE)
    set(SHIELDTIER_PLATFORM "windows")
elseif(UNIX AND NOT APPLE)
    set(OS_LINUX TRUE)
    set(SHIELDTIER_PLATFORM "linux")
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
add_subdirectory(third_party/pe-parse)

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

set(BUILD_TESTS OFF CACHE INTERNAL "")
set(BUILD_TOOLS OFF CACHE INTERNAL "")
set(BUILD_LIBWASM OFF CACHE INTERNAL "")
add_subdirectory(third_party/wabt)

# ---------------------------------------------------------------------------
# Autotools dependencies via ExternalProject
# ---------------------------------------------------------------------------
include(ExternalProject)
include(ProcessorCount)
ProcessorCount(NPROC)
if(NOT NPROC OR NPROC EQUAL 0)
    set(NPROC 4)
endif()

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

# ---------------------------------------------------------------------------
# Optional protection passes (stubs until phases C/D)
# ---------------------------------------------------------------------------
include(ObfuscationPasses OPTIONAL)
include(VMProtect OPTIONAL)

# ---------------------------------------------------------------------------
# Native source tree
# ---------------------------------------------------------------------------
add_subdirectory(src/native)
