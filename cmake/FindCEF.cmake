# FindCEF.cmake — locates CEF SDK and builds libcef_dll_wrapper
#
# Input:  CEF_ROOT (cache variable)
# Output: CEF_INCLUDE_DIRS, CEF_RESOURCES_DIR, CEF_LOCALES_DIR,
#         libcef_dll_wrapper target, CEF_LIBRARY imported target

include(FindPackageHandleStandardArgs)

if(NOT CEF_ROOT)
    message(FATAL_ERROR "CEF_ROOT is not set. Run scripts/bootstrap.sh first.")
endif()

# ---------------------------------------------------------------------------
# Include directories
# ---------------------------------------------------------------------------
set(CEF_INCLUDE_DIRS
    "${CEF_ROOT}"
    "${CEF_ROOT}/include"
)

# ---------------------------------------------------------------------------
# Build libcef_dll_wrapper (CEF's C++ wrapper around the C API)
# ---------------------------------------------------------------------------
if(EXISTS "${CEF_ROOT}/libcef_dll/CMakeLists.txt")
    add_subdirectory("${CEF_ROOT}/libcef_dll" "${CMAKE_BINARY_DIR}/libcef_dll_wrapper")
else()
    message(FATAL_ERROR "CEF libcef_dll not found at ${CEF_ROOT}/libcef_dll")
endif()

# ---------------------------------------------------------------------------
# Platform-specific CEF library
# ---------------------------------------------------------------------------
if(OS_MACOS)
    set(CEF_FRAMEWORK_DIR "${CEF_ROOT}/Release/Chromium Embedded Framework.framework")
    if(EXISTS "${CEF_FRAMEWORK_DIR}")
        add_library(CEF_LIBRARY SHARED IMPORTED GLOBAL)
        set_target_properties(CEF_LIBRARY PROPERTIES
            IMPORTED_LOCATION "${CEF_FRAMEWORK_DIR}/Chromium Embedded Framework"
        )
        set(CEF_FOUND TRUE)
    endif()
elseif(OS_LINUX)
    set(CEF_LIB_PATH "${CEF_ROOT}/Release/libcef.so")
    if(EXISTS "${CEF_LIB_PATH}")
        add_library(CEF_LIBRARY SHARED IMPORTED GLOBAL)
        set_target_properties(CEF_LIBRARY PROPERTIES
            IMPORTED_LOCATION "${CEF_LIB_PATH}"
        )
        set(CEF_FOUND TRUE)
    endif()
elseif(OS_WINDOWS)
    set(CEF_LIB_PATH "${CEF_ROOT}/Release/libcef.lib")
    if(EXISTS "${CEF_LIB_PATH}")
        add_library(CEF_LIBRARY SHARED IMPORTED GLOBAL)
        set_target_properties(CEF_LIBRARY PROPERTIES
            IMPORTED_IMPLIB "${CEF_LIB_PATH}"
            IMPORTED_LOCATION "${CEF_ROOT}/Release/libcef.dll"
        )
        set(CEF_FOUND TRUE)
    endif()
endif()

# ---------------------------------------------------------------------------
# Resource directories
# ---------------------------------------------------------------------------
set(CEF_RESOURCES_DIR "${CEF_ROOT}/Resources")
set(CEF_LOCALES_DIR "${CEF_ROOT}/Resources/locales")

find_package_handle_standard_args(CEF
    REQUIRED_VARS CEF_ROOT CEF_INCLUDE_DIRS
    FAIL_MESSAGE "CEF SDK not found. Run scripts/bootstrap.sh to download it."
)
