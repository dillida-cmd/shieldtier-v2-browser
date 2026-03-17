# FindCEF.cmake — wraps CEF's own cmake setup
#
# Input:  CEF_ROOT (cache variable)
# Output: CEF_INCLUDE_DIRS, CEF_RESOURCES_DIR, CEF_LOCALES_DIR,
#         libcef_dll_wrapper target, CEF_LIBRARY imported target

if(NOT CEF_ROOT)
    message(FATAL_ERROR "CEF_ROOT is not set. Run scripts/bootstrap.sh first.")
endif()

# Load CEF's own cmake files (cef_variables.cmake + cef_macros.cmake)
# These define macros needed by libcef_dll/CMakeLists.txt
set(_CEF_ROOT "${CEF_ROOT}")
set(_CEF_ROOT_EXPLICIT 1)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CEF_ROOT}/cmake")
include("cef_variables")
include("cef_macros")

# Include directories
set(CEF_INCLUDE_DIRS
    "${CEF_ROOT}"
    "${CEF_ROOT}/include"
)

# Build libcef_dll_wrapper
if(EXISTS "${CEF_ROOT}/libcef_dll/CMakeLists.txt")
    add_subdirectory("${CEF_ROOT}/libcef_dll" "${CMAKE_BINARY_DIR}/libcef_dll_wrapper")
else()
    message(FATAL_ERROR "CEF libcef_dll not found at ${CEF_ROOT}/libcef_dll")
endif()

# Platform-specific CEF library
if(OS_MAC OR OS_MACOS)
    set(CEF_FRAMEWORK_DIR "${CEF_ROOT}/Release/Chromium Embedded Framework.framework")
    if(EXISTS "${CEF_FRAMEWORK_DIR}")
        set(CEF_LIBRARY "${CEF_FRAMEWORK_DIR}/Chromium Embedded Framework")
        set(CEF_LIBRARY_FOUND TRUE)
    endif()
elseif(OS_LINUX)
    if(EXISTS "${CEF_ROOT}/Release/libcef.so")
        set(CEF_LIBRARY "${CEF_ROOT}/Release/libcef.so")
        set(CEF_LIBRARY_FOUND TRUE)
    endif()
elseif(OS_WINDOWS)
    if(EXISTS "${CEF_ROOT}/Release/libcef.lib")
        set(CEF_LIBRARY "${CEF_ROOT}/Release/libcef.lib")
        set(CEF_LIBRARY_FOUND TRUE)
    endif()
endif()

# Resource directories
set(CEF_RESOURCES_DIR "${CEF_ROOT}/Resources")
set(CEF_LOCALES_DIR "${CEF_ROOT}/Resources/locales")

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(CEF
    REQUIRED_VARS CEF_ROOT CEF_INCLUDE_DIRS CEF_LIBRARY_FOUND
    FAIL_MESSAGE "CEF SDK not found or incomplete. Run scripts/bootstrap.sh"
)
