option(ENABLE_VMPROTECT "Enable VMProtect post-link processing" OFF)

set(VMPROTECT_PATH "" CACHE FILEPATH "Path to VMProtect console tool")
set(VMPROTECT_PROJECT "" CACHE FILEPATH "Path to VMProtect project file (.vmp)")

function(vmprotect_post_link target)
    if(NOT ENABLE_VMPROTECT)
        return()
    endif()

    if(NOT VMPROTECT_PATH OR NOT EXISTS "${VMPROTECT_PATH}")
        message(FATAL_ERROR "ENABLE_VMPROTECT is ON but VMPROTECT_PATH is not set or does not exist: '${VMPROTECT_PATH}'")
    endif()

    if(NOT VMPROTECT_PROJECT OR NOT EXISTS "${VMPROTECT_PROJECT}")
        message(FATAL_ERROR "ENABLE_VMPROTECT is ON but VMPROTECT_PROJECT (.vmp) is not set or does not exist: '${VMPROTECT_PROJECT}'")
    endif()

    # Post-build step: run VMProtect on the target binary
    add_custom_command(TARGET ${target} POST_BUILD
        COMMAND "${VMPROTECT_PATH}"
            "$<TARGET_FILE:${target}>"
            "${VMPROTECT_PROJECT}"
        WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
        COMMENT "Running VMProtect on ${target}..."
        VERBATIM
    )

    message(STATUS "VMProtect post-link enabled for target: ${target}")
endfunction()

# Macro for marking functions in source code:
# Usage in C++:
#   #pragma vmprotect begin("function_name")
#   void critical_function() { ... }
#   #pragma vmprotect end
#
# VMProtect project file (.vmp) maps these markers to protection modes:
#   - Virtualization: scoring_engine, license_check, integrity_verify
#   - Mutation: all other marked functions
#   - Ultra (Virt+Mut): crypto_derive_key, fingerprint_hardware
