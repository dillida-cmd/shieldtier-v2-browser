option(ENABLE_OBFUSCATION "Enable LLVM obfuscation passes" OFF)

if(ENABLE_OBFUSCATION)
    message(STATUS "LLVM obfuscation passes enabled")

    # Require Clang (LLVM passes only work with Clang/LLVM toolchain)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "ENABLE_OBFUSCATION requires Clang/LLVM compiler")
    endif()

    # O-LLVM / Hikari / Pluto pass flags
    # These are added via -mllvm flag to pass options directly to LLVM backend

    # Control Flow Flattening (CFF) — applied to all code
    set(OBFUSCATION_CFF_FLAGS "-mllvm -fla")

    # Mixed Boolean Arithmetic (MBA) — applied to scoring/crypto
    set(OBFUSCATION_MBA_FLAGS "-mllvm -mba -mllvm -mba-prob=40")

    # Bogus Control Flow (BCF) — applied everywhere
    set(OBFUSCATION_BCF_FLAGS "-mllvm -bcf -mllvm -bcf-prob=30")

    # String Encryption — encrypt all string literals
    set(OBFUSCATION_STR_FLAGS "-mllvm -sobf")

    # Combined flags for "full obfuscation" (everything except MBA)
    set(OBFUSCATION_FULL_FLAGS "${OBFUSCATION_CFF_FLAGS} ${OBFUSCATION_BCF_FLAGS} ${OBFUSCATION_STR_FLAGS}")

    # Critical function flags (scoring, crypto, license) — add MBA
    set(OBFUSCATION_CRITICAL_FLAGS "${OBFUSCATION_FULL_FLAGS} ${OBFUSCATION_MBA_FLAGS}")

    # Function to apply obfuscation to a target
    function(apply_obfuscation target level)
        if(NOT ENABLE_OBFUSCATION)
            return()
        endif()

        if(level STREQUAL "full")
            target_compile_options(${target} PRIVATE ${OBFUSCATION_FULL_FLAGS})
        elseif(level STREQUAL "critical")
            target_compile_options(${target} PRIVATE ${OBFUSCATION_CRITICAL_FLAGS})
        elseif(level STREQUAL "cff_only")
            target_compile_options(${target} PRIVATE ${OBFUSCATION_CFF_FLAGS})
        elseif(level STREQUAL "strings_only")
            target_compile_options(${target} PRIVATE ${OBFUSCATION_STR_FLAGS})
        else()
            message(WARNING "Unknown obfuscation level '${level}' for target '${target}'")
        endif()

        message(STATUS "  Obfuscation [${level}] → ${target}")
    endfunction()
else()
    # No-op stub when disabled
    function(apply_obfuscation target level)
    endfunction()
endif()
