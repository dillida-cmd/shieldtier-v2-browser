option(ENABLE_OBFUSCATION "Enable LLVM obfuscation passes" OFF)

if(ENABLE_OBFUSCATION)
    message(STATUS "LLVM obfuscation passes enabled — configuration deferred to Obsidian agent")
endif()
