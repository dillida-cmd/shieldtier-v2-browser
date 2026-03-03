option(ENABLE_VMPROTECT "Enable VMProtect post-link processing" OFF)

function(vmprotect_post_link target)
    if(NOT ENABLE_VMPROTECT)
        return()
    endif()
    message(STATUS "VMProtect post-link processing for ${target} — not yet configured")
endfunction()
