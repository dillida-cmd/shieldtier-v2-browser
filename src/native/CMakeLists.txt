# ShieldTier native binary — CEF browser + analysis engine

set(SHIELDTIER_SOURCES
    app/main.cpp
    app/shieldtier_app.cpp
    app/shieldtier_client.cpp
    app/shieldtier_renderer_app.cpp
    browser/request_handler.cpp
    browser/response_filter.cpp
    browser/download_handler.cpp
    browser/session_manager.cpp
    browser/navigation.cpp
    ipc/message_handler.cpp
    analysis/yara/yara_engine.cpp
    analysis/yara/rule_manager.cpp
    analysis/fileanalysis/file_analyzer.cpp
    analysis/fileanalysis/pe_analyzer.cpp
    analysis/enrichment/enrichment_manager.cpp
    analysis/enrichment/http_client.cpp
    analysis/email/email_analyzer.cpp
    analysis/content/content_analyzer.cpp
    analysis/loganalysis/log_manager.cpp
    analysis/loganalysis/log_normalizer.cpp
    analysis/loganalysis/log_detector.cpp
    scoring/scoring_engine.cpp
    export/defang.cpp
    export/export_manager.cpp
)

add_executable(shieldtier ${SHIELDTIER_SOURCES})

target_include_directories(shieldtier PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/src/native/common
    ${CEF_INCLUDE_DIRS}
)

target_link_libraries(shieldtier PRIVATE
    libcef_dll_wrapper
    ${CEF_LIBRARY}
    nlohmann_json::nlohmann_json
    yara
    pe-parse
    CURL::libcurl
    LibArchive::LibArchive
)

# ---------------------------------------------------------------------------
# macOS bundle
# ---------------------------------------------------------------------------
if(OS_MACOS OR OS_MAC)
    set_target_properties(shieldtier PROPERTIES
        MACOSX_BUNDLE TRUE
        MACOSX_BUNDLE_GUI_IDENTIFIER "com.shieldtier.browser"
        MACOSX_BUNDLE_BUNDLE_NAME "ShieldTier"
        MACOSX_BUNDLE_BUNDLE_VERSION "${PROJECT_VERSION}"
        MACOSX_BUNDLE_SHORT_VERSION_STRING "${PROJECT_VERSION}"
    )

    # Copy CEF framework into the app bundle
    set(CEF_FRAMEWORK_SRC "${CEF_ROOT}/Release/Chromium Embedded Framework.framework")
    set(CEF_FRAMEWORK_DST "$<TARGET_BUNDLE_DIR:shieldtier>/Contents/Frameworks/Chromium Embedded Framework.framework")

    add_custom_command(TARGET shieldtier POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory "$<TARGET_BUNDLE_DIR:shieldtier>/Contents/Frameworks"
        COMMAND ${CMAKE_COMMAND} -E copy_directory "${CEF_FRAMEWORK_SRC}" "${CEF_FRAMEWORK_DST}"
        COMMENT "Copying CEF framework into bundle"
    )

    # Copy CEF helper app if it exists (needed for sandboxed subprocess)
    set(CEF_HELPER_SRC "${CEF_ROOT}/Release/cef_sandbox.a")
    if(EXISTS "${CEF_ROOT}/tests/cefclient/resources/mac/helper-Info.plist")
        # Helper apps are built separately in production; skip for now
    endif()
endif()

# ---------------------------------------------------------------------------
# Linux
# ---------------------------------------------------------------------------
if(OS_LINUX)
    set_target_properties(shieldtier PROPERTIES
        INSTALL_RPATH "$ORIGIN"
    )

    # Copy libcef.so and resources to build output
    add_custom_command(TARGET shieldtier POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CEF_ROOT}/Release/libcef.so"
            "$<TARGET_FILE_DIR:shieldtier>"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CEF_ROOT}/Release/chrome-sandbox"
            "$<TARGET_FILE_DIR:shieldtier>"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CEF_ROOT}/Release/libEGL.so"
            "$<TARGET_FILE_DIR:shieldtier>"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CEF_ROOT}/Release/libGLESv2.so"
            "$<TARGET_FILE_DIR:shieldtier>"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CEF_ROOT}/Release/snapshot_blob.bin"
            "$<TARGET_FILE_DIR:shieldtier>"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CEF_ROOT}/Release/v8_context_snapshot.bin"
            "$<TARGET_FILE_DIR:shieldtier>"
        COMMENT "Copying CEF binaries to build dir (Linux)"
    )

    # Copy CEF resources
    add_custom_command(TARGET shieldtier POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CEF_RESOURCES_DIR}/icudtl.dat"
            "$<TARGET_FILE_DIR:shieldtier>"
        COMMAND ${CMAKE_COMMAND} -E copy_directory
            "${CEF_LOCALES_DIR}"
            "$<TARGET_FILE_DIR:shieldtier>/locales"
        COMMENT "Copying CEF resources (Linux)"
    )
endif()

# ---------------------------------------------------------------------------
# Windows
# ---------------------------------------------------------------------------
if(OS_WINDOWS)
    add_custom_command(TARGET shieldtier POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CEF_ROOT}/Release/libcef.dll"
            "$<TARGET_FILE_DIR:shieldtier>"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CEF_ROOT}/Release/chrome_elf.dll"
            "$<TARGET_FILE_DIR:shieldtier>"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CEF_ROOT}/Release/d3dcompiler_47.dll"
            "$<TARGET_FILE_DIR:shieldtier>"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CEF_ROOT}/Release/libEGL.dll"
            "$<TARGET_FILE_DIR:shieldtier>"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CEF_ROOT}/Release/libGLESv2.dll"
            "$<TARGET_FILE_DIR:shieldtier>"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CEF_ROOT}/Release/snapshot_blob.bin"
            "$<TARGET_FILE_DIR:shieldtier>"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CEF_ROOT}/Release/v8_context_snapshot.bin"
            "$<TARGET_FILE_DIR:shieldtier>"
        COMMENT "Copying CEF binaries to build dir (Windows)"
    )

    # Copy CEF resources
    add_custom_command(TARGET shieldtier POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CEF_RESOURCES_DIR}/icudtl.dat"
            "$<TARGET_FILE_DIR:shieldtier>"
        COMMAND ${CMAKE_COMMAND} -E copy_directory
            "${CEF_LOCALES_DIR}"
            "$<TARGET_FILE_DIR:shieldtier>/locales"
        COMMENT "Copying CEF resources (Windows)"
    )
endif()
