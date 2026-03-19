# ShieldTier native binary — CEF browser + analysis engine

set(SHIELDTIER_SOURCES
    app/main.cpp
    app/shieldtier_app.cpp
    app/shieldtier_client.cpp
    app/content_browser_client.cpp
    app/shieldtier_renderer_app.cpp
    browser/request_handler.cpp
    browser/response_filter.cpp
    browser/download_handler.cpp
    browser/session_manager.cpp
    browser/navigation.cpp
    browser/scheme_handler.cpp
    ipc/message_handler.cpp
    ipc/event_bridge.cpp
    config/config_store.cpp
    auth/auth_manager.cpp
    network/network_policy.cpp
    chat/chat_manager.cpp
    chat/shieldcrypt.cpp
    analysis/yara/yara_engine.cpp
    analysis/yara/rule_manager.cpp
    analysis/fileanalysis/file_analyzer.cpp
    analysis/fileanalysis/pe_analyzer.cpp
    analysis/fileanalysis/pdf_analyzer.cpp
    analysis/fileanalysis/archive_analyzer.cpp
    analysis/fileanalysis/office_analyzer.cpp
    analysis/enrichment/enrichment_manager.cpp
    analysis/enrichment/http_client.cpp
    analysis/sandbox/sandbox_engine.cpp
    analysis/sandbox/behavior_signatures.cpp
    analysis/sandbox/network_profiler.cpp
    analysis/advanced/advanced_engine.cpp
    analysis/advanced/pe_capability.cpp
    analysis/advanced/shellcode_detector.cpp
    analysis/advanced/script_analyzer.cpp
    analysis/advanced/heap_analyzer.cpp
    analysis/email/email_analyzer.cpp
    analysis/content/content_analyzer.cpp
    analysis/loganalysis/log_manager.cpp
    analysis/loganalysis/log_normalizer.cpp
    analysis/loganalysis/log_detector.cpp
    analysis/loganalysis/log_analysis_engine.cpp
    analysis/loganalysis/evtx_parser.cpp
    analysis/threatfeed/threat_feed_manager.cpp
    scoring/scoring_engine.cpp
    capture/capture_manager.cpp
    capture/har_builder.cpp
    export/defang.cpp
    export/export_manager.cpp
    vm/vm_manager.cpp
    vm/qemu_launcher.cpp
    vm/inetsim_server.cpp
    vm/anti_evasion.cpp
    vm/vm_protocol.cpp
    vm/vm_scoring.cpp
    vm/vm_installer.cpp
    vm/windows_sandbox.cpp
    vm/rdp_client.cpp
    security/anti_debug.cpp
    security/integrity_guard.cpp
    security/encrypted_pages.cpp
    security/rule_crypto.cpp
    security/hardware_fingerprint.cpp
    security/license_manager.cpp
    cloud/cloud_client.cpp
    cloud/rule_sync.cpp
    analysis/sandbox/cloud_sandbox.cpp
)

if(APPLE)
    list(APPEND SHIELDTIER_SOURCES app/app_mac.mm)
    set_source_files_properties(app/app_mac.mm PROPERTIES
        COMPILE_FLAGS "-fobjc-call-cxx-cdtors"
    )
endif()

if(OS_WINDOWS)
    add_executable(shieldtier WIN32 ${SHIELDTIER_SOURCES})
else()
    add_executable(shieldtier ${SHIELDTIER_SOURCES})
endif()

target_include_directories(shieldtier PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/src/native/common
    ${CEF_INCLUDE_DIRS}
    ${CMAKE_SOURCE_DIR}/third_party/libarchive/libarchive
    ${CMAKE_BINARY_DIR}  # for libarchive config.h
)

# libarchive: when linking archive_static, LIBARCHIVE_STATIC must be defined
# to avoid __declspec(dllimport) on symbols
target_compile_definitions(shieldtier PRIVATE LIBARCHIVE_STATIC)

target_link_libraries(shieldtier PRIVATE
    libcef_dll_wrapper
    ${CEF_LIBRARY}
    nlohmann_json::nlohmann_json
    yara
    pe-parse
    CURL::libcurl
    archive_static
    sodium
)

# Platform crypto for SHA-256 (hardware_fingerprint, response_filter)
# macOS: CommonCrypto (system), Linux: OpenSSL, Windows: BCrypt
if(OS_LINUX)
    target_link_libraries(shieldtier PRIVATE OpenSSL::Crypto)
elseif(OS_WINDOWS)
    target_link_libraries(shieldtier PRIVATE bcrypt ws2_32 iphlpapi)
endif()

# Ensure renderer is built before the main binary
add_dependencies(shieldtier renderer_build)

if(APPLE)
    target_link_libraries(shieldtier PRIVATE
        "-framework Cocoa"
        "-framework AppKit"
        "-framework IOKit"
        "-framework CoreFoundation"
        "-framework Security"
        "-framework UniformTypeIdentifiers"
    )
endif()

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
        MACOSX_BUNDLE_ICON_FILE "icon.icns"
    )

    # Copy app icon into bundle Resources
    set(ICON_SRC "${CMAKE_SOURCE_DIR}/assets/icon.icns")
    set_source_files_properties(${ICON_SRC} PROPERTIES MACOSX_PACKAGE_LOCATION "Resources")
    target_sources(shieldtier PRIVATE ${ICON_SRC})

    # Copy CEF framework into the app bundle using versioned framework structure.
    # macOS 26+ / Xcode 26+ requires Versions/A/ with symlinks (see CEF README).
    set(CEF_FRAMEWORK_SRC "${CEF_ROOT}/Release/Chromium Embedded Framework.framework")
    set(CEF_FRAMEWORK_DST "$<TARGET_BUNDLE_DIR:shieldtier>/Contents/Frameworks/Chromium Embedded Framework.framework")

    add_custom_command(TARGET shieldtier POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory "$<TARGET_BUNDLE_DIR:shieldtier>/Contents/Frameworks"
        COMMAND ${CMAKE_COMMAND} -E copy_directory "${CEF_FRAMEWORK_SRC}" "${CEF_FRAMEWORK_DST}/Versions/A"
        COMMAND cd "${CEF_FRAMEWORK_DST}" && ln -sf "Versions/A/Chromium Embedded Framework" "Chromium Embedded Framework"
        COMMAND cd "${CEF_FRAMEWORK_DST}" && ln -sf "Versions/A/Libraries" "Libraries"
        COMMAND cd "${CEF_FRAMEWORK_DST}" && ln -sf "Versions/A/Resources" "Resources"
        COMMAND cd "${CEF_FRAMEWORK_DST}/Versions" && ln -sf "A" "Current"
        COMMENT "Copying CEF framework into bundle (versioned structure)"
    )

    # -------------------------------------------------------------------
    # macOS CEF Helper apps (required for multi-process architecture)
    # CEF/Chromium on macOS expects variant-specific helper bundles:
    #   "App Helper.app"             — general
    #   "App Helper (Alerts).app"    — alerts
    #   "App Helper (GPU).app"       — GPU process
    #   "App Helper (Plugin).app"    — plugin
    #   "App Helper (Renderer).app"  — renderer process
    # All use the same binary; only the bundle name/ID differs.
    # -------------------------------------------------------------------
    set(HELPER_SOURCES
        app/process_helper_mac.cpp
        app/shieldtier_renderer_app.cpp
    )

    set(HELPER_INFO_PLIST "${CMAKE_CURRENT_SOURCE_DIR}/app/helper-Info.plist")

    # Format: "<name suffix>:<cmake target suffix>:<bundle id suffix>"
    set(CEF_HELPER_SUFFIXES
        "::"
        " (Alerts):_alerts:.alerts"
        " (GPU):_gpu:.gpu"
        " (Plugin):_plugin:.plugin"
        " (Renderer):_renderer:.renderer"
    )

    foreach(_suffix_entry ${CEF_HELPER_SUFFIXES})
        # Parse the three fields
        string(REPLACE ":" ";" _suffix_list "${_suffix_entry}")
        list(GET _suffix_list 0 _name_suffix)
        list(GET _suffix_list 1 _target_suffix)
        list(GET _suffix_list 2 _id_suffix)

        set(_helper_target "shieldtier_helper${_target_suffix}")
        set(_helper_output_name "shieldtier Helper${_name_suffix}")

        add_executable(${_helper_target} ${HELPER_SOURCES})

        target_include_directories(${_helper_target} PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}
            ${CEF_INCLUDE_DIRS}
        )

        target_link_libraries(${_helper_target} PRIVATE
            libcef_dll_wrapper
            ${CEF_LIBRARY}
        )

        set_target_properties(${_helper_target} PROPERTIES
            MACOSX_BUNDLE TRUE
            OUTPUT_NAME "${_helper_output_name}"
            MACOSX_BUNDLE_INFO_PLIST "${HELPER_INFO_PLIST}"
            MACOSX_BUNDLE_GUI_IDENTIFIER "com.shieldtier.browser.helper${_id_suffix}"
            MACOSX_BUNDLE_BUNDLE_VERSION "${PROJECT_VERSION}"
            MACOSX_BUNDLE_SHORT_VERSION_STRING "${PROJECT_VERSION}"
            MACOSX_BUNDLE_BUNDLE_NAME "${_helper_output_name}"
        )

        # Fix the helper's CEF framework reference path:
        # Helper at: MainApp.app/Contents/Frameworks/Helper.app/Contents/MacOS/Helper
        # CEF at:    MainApp.app/Contents/Frameworks/CEF.framework/CEF
        add_custom_command(TARGET ${_helper_target} POST_BUILD
            COMMAND install_name_tool -change
                "@executable_path/../Frameworks/Chromium Embedded Framework.framework/Chromium Embedded Framework"
                "@executable_path/../../../Chromium Embedded Framework.framework/Chromium Embedded Framework"
                "$<TARGET_BUNDLE_DIR:${_helper_target}>/Contents/MacOS/${_helper_output_name}"
            COMMENT "Fixing CEF framework path in ${_helper_output_name}"
            VERBATIM
        )

        add_dependencies(shieldtier ${_helper_target})

        # Copy helper bundle into main app's Frameworks directory
        add_custom_command(TARGET shieldtier POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_directory
                "$<TARGET_BUNDLE_DIR:${_helper_target}>"
                "$<TARGET_BUNDLE_DIR:shieldtier>/Contents/Frameworks/${_helper_output_name}.app"
            COMMENT "Copying ${_helper_output_name} into bundle"
            VERBATIM
        )
    endforeach()

    # Sign all helpers with JIT entitlements (V8 renderer needs JIT).
    # Main app and CEF framework keep their linker signatures.
    set(_FW_DIR "$<TARGET_BUNDLE_DIR:shieldtier>/Contents/Frameworks")
    foreach(_suffix_entry ${CEF_HELPER_SUFFIXES})
        string(REPLACE ":" ";" _suffix_list "${_suffix_entry}")
        list(GET _suffix_list 0 _name_suffix)
        set(_sign_name "shieldtier Helper${_name_suffix}")
        add_custom_command(TARGET shieldtier POST_BUILD
            COMMAND codesign --force --sign - --entitlements "${CMAKE_CURRENT_SOURCE_DIR}/app/entitlements-helper.plist"
                "${_FW_DIR}/${_sign_name}.app"
            COMMENT "Ad-hoc signing ${_sign_name} with JIT entitlements"
            VERBATIM
        )
    endforeach()
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
            "${CEF_ROOT}/Release/v8_context_snapshot.bin"
            "$<TARGET_FILE_DIR:shieldtier>"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CEF_ROOT}/Release/vk_swiftshader.dll"
            "$<TARGET_FILE_DIR:shieldtier>"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CEF_ROOT}/Release/vulkan-1.dll"
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

# ---------------------------------------------------------------------------
# Copy renderer dist + preload shim into build output
# ---------------------------------------------------------------------------
if(OS_MACOS OR OS_MAC)
    # macOS: copy into app bundle Resources/
    add_custom_command(TARGET shieldtier POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
            "${RENDERER_DIST}"
            "$<TARGET_BUNDLE_DIR:shieldtier>/Contents/Resources/renderer"
        COMMAND ${CMAKE_COMMAND} -E copy_directory
            "${RENDERER_DIR}/shim"
            "$<TARGET_BUNDLE_DIR:shieldtier>/Contents/Resources/shim"
        COMMENT "Copying renderer dist + shim into app bundle"
    )
else()
    # Linux/Windows: copy next to the executable
    add_custom_command(TARGET shieldtier POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
            "${RENDERER_DIST}"
            "$<TARGET_FILE_DIR:shieldtier>/renderer"
        COMMAND ${CMAKE_COMMAND} -E copy_directory
            "${RENDERER_DIR}/shim"
            "$<TARGET_FILE_DIR:shieldtier>/shim"
        COMMENT "Copying renderer dist + shim to build dir"
    )
endif()
