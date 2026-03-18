# ShieldTier V2 — Test suite
# Built only when SHIELDTIER_BUILD_TESTS=ON

include(FetchContent)

FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG        v1.15.2
)
set(BUILD_GMOCK OFF CACHE INTERNAL "")
set(INSTALL_GTEST OFF CACHE INTERNAL "")
FetchContent_MakeAvailable(googletest)

enable_testing()

# ---------------------------------------------------------------------------
# Test sources — analysis engines (no CEF dependency)
# ---------------------------------------------------------------------------
set(TEST_SOURCES
    test_file_analyzer.cpp
    test_scoring_engine.cpp
    test_defang.cpp
    test_content_analyzer.cpp
    test_log_normalizer.cpp
    test_network_policy.cpp
    test_config_store.cpp
    test_integrity_guard.cpp
    test_sandbox_analysis.cpp
)

# Analysis engine sources needed by tests (subset of full binary)
set(TESTABLE_SOURCES
    ${CMAKE_SOURCE_DIR}/src/native/analysis/fileanalysis/file_analyzer.cpp
    ${CMAKE_SOURCE_DIR}/src/native/analysis/fileanalysis/pe_analyzer.cpp
    ${CMAKE_SOURCE_DIR}/src/native/analysis/fileanalysis/pdf_analyzer.cpp
    ${CMAKE_SOURCE_DIR}/src/native/analysis/fileanalysis/archive_analyzer.cpp
    ${CMAKE_SOURCE_DIR}/src/native/analysis/fileanalysis/office_analyzer.cpp
    ${CMAKE_SOURCE_DIR}/src/native/analysis/content/content_analyzer.cpp
    ${CMAKE_SOURCE_DIR}/src/native/analysis/loganalysis/log_manager.cpp
    ${CMAKE_SOURCE_DIR}/src/native/analysis/loganalysis/log_normalizer.cpp
    ${CMAKE_SOURCE_DIR}/src/native/analysis/loganalysis/log_detector.cpp
    ${CMAKE_SOURCE_DIR}/src/native/analysis/loganalysis/log_analysis_engine.cpp
    ${CMAKE_SOURCE_DIR}/src/native/analysis/loganalysis/evtx_parser.cpp
    ${CMAKE_SOURCE_DIR}/src/native/analysis/sandbox/sandbox_engine.cpp
    ${CMAKE_SOURCE_DIR}/src/native/analysis/sandbox/behavior_signatures.cpp
    ${CMAKE_SOURCE_DIR}/src/native/analysis/sandbox/network_profiler.cpp
    ${CMAKE_SOURCE_DIR}/src/native/scoring/scoring_engine.cpp
    ${CMAKE_SOURCE_DIR}/src/native/export/defang.cpp
    ${CMAKE_SOURCE_DIR}/src/native/network/network_policy.cpp
    ${CMAKE_SOURCE_DIR}/src/native/config/config_store.cpp
    ${CMAKE_SOURCE_DIR}/src/native/security/integrity_guard.cpp
)

add_executable(shieldtier_tests ${TEST_SOURCES} ${TESTABLE_SOURCES})

target_include_directories(shieldtier_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/src/native
    ${CMAKE_SOURCE_DIR}/src/native/common
)

target_link_libraries(shieldtier_tests PRIVATE
    GTest::gtest_main
    nlohmann_json::nlohmann_json
    pe-parse
)

include(GoogleTest)
gtest_discover_tests(shieldtier_tests)
