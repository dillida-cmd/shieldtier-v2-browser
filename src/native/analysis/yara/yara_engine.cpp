#include "analysis/yara/yara_engine.h"

#include <chrono>

namespace shieldtier {

#ifdef SHIELDTIER_NO_YARA

// Stub implementation when YARA is not available (Windows without vcpkg)
YaraEngine::YaraEngine() = default;
YaraEngine::~YaraEngine() = default;

Result<bool> YaraEngine::initialize() {
    initialized_ = true;
    return true;
}

Result<bool> YaraEngine::compile_rules() {
    return true;
}

Result<AnalysisEngineResult> YaraEngine::scan(const FileBuffer& file) {
    AnalysisEngineResult result;
    result.engine = AnalysisEngine::kYara;
    result.success = true;
    result.duration_ms = 0.0;
    result.raw_output = {
        {"rules_matched", 0},
        {"note", "YARA not available — install via vcpkg"},
    };
    return result;
}

#else  // YARA available

namespace {

Severity severity_from_string(const char* str) {
    if (!str) return Severity::kMedium;
    std::string s(str);
    if (s == "info") return Severity::kInfo;
    if (s == "low") return Severity::kLow;
    if (s == "medium") return Severity::kMedium;
    if (s == "high") return Severity::kHigh;
    if (s == "critical") return Severity::kCritical;
    return Severity::kMedium;
}

}  // namespace

YaraEngine::YaraEngine() = default;

YaraEngine::~YaraEngine() {
    if (compiled_rules_) {
        yr_rules_destroy(compiled_rules_);
        compiled_rules_ = nullptr;
    }
    if (initialized_) {
        yr_finalize();
    }
}

Result<bool> YaraEngine::initialize() {
    {
        std::lock_guard<std::mutex> lock(compile_mutex_);
        if (initialized_) return true;

        int result = yr_initialize();
        if (result != ERROR_SUCCESS) {
            return Error("Failed to initialize YARA library (error " +
                             std::to_string(result) + ")",
                         "YARA_INIT");
        }
        initialized_ = true;
    }

    auto compile_result = compile_rules();
    if (!compile_result.ok()) return compile_result;

    return true;
}

Result<bool> YaraEngine::compile_rules() {
    std::lock_guard<std::mutex> lock(compile_mutex_);

    if (!initialized_) {
        return Error("YARA not initialized", "YARA_NOT_INIT");
    }

    YR_COMPILER* compiler = nullptr;
    int result = yr_compiler_create(&compiler);
    if (result != ERROR_SUCCESS) {
        return Error("Failed to create YARA compiler (error " +
                         std::to_string(result) + ")",
                     "YARA_COMPILER");
    }

    auto rules = rule_manager_.get_all_rules();
    for (const auto& rule : rules) {
        int errors = yr_compiler_add_string(compiler, rule.source.c_str(),
                                            nullptr);
        if (errors > 0) {
            yr_compiler_destroy(compiler);
            return Error("Failed to compile rule: " + rule.name, "YARA_COMPILE");
        }
    }

    YR_RULES* new_rules = nullptr;
    result = yr_compiler_get_rules(compiler, &new_rules);
    yr_compiler_destroy(compiler);

    if (result != ERROR_SUCCESS) {
        return Error("Failed to get compiled rules (error " +
                         std::to_string(result) + ")",
                     "YARA_GET_RULES");
    }

    if (compiled_rules_) {
        yr_rules_destroy(compiled_rules_);
    }
    compiled_rules_ = new_rules;

    return true;
}

int YaraEngine::scan_callback(YR_SCAN_CONTEXT* /*context*/, int message,
                              void* message_data, void* user_data) {
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        auto* findings = static_cast<std::vector<Finding>*>(user_data);
        auto* rule = static_cast<YR_RULE*>(message_data);

        std::string name = rule->identifier;
        std::string description;
        std::string author;
        Severity severity = Severity::kMedium;

        YR_META* meta;
        yr_rule_metas_foreach(rule, meta) {
            std::string key(meta->identifier);
            if (key == "severity" && meta->type == META_TYPE_STRING) {
                severity = severity_from_string(meta->string);
            } else if (key == "description" && meta->type == META_TYPE_STRING) {
                description = meta->string;
            } else if (key == "author" && meta->type == META_TYPE_STRING) {
                author = meta->string;
            }
        }

        if (description.empty()) {
            description = "YARA rule matched: " + name;
        }

        Finding finding;
        finding.title = "YARA: " + name;
        finding.description = description;
        finding.severity = severity;
        finding.engine = AnalysisEngine::kYara;
        finding.metadata = {
            {"rule_name", name},
            {"author", author},
        };

        const char* tag;
        std::vector<std::string> tags;
        yr_rule_tags_foreach(rule, tag) {
            tags.emplace_back(tag);
        }
        if (!tags.empty()) {
            finding.metadata["tags"] = tags;
        }

        findings->push_back(std::move(finding));
    }

    return CALLBACK_CONTINUE;
}

Result<AnalysisEngineResult> YaraEngine::scan(const FileBuffer& file) {
    YR_RULES* rules = nullptr;
    {
        std::lock_guard<std::mutex> lock(compile_mutex_);
        if (!initialized_) {
            return Error("YARA engine not initialized", "YARA_NOT_INIT");
        }
        if (!compiled_rules_) {
            return Error("No compiled rules available", "YARA_NO_RULES");
        }
        rules = compiled_rules_;
    }

    auto start = std::chrono::steady_clock::now();

    std::vector<Finding> findings;
    int result = yr_rules_scan_mem(rules, file.ptr(),
                                   file.size(), 0, scan_callback,
                                   &findings, 30);

    auto end = std::chrono::steady_clock::now();
    double duration_ms =
        std::chrono::duration<double, std::milli>(end - start).count();

    AnalysisEngineResult engine_result;
    engine_result.engine = AnalysisEngine::kYara;
    engine_result.duration_ms = duration_ms;

    if (result != ERROR_SUCCESS) {
        engine_result.success = false;
        engine_result.error =
            "YARA scan failed (error " + std::to_string(result) + ")";
        return engine_result;
    }

    engine_result.success = true;
    engine_result.findings = std::move(findings);
    engine_result.raw_output = {
        {"rules_matched", engine_result.findings.size()},
        {"file_size", file.size()},
        {"filename", file.filename},
    };

    return engine_result;
}

#endif  // SHIELDTIER_NO_YARA

}  // namespace shieldtier
