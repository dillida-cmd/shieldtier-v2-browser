#pragma once

#include <memory>
#include <mutex>
#include <string>
#include <vector>

#ifndef SHIELDTIER_NO_YARA
#include <yara.h>
#endif

#include "analysis/yara/rule_manager.h"
#include "common/result.h"
#include "common/types.h"

namespace shieldtier {

class YaraEngine {
public:
    YaraEngine();
    ~YaraEngine();

    YaraEngine(const YaraEngine&) = delete;
    YaraEngine& operator=(const YaraEngine&) = delete;

    Result<bool> initialize();
    Result<bool> compile_rules();
    Result<AnalysisEngineResult> scan(const FileBuffer& file);

    RuleManager& rule_manager() { return rule_manager_; }

private:
#ifndef SHIELDTIER_NO_YARA
    static int scan_callback(YR_SCAN_CONTEXT* context, int message,
                             void* message_data, void* user_data);

    YR_RULES* compiled_rules_ = nullptr;
#endif

    RuleManager rule_manager_;
    std::mutex compile_mutex_;
    bool initialized_ = false;
};

}  // namespace shieldtier
