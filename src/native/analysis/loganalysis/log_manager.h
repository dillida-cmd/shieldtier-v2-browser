#pragma once

#include <string>
#include <vector>

#include "common/json.h"
#include "common/result.h"
#include "common/types.h"

namespace shieldtier {

enum class LogFormat {
    kCsv, kJson, kEvtx, kSyslog, kCef, kLeef,
    kW3c, kApache, kNginx, kPcap, kEml, kXlsx, kAuto
};

struct NormalizedEvent {
    int64_t timestamp = 0;
    std::string source;
    std::string event_type;
    Severity severity = Severity::kInfo;
    std::string message;
    json fields;
};

class LogManager {
public:
    LogManager();

    Result<std::vector<NormalizedEvent>> parse(
        const uint8_t* data, size_t size, LogFormat format = LogFormat::kAuto);

    Result<AnalysisEngineResult> analyze(const FileBuffer& file);

    LogFormat detect_format(const uint8_t* data, size_t size);

private:
    std::vector<NormalizedEvent> parse_csv(const std::string& content);
    std::vector<NormalizedEvent> parse_json_lines(const std::string& content);
    std::vector<NormalizedEvent> parse_syslog(const std::string& content);
    std::vector<NormalizedEvent> parse_cef(const std::string& content);
    std::vector<NormalizedEvent> parse_w3c(const std::string& content);
    std::vector<NormalizedEvent> parse_apache(const std::string& content);
};

}  // namespace shieldtier
