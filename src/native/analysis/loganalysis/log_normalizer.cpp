#include "analysis/loganalysis/log_normalizer.h"

#include <algorithm>
#include <chrono>
#include <ctime>
#include <string>

#include "analysis/loganalysis/log_manager.h"

namespace shieldtier {

namespace {

std::string to_lower(const std::string& s) {
    std::string out = s;
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return out;
}

bool is_digit(char c) { return c >= '0' && c <= '9'; }

// Try to get a string value from a json field, returning empty if not present or not a string
std::string json_string(const json& obj, const char* key) {
    if (obj.contains(key) && obj[key].is_string()) {
        return obj[key].get<std::string>();
    }
    return "";
}

// Set a canonical field if not already present, checking a list of source field names
void set_canonical(json& fields, const std::string& canonical,
                   const std::vector<std::string>& source_keys) {
    if (fields.contains(canonical)) return;
    for (const auto& key : source_keys) {
        if (fields.contains(key) && fields[key].is_string()) {
            std::string val = fields[key].get<std::string>();
            if (!val.empty()) {
                fields[canonical] = val;
                return;
            }
        }
    }
}

int month_from_abbr(const std::string& abbr) {
    static const char* months[] = {
        "jan", "feb", "mar", "apr", "may", "jun",
        "jul", "aug", "sep", "oct", "nov", "dec"
    };
    std::string lower = to_lower(abbr.substr(0, 3));
    for (int i = 0; i < 12; ++i) {
        if (lower == months[i]) return i;  // 0-based for tm_mon
    }
    return -1;
}

}  // namespace

LogNormalizer::LogNormalizer() = default;

void LogNormalizer::normalize(std::vector<NormalizedEvent>& events) {
    for (auto& event : events) {
        normalize_fields(event);
        extract_canonical_fields(event);
    }
}

void LogNormalizer::normalize_fields(NormalizedEvent& event) {
    if (event.timestamp == 0) {
        for (const char* key : {"timestamp", "@timestamp", "time", "date", "_raw_timestamp"}) {
            std::string ts = json_string(event.fields, key);
            if (!ts.empty()) {
                int64_t parsed = parse_timestamp(ts);
                if (parsed != 0) {
                    event.timestamp = parsed;
                    break;
                }
            }
        }
    }

    if (event.event_type.empty()) {
        for (const char* key : {"eventType", "event_type", "action", "ActionType"}) {
            std::string val = json_string(event.fields, key);
            if (!val.empty()) {
                event.event_type = val;
                break;
            }
        }
    }

    if (event.source.empty()) {
        for (const char* key : {"source", "hostname", "host", "Computer"}) {
            std::string val = json_string(event.fields, key);
            if (!val.empty()) {
                event.source = val;
                break;
            }
        }
    }
}

void LogNormalizer::extract_canonical_fields(NormalizedEvent& event) {
    set_canonical(event.fields, "_user",
        {"User", "Username", "user", "username", "TargetUserName", "suser", "duser"});

    set_canonical(event.fields, "_src_ip",
        {"src_ip", "SourceIP", "IpAddress", "ClientIP", "src", "callerIpAddress"});

    set_canonical(event.fields, "_dst_ip",
        {"dst_ip", "DestinationIP", "RemoteIP", "dst", "destinationAddress"});

    set_canonical(event.fields, "_host",
        {"hostname", "Computer", "MachineName", "deviceHostName", "host"});

    set_canonical(event.fields, "_process",
        {"Image", "ProcessName", "FileName", "process", "app"});

    set_canonical(event.fields, "_command",
        {"CommandLine", "ProcessCommandLine", "command", "cmd"});
}

int64_t LogNormalizer::parse_timestamp(const std::string& ts) {
    if (ts.empty()) return 0;

    // Check for pure numeric (epoch seconds or millis)
    bool all_digits = true;
    for (char c : ts) {
        if (!is_digit(c)) { all_digits = false; break; }
    }
    if (all_digits && ts.size() >= 10) {
        try {
            int64_t val = std::stoll(ts);
            return (val > 9999999999LL) ? val : val * 1000;
        } catch (...) {}
    }

    // ISO 8601: 2025-03-03T14:22:15Z or 2025-03-03T14:22:15.000Z or with offset
    if (ts.size() >= 19 && ts[4] == '-' && ts[7] == '-' && (ts[10] == 'T' || ts[10] == ' ')) {
        struct std::tm tm = {};
        tm.tm_year = std::stoi(ts.substr(0, 4)) - 1900;
        tm.tm_mon = std::stoi(ts.substr(5, 2)) - 1;
        tm.tm_mday = std::stoi(ts.substr(8, 2));
        tm.tm_hour = std::stoi(ts.substr(11, 2));
        tm.tm_min = std::stoi(ts.substr(14, 2));
        tm.tm_sec = std::stoi(ts.substr(17, 2));

        int64_t millis = 0;
        size_t frac_pos = 19;
        if (frac_pos < ts.size() && ts[frac_pos] == '.') {
            ++frac_pos;
            std::string frac;
            while (frac_pos < ts.size() && is_digit(ts[frac_pos])) {
                frac += ts[frac_pos++];
            }
            while (frac.size() < 3) frac += '0';
            try { millis = std::stoll(frac.substr(0, 3)); } catch (...) {}
        }

        // Handle timezone offset
        int tz_offset_sec = 0;
        if (frac_pos < ts.size()) {
            char tz_char = ts[frac_pos];
            if (tz_char == '+' || tz_char == '-') {
                int tz_h = 0, tz_m = 0;
                if (frac_pos + 5 <= ts.size()) {
                    tz_h = std::stoi(ts.substr(frac_pos + 1, 2));
                    // Colon-separated or not
                    size_t min_start = frac_pos + 3;
                    if (min_start < ts.size() && ts[min_start] == ':') ++min_start;
                    if (min_start + 2 <= ts.size()) {
                        tz_m = std::stoi(ts.substr(min_start, 2));
                    }
                }
                tz_offset_sec = (tz_h * 3600 + tz_m * 60) * (tz_char == '+' ? 1 : -1);
            }
        }

#ifdef _WIN32
        time_t epoch = _mkgmtime(&tm);
#else
        time_t epoch = timegm(&tm);
#endif
        if (epoch == -1) return 0;
        epoch -= tz_offset_sec;
        return static_cast<int64_t>(epoch) * 1000 + millis;
    }

    // Apache-style: DD/Mon/YYYY:HH:MM:SS +ZONE
    // e.g. 03/Mar/2025:14:22:15 +0000
    if (ts.size() >= 20 && ts[2] == '/' && ts[6] == '/') {
        struct std::tm tm = {};
        tm.tm_mday = std::stoi(ts.substr(0, 2));
        int mon = month_from_abbr(ts.substr(3, 3));
        if (mon < 0) return 0;
        tm.tm_mon = mon;
        tm.tm_year = std::stoi(ts.substr(7, 4)) - 1900;
        tm.tm_hour = std::stoi(ts.substr(12, 2));
        tm.tm_min = std::stoi(ts.substr(15, 2));
        tm.tm_sec = std::stoi(ts.substr(18, 2));

        int tz_offset_sec = 0;
        if (ts.size() >= 24 && (ts[21] == '+' || ts[21] == '-')) {
            int tz_h = std::stoi(ts.substr(22, 2));
            int tz_m = std::stoi(ts.substr(24, 2));
            tz_offset_sec = (tz_h * 3600 + tz_m * 60) * (ts[21] == '+' ? 1 : -1);
        }

#ifdef _WIN32
        time_t epoch = _mkgmtime(&tm);
#else
        time_t epoch = timegm(&tm);
#endif
        if (epoch == -1) return 0;
        epoch -= tz_offset_sec;
        return static_cast<int64_t>(epoch) * 1000;
    }

    // Syslog-style: Mon DD HH:MM:SS (use current year)
    // e.g. Mar  3 14:22:15 or Mar 03 14:22:15
    if (ts.size() >= 14) {
        int mon = month_from_abbr(ts.substr(0, 3));
        if (mon >= 0) {
            // Find day: skip spaces after month
            size_t day_start = 3;
            while (day_start < ts.size() && ts[day_start] == ' ') ++day_start;
            size_t day_end = day_start;
            while (day_end < ts.size() && is_digit(ts[day_end])) ++day_end;
            if (day_end > day_start && day_end + 1 < ts.size()) {
                int day = std::stoi(ts.substr(day_start, day_end - day_start));

                // Time starts after space
                size_t time_start = day_end + 1;
                if (time_start + 8 <= ts.size()) {
                    struct std::tm tm = {};
                    auto now = std::chrono::system_clock::now();
                    auto now_t = std::chrono::system_clock::to_time_t(now);
                    struct std::tm now_tm;
#ifdef _WIN32
                    gmtime_s(&now_tm, &now_t);
#else
                    gmtime_r(&now_t, &now_tm);
#endif
                    tm.tm_year = now_tm.tm_year;
                    tm.tm_mon = mon;
                    tm.tm_mday = day;
                    tm.tm_hour = std::stoi(ts.substr(time_start, 2));
                    tm.tm_min = std::stoi(ts.substr(time_start + 3, 2));
                    tm.tm_sec = std::stoi(ts.substr(time_start + 6, 2));

#ifdef _WIN32
                    time_t epoch = _mkgmtime(&tm);
#else
                    time_t epoch = timegm(&tm);
#endif
                    if (epoch != -1) return static_cast<int64_t>(epoch) * 1000;
                }
            }
        }
    }

    return 0;
}

Severity LogNormalizer::map_severity(const std::string& level) {
    std::string l = to_lower(level);
    if (l == "critical" || l == "fatal" || l == "emergency" || l == "alert") return Severity::kCritical;
    if (l == "high" || l == "error" || l == "err") return Severity::kHigh;
    if (l == "medium" || l == "warning" || l == "warn") return Severity::kMedium;
    if (l == "low" || l == "notice") return Severity::kLow;
    if (l == "info" || l == "debug" || l == "trace" || l == "informational") return Severity::kInfo;
    return Severity::kInfo;
}

}  // namespace shieldtier
