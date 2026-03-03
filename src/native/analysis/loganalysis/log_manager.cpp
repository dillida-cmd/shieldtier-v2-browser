#include "analysis/loganalysis/log_manager.h"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <sstream>
#include <string>

#include "analysis/loganalysis/log_detector.h"
#include "analysis/loganalysis/log_normalizer.h"

namespace shieldtier {

namespace {

constexpr size_t kMaxInputSize = 100 * 1024 * 1024;  // 100 MB
constexpr size_t kMaxEvents = 100000;

std::string to_lower(const std::string& s) {
    std::string out = s;
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return out;
}

bool contains_ci(const std::string& haystack, const std::string& needle) {
    auto it = std::search(
        haystack.begin(), haystack.end(),
        needle.begin(), needle.end(),
        [](char a, char b) {
            return std::tolower(static_cast<unsigned char>(a)) ==
                   std::tolower(static_cast<unsigned char>(b));
        });
    return it != haystack.end();
}

std::vector<std::string> split_lines(const std::string& content) {
    std::vector<std::string> lines;
    std::istringstream stream(content);
    std::string line;
    while (std::getline(stream, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        lines.push_back(std::move(line));
    }
    return lines;
}

std::string trim(const std::string& s) {
    auto start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    auto end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

// Split a CSV-like line by a delimiter, respecting double-quoted fields
std::vector<std::string> split_delimited(const std::string& line, char delim) {
    std::vector<std::string> fields;
    std::string field;
    bool in_quotes = false;
    for (size_t i = 0; i < line.size(); ++i) {
        char c = line[i];
        if (c == '"') {
            if (in_quotes && i + 1 < line.size() && line[i + 1] == '"') {
                field += '"';
                ++i;
            } else {
                in_quotes = !in_quotes;
            }
        } else if (c == delim && !in_quotes) {
            fields.push_back(trim(field));
            field.clear();
        } else {
            field += c;
        }
    }
    fields.push_back(trim(field));
    return fields;
}

// Detect the most likely delimiter from the first few lines
char detect_delimiter(const std::vector<std::string>& lines) {
    const char candidates[] = {',', '\t', ';', '|'};
    int best_count = 0;
    char best_delim = ',';

    size_t check_count = std::min(lines.size(), size_t(5));
    for (char delim : candidates) {
        int first_count = -1;
        bool consistent = true;
        for (size_t i = 0; i < check_count; ++i) {
            int count = 0;
            bool in_quotes = false;
            for (char c : lines[i]) {
                if (c == '"') in_quotes = !in_quotes;
                else if (c == delim && !in_quotes) ++count;
            }
            if (first_count == -1) {
                first_count = count;
            } else if (count != first_count) {
                consistent = false;
                break;
            }
        }
        if (consistent && first_count > best_count) {
            best_count = first_count;
            best_delim = delim;
        }
    }
    return best_delim;
}

// Map a header name to a NormalizedEvent field role
enum class FieldRole { kNone, kTimestamp, kSource, kMessage, kSeverity, kEventType };

FieldRole classify_header(const std::string& header) {
    std::string h = to_lower(header);
    if (h == "timestamp" || h == "time" || h == "date" || h == "@timestamp" ||
        h == "datetime" || h == "eventtime") {
        return FieldRole::kTimestamp;
    }
    if (h == "source" || h == "src" || h == "hostname" || h == "host" ||
        h == "computer") {
        return FieldRole::kSource;
    }
    if (h == "message" || h == "msg" || h == "description" || h == "log" ||
        h == "text") {
        return FieldRole::kMessage;
    }
    if (h == "severity" || h == "level" || h == "priority" || h == "loglevel") {
        return FieldRole::kSeverity;
    }
    if (h == "event_type" || h == "eventtype" || h == "action" || h == "type") {
        return FieldRole::kEventType;
    }
    return FieldRole::kNone;
}

Severity map_severity_string(const std::string& s) {
    std::string l = to_lower(s);
    if (l == "critical" || l == "fatal" || l == "emergency" || l == "alert") return Severity::kCritical;
    if (l == "high" || l == "error" || l == "err") return Severity::kHigh;
    if (l == "medium" || l == "warning" || l == "warn") return Severity::kMedium;
    if (l == "low" || l == "notice") return Severity::kLow;
    return Severity::kInfo;
}

// Check if a line looks like it starts with a month abbreviation (RFC 3164)
bool starts_with_month(const std::string& line) {
    static const char* months[] = {
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
    };
    if (line.size() < 3) return false;
    for (const char* m : months) {
        if (line[0] == m[0] && line[1] == m[1] && line[2] == m[2]) return true;
    }
    return false;
}

// Check if a character is a digit
bool is_digit(char c) { return c >= '0' && c <= '9'; }

// Check if a line looks like Apache Common Log Format: IP - - [timestamp] "METHOD ...
bool looks_like_apache(const std::string& line) {
    // Must have IP-like start, then bracket-enclosed timestamp, then quoted request
    auto bracket_pos = line.find('[');
    auto quote_pos = line.find('"');
    if (bracket_pos == std::string::npos || quote_pos == std::string::npos) return false;
    if (bracket_pos >= quote_pos) return false;
    // Check for IP-like prefix (digits and dots before first space)
    auto first_space = line.find(' ');
    if (first_space == std::string::npos || first_space < 7) return false;
    bool has_dot = false;
    for (size_t i = 0; i < first_space; ++i) {
        if (line[i] == '.') has_dot = true;
        else if (!is_digit(line[i]) && line[i] != ':') return false;  // allow : for IPv6
    }
    return has_dot;
}

}  // namespace

LogManager::LogManager() = default;

LogFormat LogManager::detect_format(const uint8_t* data, size_t size) {
    if (size < 4) return LogFormat::kAuto;

    // Tier 1: Magic bytes
    if (size >= 8 && std::memcmp(data, "ElfFile\0", 8) == 0) return LogFormat::kEvtx;
    if (size >= 4) {
        uint32_t magic = (uint32_t(data[0]) << 24) | (uint32_t(data[1]) << 16) |
                         (uint32_t(data[2]) << 8) | data[3];
        if (magic == 0xD4C3B2A1 || magic == 0xA1B2C3D4) return LogFormat::kPcap;
        if (magic == 0x0A0D0D0A) return LogFormat::kPcap;  // PCAPNG
    }
    if (size >= 4 && data[0] == 'P' && data[1] == 'K' && data[2] == 0x03 && data[3] == 0x04) {
        return LogFormat::kXlsx;
    }

    // Tier 2 & 3: Content sampling
    size_t scan_size = std::min(size, size_t(64 * 1024));
    std::string sample(reinterpret_cast<const char*>(data), scan_size);
    auto lines = split_lines(sample);

    // Collect first 50 non-empty lines
    std::vector<std::string> sample_lines;
    for (const auto& line : lines) {
        std::string trimmed = trim(line);
        if (!trimmed.empty()) {
            sample_lines.push_back(trimmed);
            if (sample_lines.size() >= 50) break;
        }
    }

    if (sample_lines.empty()) return LogFormat::kAuto;

    int cef_count = 0;
    int syslog_rfc5424_count = 0;
    int syslog_rfc3164_count = 0;
    int json_count = 0;
    int apache_count = 0;
    bool has_w3c_fields = false;
    int csv_consistent_lines = 0;

    char csv_delim = '\0';
    int csv_first_field_count = -1;

    for (size_t i = 0; i < sample_lines.size(); ++i) {
        const auto& line = sample_lines[i];

        // CEF check
        if (line.find("CEF:") != std::string::npos) ++cef_count;

        // RFC 5424: starts with <digits>
        if (line.size() > 1 && line[0] == '<' && is_digit(line[1])) {
            ++syslog_rfc5424_count;
        }

        // RFC 3164: starts with month abbreviation
        if (starts_with_month(line)) ++syslog_rfc3164_count;

        // JSON lines
        if (line.front() == '{' && line.back() == '}') ++json_count;

        // W3C directives
        if (line.find("#Fields:") == 0 || line.find("#Software:") == 0) has_w3c_fields = true;

        // Apache CLF
        if (looks_like_apache(line)) ++apache_count;

        // CSV delimiter consistency
        if (line[0] != '#') {
            for (char delim : {',', '\t', ';'}) {
                int count = 0;
                bool in_quotes = false;
                for (char c : line) {
                    if (c == '"') in_quotes = !in_quotes;
                    else if (c == delim && !in_quotes) ++count;
                }
                if (count > 0) {
                    if (csv_delim == '\0') {
                        csv_delim = delim;
                        csv_first_field_count = count;
                        csv_consistent_lines = 1;
                    } else if (delim == csv_delim && count == csv_first_field_count) {
                        ++csv_consistent_lines;
                    }
                }
            }
        }
    }

    // Decision hierarchy
    if (cef_count >= 2) return LogFormat::kCef;
    if (syslog_rfc5424_count >= 2 || syslog_rfc3164_count >= 2) return LogFormat::kSyslog;
    if (json_count >= 2) return LogFormat::kJson;
    if (has_w3c_fields) return LogFormat::kW3c;
    if (apache_count >= 2) return LogFormat::kApache;
    if (csv_consistent_lines >= 3) return LogFormat::kCsv;

    return LogFormat::kAuto;
}

Result<std::vector<NormalizedEvent>> LogManager::parse(
    const uint8_t* data, size_t size, LogFormat format) {

    if (size == 0) {
        return std::vector<NormalizedEvent>{};
    }

    if (size > kMaxInputSize) {
        return Error("input exceeds 100MB limit");
    }

    if (format == LogFormat::kAuto) {
        format = detect_format(data, size);
    }

    // Binary formats not yet supported
    if (format == LogFormat::kEvtx || format == LogFormat::kPcap ||
        format == LogFormat::kEml || format == LogFormat::kXlsx) {
        return Error("format not yet supported");
    }

    std::string content(reinterpret_cast<const char*>(data), size);

    std::vector<NormalizedEvent> events;
    switch (format) {
        case LogFormat::kCsv:    events = parse_csv(content); break;
        case LogFormat::kJson:   events = parse_json_lines(content); break;
        case LogFormat::kSyslog: events = parse_syslog(content); break;
        case LogFormat::kCef:    events = parse_cef(content); break;
        case LogFormat::kW3c:    events = parse_w3c(content); break;
        case LogFormat::kApache: events = parse_apache(content); break;
        case LogFormat::kNginx:  events = parse_apache(content); break;  // similar format
        default:
            return Error("unable to detect log format");
    }

    return events;
}

std::vector<NormalizedEvent> LogManager::parse_csv(const std::string& content) {
    auto lines = split_lines(content);
    if (lines.size() < 2) return {};

    char delim = detect_delimiter(lines);
    auto headers = split_delimited(lines[0], delim);

    // Map header indices to roles
    std::vector<FieldRole> roles;
    roles.reserve(headers.size());
    for (const auto& h : headers) {
        roles.push_back(classify_header(h));
    }

    std::vector<NormalizedEvent> events;
    for (size_t i = 1; i < lines.size() && events.size() < kMaxEvents; ++i) {
        if (lines[i].empty()) continue;
        auto fields = split_delimited(lines[i], delim);

        NormalizedEvent event;
        for (size_t j = 0; j < fields.size() && j < headers.size(); ++j) {
            switch (roles[j]) {
                case FieldRole::kTimestamp:
                    event.fields[headers[j]] = fields[j];
                    break;
                case FieldRole::kSource:
                    event.source = fields[j];
                    event.fields[headers[j]] = fields[j];
                    break;
                case FieldRole::kMessage:
                    event.message = fields[j];
                    event.fields[headers[j]] = fields[j];
                    break;
                case FieldRole::kSeverity:
                    event.severity = map_severity_string(fields[j]);
                    event.fields[headers[j]] = fields[j];
                    break;
                case FieldRole::kEventType:
                    event.event_type = fields[j];
                    event.fields[headers[j]] = fields[j];
                    break;
                default:
                    event.fields[headers[j]] = fields[j];
                    break;
            }
        }
        events.push_back(std::move(event));
    }

    return events;
}

std::vector<NormalizedEvent> LogManager::parse_json_lines(const std::string& content) {
    auto lines = split_lines(content);
    std::vector<NormalizedEvent> events;

    for (const auto& line : lines) {
        if (events.size() >= kMaxEvents) break;
        std::string trimmed = trim(line);
        if (trimmed.empty() || trimmed.front() != '{') continue;

        json obj;
        try {
            obj = json::parse(trimmed);
        } catch (...) {
            continue;
        }
        if (!obj.is_object()) continue;

        NormalizedEvent event;
        event.fields = obj;

        // Extract timestamp
        for (const char* key : {"timestamp", "@timestamp", "time", "date", "ts"}) {
            if (obj.contains(key)) {
                if (obj[key].is_string()) {
                    event.fields["_raw_timestamp"] = obj[key].get<std::string>();
                } else if (obj[key].is_number()) {
                    int64_t val = obj[key].get<int64_t>();
                    // 13-digit = millis, 10-digit = seconds
                    event.timestamp = (val > 9999999999LL) ? val : val * 1000;
                }
                break;
            }
        }

        // Extract message
        for (const char* key : {"message", "msg", "log", "text"}) {
            if (obj.contains(key) && obj[key].is_string()) {
                event.message = obj[key].get<std::string>();
                break;
            }
        }

        // Extract severity
        for (const char* key : {"level", "severity", "priority"}) {
            if (obj.contains(key) && obj[key].is_string()) {
                event.severity = map_severity_string(obj[key].get<std::string>());
                break;
            }
        }

        // Extract source
        for (const char* key : {"source", "hostname", "host"}) {
            if (obj.contains(key) && obj[key].is_string()) {
                event.source = obj[key].get<std::string>();
                break;
            }
        }

        events.push_back(std::move(event));
    }

    return events;
}

std::vector<NormalizedEvent> LogManager::parse_syslog(const std::string& content) {
    auto lines = split_lines(content);
    std::vector<NormalizedEvent> events;

    for (const auto& line : lines) {
        if (events.size() >= kMaxEvents) break;
        if (line.empty()) continue;

        NormalizedEvent event;
        size_t pos = 0;

        // Try RFC 5424/3164 with PRI: <PRI>...
        if (line[0] == '<') {
            auto close = line.find('>');
            if (close != std::string::npos && close < 5) {
                int pri = 0;
                bool valid_pri = true;
                for (size_t i = 1; i < close; ++i) {
                    if (is_digit(line[i])) {
                        pri = pri * 10 + (line[i] - '0');
                    } else {
                        valid_pri = false;
                        break;
                    }
                }
                if (valid_pri) {
                    int sev_val = pri % 8;
                    if (sev_val <= 2) event.severity = Severity::kCritical;
                    else if (sev_val == 3) event.severity = Severity::kHigh;
                    else if (sev_val == 4) event.severity = Severity::kMedium;
                    else if (sev_val == 5) event.severity = Severity::kLow;
                    else event.severity = Severity::kInfo;

                    event.fields["facility"] = pri / 8;
                    event.fields["priority"] = sev_val;
                }
                pos = close + 1;
            }
        }

        // After PRI, check for RFC 5424 version digit
        bool is_rfc5424 = false;
        if (pos < line.size() && is_digit(line[pos]) && pos + 1 < line.size() && line[pos + 1] == ' ') {
            event.fields["version"] = line[pos] - '0';
            pos += 2;
            is_rfc5424 = true;
        }

        // Extract remaining as message, parse hostname from it
        std::string remainder = line.substr(pos);

        if (is_rfc5424) {
            // RFC 5424: TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG
            // Timestamp ends at space, then hostname, etc.
            auto parts_end = remainder.find(" - ");
            if (parts_end == std::string::npos) parts_end = remainder.size();

            // Split by spaces for structured fields
            std::vector<std::string> tokens;
            std::istringstream iss(remainder);
            std::string token;
            while (iss >> token && tokens.size() < 6) {
                tokens.push_back(token);
            }
            // tokens: [TIMESTAMP, HOSTNAME, APP-NAME, PROCID, MSGID, ...]
            if (tokens.size() >= 2) {
                event.fields["_raw_timestamp"] = tokens[0];
                event.source = tokens[1];
            }
            if (tokens.size() >= 3 && tokens[2] != "-") {
                event.fields["app_name"] = tokens[2];
            }
            if (tokens.size() >= 4 && tokens[3] != "-") {
                event.fields["proc_id"] = tokens[3];
            }
            if (tokens.size() >= 5 && tokens[4] != "-") {
                event.fields["msg_id"] = tokens[4];
            }

            // Message is everything after the structured data
            auto msg_start = remainder.find(']');
            if (msg_start != std::string::npos && msg_start + 1 < remainder.size()) {
                event.message = trim(remainder.substr(msg_start + 1));
            } else {
                // No structured data — find message after MSGID
                size_t space_count = 0;
                size_t msg_pos = 0;
                for (size_t i = 0; i < remainder.size(); ++i) {
                    if (remainder[i] == ' ') {
                        ++space_count;
                        if (space_count >= 5) {
                            msg_pos = i + 1;
                            break;
                        }
                    }
                }
                if (msg_pos > 0 && msg_pos < remainder.size()) {
                    event.message = remainder.substr(msg_pos);
                }
            }
        } else {
            // RFC 3164 or bare syslog: Mon DD HH:MM:SS HOSTNAME MSG
            // Or just the text after PRI
            if (starts_with_month(remainder)) {
                // Parse: Mon DD HH:MM:SS HOSTNAME MSG
                size_t space_count = 0;
                size_t hostname_start = 0;
                for (size_t i = 0; i < remainder.size(); ++i) {
                    if (remainder[i] == ' ') {
                        ++space_count;
                        if (space_count == 3) {
                            hostname_start = i + 1;
                        }
                        if (space_count == 4) {
                            event.source = remainder.substr(hostname_start, i - hostname_start);
                            event.message = remainder.substr(i + 1);
                            break;
                        }
                    }
                }
                event.fields["_raw_timestamp"] = remainder.substr(0, hostname_start > 0 ? hostname_start - 1 : 15);
            } else {
                event.message = remainder;
            }
        }

        // SSH pattern enrichment
        if (event.message.find("Failed password") != std::string::npos) {
            event.fields["ssh_event"] = "failed_auth";
        } else if (event.message.find("Accepted password") != std::string::npos) {
            event.fields["ssh_event"] = "accepted_auth";
        } else if (event.message.find("Invalid user") != std::string::npos) {
            event.fields["ssh_event"] = "invalid_user";
        }

        events.push_back(std::move(event));
    }

    return events;
}

std::vector<NormalizedEvent> LogManager::parse_cef(const std::string& content) {
    auto lines = split_lines(content);
    std::vector<NormalizedEvent> events;

    for (const auto& line : lines) {
        if (events.size() >= kMaxEvents) break;
        if (line.empty()) continue;

        // Find CEF: header — may be preceded by syslog prefix
        auto cef_pos = line.find("CEF:");
        if (cef_pos == std::string::npos) continue;

        std::string cef_line = line.substr(cef_pos);

        // Split on unescaped '|' — CEF has exactly 7 pipe-delimited header fields
        // CEF:Version|DeviceVendor|DeviceProduct|DeviceVersion|SignatureID|Name|Severity|Extensions
        std::vector<std::string> header_fields;
        std::string current;
        bool escaped = false;

        for (size_t i = 0; i < cef_line.size(); ++i) {
            char c = cef_line[i];
            if (escaped) {
                current += c;
                escaped = false;
                continue;
            }
            if (c == '\\') {
                escaped = true;
                continue;
            }
            if (c == '|' && header_fields.size() < 7) {
                header_fields.push_back(current);
                current.clear();
            } else {
                current += c;
            }
        }
        // Last field is extensions
        std::string extensions = current;

        if (header_fields.size() < 7) continue;

        // header_fields[0] = "CEF:Version"
        // header_fields[1] = DeviceVendor
        // header_fields[2] = DeviceProduct
        // header_fields[3] = DeviceVersion
        // header_fields[4] = SignatureID
        // header_fields[5] = Name
        // header_fields[6] = Severity

        NormalizedEvent event;
        event.message = header_fields[5];
        event.event_type = header_fields[4];
        event.fields["device_vendor"] = header_fields[1];
        event.fields["device_product"] = header_fields[2];
        event.fields["device_version"] = header_fields[3];
        event.fields["signature_id"] = header_fields[4];
        event.fields["cef_version"] = header_fields[0];

        // Map CEF severity (0-10) to Severity enum
        int cef_sev = 0;
        try {
            cef_sev = std::stoi(header_fields[6]);
        } catch (...) {
            // May be a string severity
            event.severity = map_severity_string(header_fields[6]);
            cef_sev = -1;
        }
        if (cef_sev >= 0) {
            if (cef_sev <= 3) event.severity = Severity::kInfo;
            else if (cef_sev == 4) event.severity = Severity::kLow;
            else if (cef_sev <= 6) event.severity = Severity::kMedium;
            else if (cef_sev <= 8) event.severity = Severity::kHigh;
            else event.severity = Severity::kCritical;
        }

        // Parse extensions as key=value pairs
        if (!extensions.empty()) {
            std::string key;
            std::string value;
            bool reading_key = true;
            bool ext_escaped = false;

            for (size_t i = 0; i < extensions.size(); ++i) {
                char c = extensions[i];
                if (ext_escaped) {
                    if (reading_key) key += c;
                    else value += c;
                    ext_escaped = false;
                    continue;
                }
                if (c == '\\') {
                    ext_escaped = true;
                    continue;
                }
                if (c == '=' && reading_key) {
                    reading_key = false;
                    continue;
                }
                // A space followed by a key= pattern means new key-value pair
                if (c == ' ' && !reading_key) {
                    // Look ahead for key=
                    size_t eq_pos = extensions.find('=', i + 1);
                    size_t sp_pos = extensions.find(' ', i + 1);
                    if (eq_pos != std::string::npos &&
                        (sp_pos == std::string::npos || eq_pos < sp_pos)) {
                        // New key starting — save current pair
                        event.fields[trim(key)] = trim(value);
                        key.clear();
                        value.clear();
                        reading_key = true;
                        continue;
                    }
                }
                if (reading_key) key += c;
                else value += c;
            }
            if (!key.empty()) {
                event.fields[trim(key)] = trim(value);
            }
        }

        events.push_back(std::move(event));
    }

    return events;
}

std::vector<NormalizedEvent> LogManager::parse_w3c(const std::string& content) {
    auto lines = split_lines(content);
    std::vector<NormalizedEvent> events;
    std::vector<std::string> field_names;

    for (const auto& line : lines) {
        if (events.size() >= kMaxEvents) break;
        if (line.empty()) continue;

        if (line[0] == '#') {
            // Directive
            if (line.find("#Fields:") == 0 || line.find("#Fields: ") == 0) {
                std::string fields_str = line.substr(line.find(':') + 1);
                field_names.clear();
                std::istringstream iss(trim(fields_str));
                std::string fname;
                while (iss >> fname) {
                    field_names.push_back(fname);
                }
            }
            continue;
        }

        if (field_names.empty()) continue;

        // Data line — space-separated values
        std::vector<std::string> values;
        std::istringstream iss(line);
        std::string val;
        while (iss >> val) {
            values.push_back(val);
        }

        NormalizedEvent event;
        std::string date_part;
        std::string time_part;

        for (size_t i = 0; i < values.size() && i < field_names.size(); ++i) {
            if (values[i] == "-") continue;  // W3C uses - for empty fields

            const auto& fname = field_names[i];
            event.fields[fname] = values[i];

            if (fname == "date") date_part = values[i];
            else if (fname == "time") time_part = values[i];
            else if (fname == "s-ip" || fname == "c-ip") event.source = values[i];
            else if (fname == "cs-method") event.event_type = values[i];
            else if (fname == "cs-uri-stem" || fname == "cs-uri-query") {
                if (!event.message.empty()) event.message += "?";
                event.message += values[i];
            }
            else if (fname == "sc-status") {
                int status = 0;
                try { status = std::stoi(values[i]); } catch (...) {}
                if (status >= 500) event.severity = Severity::kHigh;
                else if (status >= 400) event.severity = Severity::kMedium;
            }
        }

        if (!date_part.empty() && !time_part.empty()) {
            event.fields["_raw_timestamp"] = date_part + "T" + time_part + "Z";
        }

        events.push_back(std::move(event));
    }

    return events;
}

std::vector<NormalizedEvent> LogManager::parse_apache(const std::string& content) {
    auto lines = split_lines(content);
    std::vector<NormalizedEvent> events;

    for (const auto& line : lines) {
        if (events.size() >= kMaxEvents) break;
        if (line.empty()) continue;

        NormalizedEvent event;

        // Apache CLF: IP - USER [DD/Mon/YYYY:HH:MM:SS +ZONE] "METHOD URI PROTO" STATUS SIZE
        size_t pos = 0;

        // Extract IP
        auto first_space = line.find(' ', pos);
        if (first_space == std::string::npos) continue;
        std::string ip = line.substr(pos, first_space);
        event.source = ip;
        event.fields["client_ip"] = ip;

        // Skip ident (-) and user
        pos = first_space + 1;
        auto ident_space = line.find(' ', pos);
        if (ident_space == std::string::npos) continue;
        pos = ident_space + 1;

        auto user_space = line.find(' ', pos);
        if (user_space == std::string::npos) continue;
        std::string user = line.substr(pos, user_space - pos);
        if (user != "-") event.fields["user"] = user;
        pos = user_space + 1;

        // Extract timestamp [DD/Mon/YYYY:HH:MM:SS +ZONE]
        if (pos >= line.size() || line[pos] != '[') continue;
        auto ts_end = line.find(']', pos);
        if (ts_end == std::string::npos) continue;
        std::string ts_str = line.substr(pos + 1, ts_end - pos - 1);
        event.fields["_raw_timestamp"] = ts_str;
        pos = ts_end + 1;

        // Skip space
        if (pos < line.size() && line[pos] == ' ') ++pos;

        // Extract request "METHOD URI PROTO"
        if (pos >= line.size() || line[pos] != '"') continue;
        auto req_end = line.find('"', pos + 1);
        if (req_end == std::string::npos) continue;
        std::string request = line.substr(pos + 1, req_end - pos - 1);
        event.message = request;

        // Parse method and URI from request
        auto method_end = request.find(' ');
        if (method_end != std::string::npos) {
            event.event_type = request.substr(0, method_end);
            event.fields["method"] = event.event_type;
            auto uri_end = request.find(' ', method_end + 1);
            if (uri_end != std::string::npos) {
                event.fields["uri"] = request.substr(method_end + 1, uri_end - method_end - 1);
                event.fields["protocol"] = request.substr(uri_end + 1);
            } else {
                event.fields["uri"] = request.substr(method_end + 1);
            }
        }
        pos = req_end + 1;

        // Skip space
        if (pos < line.size() && line[pos] == ' ') ++pos;

        // Extract status code
        auto status_end = line.find(' ', pos);
        if (status_end == std::string::npos) status_end = line.size();
        std::string status_str = line.substr(pos, status_end - pos);
        int status = 0;
        try { status = std::stoi(status_str); } catch (...) {}
        event.fields["status"] = status;
        if (status >= 500) event.severity = Severity::kHigh;
        else if (status >= 400) event.severity = Severity::kMedium;
        pos = status_end;

        // Extract size
        if (pos < line.size() && line[pos] == ' ') ++pos;
        auto size_end = line.find(' ', pos);
        if (size_end == std::string::npos) size_end = line.size();
        std::string size_str = line.substr(pos, size_end - pos);
        if (size_str != "-") {
            try { event.fields["bytes"] = std::stoll(size_str); } catch (...) {}
        }
        pos = size_end;

        // Combined format: "referer" "user-agent"
        if (pos < line.size() && line[pos] == ' ') ++pos;
        if (pos < line.size() && line[pos] == '"') {
            auto ref_end = line.find('"', pos + 1);
            if (ref_end != std::string::npos) {
                std::string referer = line.substr(pos + 1, ref_end - pos - 1);
                if (referer != "-") event.fields["referer"] = referer;
                pos = ref_end + 1;

                if (pos < line.size() && line[pos] == ' ') ++pos;
                if (pos < line.size() && line[pos] == '"') {
                    auto ua_end = line.find('"', pos + 1);
                    if (ua_end != std::string::npos) {
                        event.fields["user_agent"] = line.substr(pos + 1, ua_end - pos - 1);
                    }
                }
            }
        }

        events.push_back(std::move(event));
    }

    return events;
}

Result<AnalysisEngineResult> LogManager::analyze(const FileBuffer& file) {
    auto start = std::chrono::steady_clock::now();

    auto parse_result = parse(file.ptr(), file.size());
    if (!parse_result.ok()) {
        AnalysisEngineResult result;
        result.engine = AnalysisEngine::kLogAnalysis;
        result.success = false;
        result.error = parse_result.error().message;
        auto end = std::chrono::steady_clock::now();
        result.duration_ms = std::chrono::duration<double, std::milli>(end - start).count();
        return result;
    }

    auto& events = parse_result.value();

    // Normalize events
    LogNormalizer normalizer;
    normalizer.normalize(events);

    // Run detections
    LogDetector detector;
    auto findings = detector.detect(events);

    auto end = std::chrono::steady_clock::now();
    double duration_ms = std::chrono::duration<double, std::milli>(end - start).count();

    AnalysisEngineResult result;
    result.engine = AnalysisEngine::kLogAnalysis;
    result.success = true;
    result.findings = std::move(findings);
    result.duration_ms = duration_ms;
    result.raw_output = {
        {"event_count", events.size()},
        {"filename", file.filename},
        {"format_detected", static_cast<int>(detect_format(file.ptr(), file.size()))},
    };

    return result;
}

}  // namespace shieldtier
