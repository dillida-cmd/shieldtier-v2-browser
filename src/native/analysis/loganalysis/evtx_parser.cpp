#include "analysis/loganalysis/evtx_parser.h"

#include <cstring>
#include <ctime>

namespace shieldtier {

namespace {

// Read a little-endian uint16 from buffer
uint16_t read_u16(const uint8_t* p) { return p[0] | (uint16_t(p[1]) << 8); }
uint32_t read_u32(const uint8_t* p) { return p[0] | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24); }
uint64_t read_u64(const uint8_t* p) { return uint64_t(read_u32(p)) | (uint64_t(read_u32(p + 4)) << 32); }

constexpr size_t kFileHeaderSize = 4096;    // EVTX file header is 4KB
constexpr size_t kChunkSize = 65536;        // Each chunk is 64KB
constexpr size_t kChunkHeaderSize = 512;    // Chunk header
constexpr size_t kMaxEvents = 100000;

// Simple XML tag/attribute extraction
std::string xml_attr(const std::string& xml, const std::string& tag, const std::string& attr) {
    auto tag_pos = xml.find("<" + tag);
    if (tag_pos == std::string::npos) return "";
    auto attr_pos = xml.find(attr + "=\"", tag_pos);
    if (attr_pos == std::string::npos || attr_pos > xml.find(">", tag_pos) + 200) return "";
    auto start = attr_pos + attr.size() + 2;
    auto end = xml.find('"', start);
    if (end == std::string::npos) return "";
    return xml.substr(start, end - start);
}

std::string xml_inner(const std::string& xml, const std::string& tag) {
    auto open = xml.find("<" + tag);
    if (open == std::string::npos) return "";
    auto close_bracket = xml.find(">", open);
    if (close_bracket == std::string::npos) return "";
    // Check for self-closing tag
    if (xml[close_bracket - 1] == '/') return "";
    auto start = close_bracket + 1;
    auto end_tag = xml.find("</" + tag, start);
    if (end_tag == std::string::npos) return "";
    return xml.substr(start, end_tag - start);
}

// Extract all <Data Name="X">Y</Data> pairs
std::vector<std::pair<std::string, std::string>> extract_data_pairs(const std::string& xml) {
    std::vector<std::pair<std::string, std::string>> pairs;
    size_t pos = 0;
    while (pos < xml.size()) {
        auto data_pos = xml.find("<Data Name=\"", pos);
        if (data_pos == std::string::npos) break;
        auto name_start = data_pos + 12;
        auto name_end = xml.find('"', name_start);
        if (name_end == std::string::npos) break;
        std::string name = xml.substr(name_start, name_end - name_start);

        auto close = xml.find(">", name_end);
        if (close == std::string::npos) break;

        // Self-closing: <Data Name="X"/>
        if (xml[close - 1] == '/') {
            pairs.emplace_back(name, "");
            pos = close + 1;
            continue;
        }

        auto end_tag = xml.find("</Data>", close);
        if (end_tag == std::string::npos) break;
        std::string value = xml.substr(close + 1, end_tag - close - 1);
        pairs.emplace_back(name, value);
        pos = end_tag + 7;
    }
    return pairs;
}

std::string trim(const std::string& s) {
    auto start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    auto end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

}  // namespace

// ═════════════════════════════════════════════════════════════
// Windows FILETIME to ISO 8601
// ═════════════════════════════════════════════════════════════

std::string EvtxParser::filetime_to_iso(uint64_t ft) {
    if (ft == 0) return "";
    // FILETIME: 100ns intervals since 1601-01-01
    // Unix epoch: 1970-01-01 = 11644473600 seconds after 1601-01-01
    constexpr uint64_t kEpochDiff = 11644473600ULL;
    uint64_t secs = ft / 10000000ULL;
    if (secs <= kEpochDiff) return "";
    time_t unix_ts = static_cast<time_t>(secs - kEpochDiff);
    struct tm tm;
#ifdef _WIN32
    gmtime_s(&tm, &unix_ts);
#else
    gmtime_r(&unix_ts, &tm);
#endif
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buf;
}

// ═════════════════════════════════════════════════════════════
// Event ID Mapping (same as Shieldy)
// ═════════════════════════════════════════════════════════════

EvtxParser::EventIdInfo EvtxParser::map_event_id(int eid) {
    switch (eid) {
        // Authentication
        case 4624: return {"login_success", Severity::kInfo, "authentication"};
        case 4625: return {"login_failure", Severity::kHigh, "authentication"};
        case 4634: return {"logoff", Severity::kInfo, "authentication"};
        case 4647: return {"user_initiated_logoff", Severity::kInfo, "authentication"};
        case 4648: return {"explicit_credential_logon", Severity::kMedium, "authentication"};
        case 4672: return {"special_privileges_assigned", Severity::kMedium, "authentication"};
        case 4720: return {"user_account_created", Severity::kMedium, "authentication"};
        case 4722: return {"user_account_enabled", Severity::kLow, "authentication"};
        case 4724: return {"password_reset_attempt", Severity::kMedium, "authentication"};
        case 4725: return {"user_account_disabled", Severity::kMedium, "authentication"};
        case 4726: return {"user_account_deleted", Severity::kHigh, "authentication"};
        case 4732: return {"member_added_to_group", Severity::kMedium, "authentication"};
        case 4733: return {"member_removed_from_group", Severity::kMedium, "authentication"};
        case 4740: return {"account_locked_out", Severity::kHigh, "authentication"};
        // Process
        case 4688: return {"process_created", Severity::kInfo, "process"};
        case 4689: return {"process_terminated", Severity::kInfo, "process"};
        case 1:    return {"process_created", Severity::kInfo, "process"};      // Sysmon
        case 3:    return {"network_connection", Severity::kInfo, "network"};   // Sysmon
        case 11:   return {"file_created", Severity::kInfo, "file"};            // Sysmon
        case 22:   return {"dns_query", Severity::kInfo, "dns"};               // Sysmon
        // Object access
        case 4663: return {"object_access_attempt", Severity::kLow, "file"};
        case 4656: return {"handle_requested", Severity::kInfo, "file"};
        // Policy changes
        case 4719: return {"audit_policy_changed", Severity::kHigh, "system"};
        case 4713: return {"kerberos_policy_changed", Severity::kHigh, "system"};
        // Firewall
        case 5152: return {"packet_dropped", Severity::kLow, "firewall"};
        case 5156: return {"connection_allowed", Severity::kInfo, "firewall"};
        case 5157: return {"connection_blocked", Severity::kMedium, "firewall"};
        // System
        case 7045: return {"service_installed", Severity::kMedium, "system"};
        case 1102: return {"audit_log_cleared", Severity::kCritical, "system"};
        default:   return {"event", Severity::kInfo, "system"};
    }
}

// ═════════════════════════════════════════════════════════════
// Extract XML from BinXML record
// ═════════════════════════════════════════════════════════════

std::string EvtxParser::extract_xml_from_record(const uint8_t* data, size_t size) {
    // BinXML is a binary-encoded XML. Rather than fully parsing BinXML tokens,
    // we scan for UTF-16LE strings that form XML content.
    // This is a pragmatic approach — extract readable text from the binary.

    // First, try to find XML-like content by converting UTF-16LE to UTF-8
    std::string utf8;
    utf8.reserve(size);

    for (size_t i = 0; i + 1 < size; i += 2) {
        uint16_t ch = data[i] | (uint16_t(data[i + 1]) << 8);
        if (ch == 0) continue;
        if (ch < 128) {
            utf8 += static_cast<char>(ch);
        } else if (ch < 0x800) {
            utf8 += static_cast<char>(0xC0 | (ch >> 6));
            utf8 += static_cast<char>(0x80 | (ch & 0x3F));
        }
        // Skip higher codepoints
    }

    // Check if we got XML-like content
    if (utf8.find("<Event") != std::string::npos ||
        utf8.find("<System") != std::string::npos ||
        utf8.find("EventID") != std::string::npos) {
        return utf8;
    }

    // Fallback: try direct ASCII extraction
    std::string ascii;
    for (size_t i = 0; i < size; ++i) {
        char c = static_cast<char>(data[i]);
        if (c >= 32 && c <= 126) {
            ascii += c;
        } else if (c == '\n' || c == '\r' || c == '\t') {
            ascii += c;
        }
    }
    return ascii;
}

// ═════════════════════════════════════════════════════════════
// Parse XML Event → NormalizedEvent
// ═════════════════════════════════════════════════════════════

NormalizedEvent EvtxParser::parse_xml_event(const std::string& xml, const std::string& filename) {
    NormalizedEvent ev;
    ev.source = filename;

    // Extract EventID
    std::string eid_str = xml_inner(xml, "EventID");
    int event_id = 0;
    if (!eid_str.empty()) {
        try { event_id = std::stoi(trim(eid_str)); } catch (...) {}
    }

    // Extract timestamp
    std::string ts = xml_attr(xml, "TimeCreated", "SystemTime");

    // Extract computer
    std::string computer = xml_inner(xml, "Computer");

    // Extract channel
    std::string channel = xml_inner(xml, "Channel");

    // Extract provider
    std::string provider = xml_attr(xml, "Provider", "Name");

    // Map EventID
    auto info = map_event_id(event_id);
    ev.event_type = info.event_type;
    ev.severity = info.severity;

    // Store timestamp
    if (!ts.empty()) {
        ev.fields["_raw_timestamp"] = ts;
    }

    // Store metadata
    ev.fields["event_id"] = event_id;
    ev.fields["_host"] = computer;
    if (!channel.empty()) ev.fields["channel"] = channel;
    if (!provider.empty()) ev.fields["provider"] = provider;

    // Extract EventData pairs
    auto pairs = extract_data_pairs(xml);
    for (const auto& [name, value] : pairs) {
        if (!name.empty() && !value.empty()) {
            ev.fields[name] = value;
            // Map well-known fields to canonical metadata
            if (name == "TargetUserName" || name == "SubjectUserName") {
                if (ev.fields.find("_user") == ev.fields.end() || name == "TargetUserName") {
                    ev.fields["_user"] = value;
                }
            }
            if (name == "IpAddress" && value != "-" && value != "::1" && value != "127.0.0.1") {
                ev.fields["_src_ip"] = value;
            }
            if (name == "ProcessName" || name == "NewProcessName") {
                ev.fields["_process"] = value;
            }
            if (name == "CommandLine") {
                ev.fields["_command"] = value;
            }
            if (name == "WorkstationName" || name == "Workstation") {
                if (computer.empty()) ev.fields["_host"] = value;
            }
            if (name == "ParentProcessName") {
                ev.fields["_parent_process"] = value;
            }
        }
    }

    // Build message
    std::string msg = "EventID=" + std::to_string(event_id);
    auto user = ev.fields.find("_user");
    if (user != ev.fields.end() && user->is_string()) {
        msg += " | User=" + user->get<std::string>();
    }
    auto ip = ev.fields.find("_src_ip");
    if (ip != ev.fields.end() && ip->is_string()) {
        msg += " | IP=" + ip->get<std::string>();
    }
    auto proc = ev.fields.find("_process");
    if (proc != ev.fields.end() && proc->is_string()) {
        msg += " | Process=" + proc->get<std::string>();
    }
    if (!computer.empty()) {
        msg += " | Computer=" + computer;
    }
    ev.message = msg;

    // Store raw XML (truncated)
    ev.fields["_raw_xml"] = xml.substr(0, 500);

    return ev;
}

// ═════════════════════════════════════════════════════════════
// Main Parse Function
// ═════════════════════════════════════════════════════════════

std::vector<NormalizedEvent> EvtxParser::parse(const uint8_t* data, size_t size,
                                                const std::string& filename) {
    std::vector<NormalizedEvent> events;

    if (size < kFileHeaderSize) return events;

    // Verify file header magic
    if (std::memcmp(data, "ElfFile\0", 8) != 0) return events;

    // Iterate chunks (starting after 4KB file header)
    for (size_t chunk_offset = kFileHeaderSize;
         chunk_offset + kChunkSize <= size && events.size() < kMaxEvents;
         chunk_offset += kChunkSize) {

        const uint8_t* chunk = data + chunk_offset;

        // Verify chunk magic
        if (std::memcmp(chunk, "ElfChnk\0", 8) != 0) continue;

        // Scan for records within the chunk (after 512-byte chunk header)
        size_t pos = kChunkHeaderSize;
        while (pos + 24 < kChunkSize && events.size() < kMaxEvents) {
            const uint8_t* rec = chunk + pos;

            // Record magic: 0x00002a2a (little-endian)
            if (rec[0] != 0x2a || rec[1] != 0x2a || rec[2] != 0x00 || rec[3] != 0x00) {
                // No more records in this chunk
                break;
            }

            uint32_t rec_size = read_u32(rec + 4);
            if (rec_size < 24 || pos + rec_size > kChunkSize) break;

            uint64_t record_id = read_u64(rec + 8);
            uint64_t timestamp = read_u64(rec + 16);

            // The record payload starts at offset 24
            const uint8_t* payload = rec + 24;
            size_t payload_size = rec_size - 24;

            // Extract XML content from BinXML payload
            std::string xml = extract_xml_from_record(payload, payload_size);

            if (!xml.empty()) {
                auto ev = parse_xml_event(xml, filename);

                // Use record timestamp if XML didn't have one
                if (ev.fields.find("_raw_timestamp") == ev.fields.end() ||
                    !ev.fields["_raw_timestamp"].is_string() ||
                    ev.fields["_raw_timestamp"].get<std::string>().empty()) {
                    std::string ts = filetime_to_iso(timestamp);
                    if (!ts.empty()) {
                        ev.fields["_raw_timestamp"] = ts;
                    }
                }

                events.push_back(std::move(ev));
            }

            pos += rec_size;
        }
    }

    return events;
}

}  // namespace shieldtier
