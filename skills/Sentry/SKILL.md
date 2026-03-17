---
name: Sentry
description: Use when building log analysis (13 converters + 6 engines), STIX/TAXII threat feed ingestion, and HAR/network capture via CEF CDP integration
---

# S7 — Sentry: Log Analysis, Threat Feed & Network Capture

## Overview

Port V1's log analysis subsystem (13 format converters, 6 analysis engines), STIX/TAXII threat feed ingestion, and network capture (HAR builder via CEF's native CDP access). Log analysis normalizes diverse log formats into a common schema for threat detection.

## Dependencies

- **Requires:** S0 (foundation), S1 (CEF shell for CDP capture access)
- **No blocking dependencies** on other analysis agents

## File Ownership

```
src/native/analysis/loganalysis/
  manager.cpp/.h       (log analysis orchestrator)
  detector.cpp/.h      (threat detection on normalized logs)
  normalizer.cpp/.h    (common log schema normalization)
  converters/
    csv.cpp/.h         (CSV log parser)
    json_log.cpp/.h    (JSON-structured logs)
    evtx.cpp/.h        (Windows Event Log)
    pcap.cpp/.h        (PCAP network capture)
    eml.cpp/.h         (email log format)
    xlsx.cpp/.h        (Excel spreadsheet logs)
    syslog.cpp/.h      (syslog format)
    cef_log.cpp/.h     (Common Event Format)
    leef.cpp/.h        (Log Event Extended Format)
    w3c.cpp/.h         (W3C Extended Log Format)
    apache.cpp/.h      (Apache access/error logs)
    nginx.cpp/.h       (Nginx access logs)
    custom.cpp/.h      (custom regex-based parser)
  engines/
    verdict.cpp/.h      (threat verdict engine)
    insights.cpp/.h     (pattern insight extraction)
    investigation.cpp/.h (investigation recommendation)
    triage.cpp/.h       (alert triage and prioritization)
    graph.cpp/.h        (relationship graph builder)
    hunting.cpp/.h      (threat hunting queries)

src/native/analysis/threatfeed/
  manager.cpp/.h       (threat feed orchestrator)
  stix.cpp/.h          (STIX 2.1 JSON parser)
  taxii.cpp/.h         (TAXII 2.1 client — discovery, collections, objects)
  indicator.cpp/.h     (indicator matching against log data)

src/native/capture/
  manager.cpp/.h       (capture session orchestrator)
  har_builder.cpp/.h   (HAR 1.2 format builder)
  session.cpp/.h       (CEF CDP session — Network domain events)
```

## Exit Criteria

EVTX/syslog/CSV → normalize → detect threats → findings. STIX/TAXII ingestion from threat intel feeds. HAR capture from live CEF browsing session via CDP.

---

## Log Normalizer (Common Schema)

```cpp
struct NormalizedEvent {
    std::string timestamp;      // ISO 8601
    std::string source;         // log source identifier
    std::string event_type;     // "authentication", "network", "process", "file", etc.
    std::string severity;       // "critical", "high", "medium", "low", "info"
    std::string message;        // human-readable description
    std::string source_ip;
    std::string dest_ip;
    int source_port = 0;
    int dest_port = 0;
    std::string username;
    std::string hostname;
    std::string process_name;
    int pid = 0;
    nlohmann::json raw;         // original event data
    nlohmann::json metadata;    // additional parsed fields
};

class LogNormalizer {
public:
    std::vector<NormalizedEvent> normalize(const FileBuffer& file,
                                           const std::string& format_hint = "") {
        auto format = format_hint.empty() ? detect_format(file) : format_hint;

        if (format == "evtx") return evtx_converter_.convert(file);
        if (format == "csv") return csv_converter_.convert(file);
        if (format == "json") return json_converter_.convert(file);
        if (format == "syslog") return syslog_converter_.convert(file);
        if (format == "pcap") return pcap_converter_.convert(file);
        if (format == "apache") return apache_converter_.convert(file);
        if (format == "nginx") return nginx_converter_.convert(file);
        if (format == "cef") return cef_converter_.convert(file);
        if (format == "leef") return leef_converter_.convert(file);
        if (format == "w3c") return w3c_converter_.convert(file);

        return custom_converter_.convert(file);
    }

private:
    std::string detect_format(const FileBuffer& file);
};
```

## EVTX Converter

```cpp
// Windows Event Log format: binary format with chunks and records
// Each record contains XML event data

struct EvtxHeader {
    char magic[8];       // "ElfFile\0"
    uint64_t first_chunk;
    uint64_t last_chunk;
    uint64_t next_record_id;
    uint32_t header_size; // 4096
    // ...
};

std::vector<NormalizedEvent> convert_evtx(const FileBuffer& file) {
    std::vector<NormalizedEvent> events;

    if (file.size() < sizeof(EvtxHeader)) return events;
    auto* header = reinterpret_cast<const EvtxHeader*>(file.data.data());
    if (memcmp(header->magic, "ElfFile\0", 8) != 0) return events;

    // Parse chunks (each 64KB)
    // Each chunk contains records with BinXML-encoded event data
    // Decode BinXML → extract EventID, TimeCreated, Computer, etc.
    // Map Windows EventIDs to normalized event types:
    //   4624/4625 → authentication (success/failure)
    //   4688      → process creation
    //   4663      → file access
    //   5156/5157 → network connection (allow/block)
    //   7045      → service installation

    return events;
}
```

## Threat Detection Engine

```cpp
class ThreatDetector {
public:
    std::vector<Finding> detect(const std::vector<NormalizedEvent>& events) {
        std::vector<Finding> findings;

        detect_brute_force(events, findings);
        detect_lateral_movement(events, findings);
        detect_privilege_escalation(events, findings);
        detect_data_exfiltration(events, findings);
        detect_suspicious_process(events, findings);

        return findings;
    }

private:
    void detect_brute_force(const std::vector<NormalizedEvent>& events,
                            std::vector<Finding>& findings) {
        // Count failed authentication per source IP in time windows
        std::map<std::string, int> failed_by_ip;
        for (auto& e : events) {
            if (e.event_type == "authentication" && e.severity == "high") {
                failed_by_ip[e.source_ip]++;
            }
        }
        for (auto& [ip, count] : failed_by_ip) {
            if (count >= 10) {
                findings.push_back({
                    "Brute Force Detected",
                    std::to_string(count) + " failed auth attempts from " + ip,
                    "high", "loganalysis",
                    {{"source_ip", ip}, {"attempts", count}, {"mitre", "T1110"}}
                });
            }
        }
    }

    void detect_lateral_movement(const std::vector<NormalizedEvent>& events,
                                  std::vector<Finding>& findings) {
        // Detect single source connecting to multiple internal destinations
        std::map<std::string, std::set<std::string>> connections;
        for (auto& e : events) {
            if (e.event_type == "network" && !e.source_ip.empty() && !e.dest_ip.empty()) {
                connections[e.source_ip].insert(e.dest_ip);
            }
        }
        for (auto& [src, dests] : connections) {
            if (dests.size() >= 5) {
                findings.push_back({
                    "Lateral Movement Suspected",
                    src + " connected to " + std::to_string(dests.size()) + " destinations",
                    "high", "loganalysis",
                    {{"source_ip", src}, {"dest_count", dests.size()}, {"mitre", "T1021"}}
                });
            }
        }
    }
};
```

## STIX/TAXII Client

```cpp
// TAXII 2.1 — RESTful API for threat intelligence sharing

class TaxiiClient {
    std::string server_url_;
    std::string api_key_;

public:
    // Discover API root and collections
    nlohmann::json discover() {
        auto resp = http::get(server_url_ + "/taxii2/",
            {{"Accept", "application/taxii+json;version=2.1"},
             {"Authorization", "Bearer " + api_key_}});
        return nlohmann::json::parse(resp.body);
    }

    // Get collection objects (STIX indicators)
    std::vector<StixIndicator> get_indicators(const std::string& collection_id,
                                               const std::string& added_after = "") {
        std::string url = server_url_ + "/collections/" + collection_id + "/objects/";
        if (!added_after.empty()) url += "?added_after=" + added_after;

        auto resp = http::get(url,
            {{"Accept", "application/stix+json;version=2.1"},
             {"Authorization", "Bearer " + api_key_}});

        auto bundle = nlohmann::json::parse(resp.body);
        std::vector<StixIndicator> indicators;

        for (auto& obj : bundle["objects"]) {
            if (obj["type"] == "indicator") {
                indicators.push_back({
                    obj["id"],
                    obj["name"],
                    obj["pattern"],      // STIX pattern: [file:hashes.SHA-256 = '...']
                    obj["valid_from"],
                    obj.value("valid_until", ""),
                    obj.value("confidence", 0)
                });
            }
        }
        return indicators;
    }
};

struct StixIndicator {
    std::string id;
    std::string name;
    std::string pattern;       // STIX pattern language
    std::string valid_from;
    std::string valid_until;
    int confidence;
};
```

## HAR Capture (CEF CDP)

```cpp
// Capture network traffic from CEF browsing session via Chrome DevTools Protocol
// CEF provides native CDP access — no need for external debugger

class HarBuilder {
    nlohmann::json har_;

public:
    HarBuilder() {
        har_ = {
            {"log", {
                {"version", "1.2"},
                {"creator", {{"name", "ShieldTier"}, {"version", "2.0"}}},
                {"entries", nlohmann::json::array()}
            }}
        };
    }

    void add_entry(const std::string& url,
                   const std::string& method,
                   int status,
                   const std::map<std::string, std::string>& request_headers,
                   const std::map<std::string, std::string>& response_headers,
                   const std::string& response_body,
                   double time_ms) {
        nlohmann::json entry = {
            {"startedDateTime", iso8601_now()},
            {"time", time_ms},
            {"request", {
                {"method", method},
                {"url", url},
                {"httpVersion", "HTTP/1.1"},
                {"headers", headers_to_json(request_headers)},
                {"queryString", nlohmann::json::array()},
                {"bodySize", 0}
            }},
            {"response", {
                {"status", status},
                {"statusText", status_text(status)},
                {"httpVersion", "HTTP/1.1"},
                {"headers", headers_to_json(response_headers)},
                {"content", {
                    {"size", response_body.size()},
                    {"mimeType", response_headers.count("Content-Type") ?
                        response_headers.at("Content-Type") : "text/html"},
                    {"text", response_body}
                }},
                {"bodySize", response_body.size()}
            }},
            {"timings", {{"send", 0}, {"wait", time_ms}, {"receive", 0}}}
        };
        har_["log"]["entries"].push_back(entry);
    }

    std::string to_json() const { return har_.dump(2); }
};
```

## CDP Session Integration

```cpp
// CEF provides CefBrowserHost::SendDevToolsMessage for CDP
// Use Network domain events to capture all requests/responses

void start_capture(CefRefPtr<CefBrowser> browser) {
    // Enable Network domain
    auto msg = CefProcessMessage::Create("DevToolsMessage");
    browser->GetHost()->SendDevToolsMessage(
        R"({"id":1,"method":"Network.enable"})");
}

// Handle CDP events in CefDevToolsMessageObserver:
// Network.requestWillBeSent  → record request
// Network.responseReceived   → record response headers
// Network.loadingFinished    → add to HAR
```

## Common Mistakes

| Mistake | Fix |
|---------|-----|
| Parsing EVTX as text | EVTX is binary format with BinXML — needs proper parser |
| Not paginating TAXII responses | Large collections use pagination — follow `next` links |
| Blocking on CDP capture | Network events are async — use observer pattern |
| Not normalizing timestamps | Different log formats use different timestamp formats — always normalize to ISO 8601 |
| Missing PCAP parser for encrypted traffic | PCAP with TLS shows only connection metadata, not content |
| Not deduplicating threat feed indicators | STIX objects can repeat across collections — deduplicate by ID |
