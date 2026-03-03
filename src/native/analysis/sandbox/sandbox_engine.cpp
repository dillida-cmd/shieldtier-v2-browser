#include "analysis/sandbox/sandbox_engine.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>

#include "analysis/fileanalysis/file_analyzer.h"
#include "analysis/sandbox/behavior_signatures.h"
#include "analysis/sandbox/network_profiler.h"

namespace shieldtier {

namespace {

// Shannon entropy over a byte range
double section_entropy(const uint8_t* data, size_t size) {
    if (size == 0) return 0.0;

    std::array<uint64_t, 256> freq{};
    for (size_t i = 0; i < size; ++i) {
        freq[data[i]]++;
    }

    double entropy = 0.0;
    double log2 = std::log(2.0);
    for (auto count : freq) {
        if (count == 0) continue;
        double p = static_cast<double>(count) / static_cast<double>(size);
        entropy -= p * (std::log(p) / log2);
    }
    return entropy;
}

}  // namespace

SandboxEngine::SandboxEngine() = default;

Result<AnalysisEngineResult> SandboxEngine::analyze(const FileBuffer& file) {
    auto start = std::chrono::steady_clock::now();

    auto strings = FileAnalyzer::extract_strings(file.ptr(), file.size(), 4, 5000);

    std::vector<BehaviorEvent> events;

    auto import_events = analyze_import_behavior(strings);
    events.insert(events.end(), import_events.begin(), import_events.end());

    auto string_events = analyze_string_behavior(strings);
    events.insert(events.end(), string_events.begin(), string_events.end());

    auto resource_events = analyze_resource_behavior(file);
    events.insert(events.end(), resource_events.begin(), resource_events.end());

    // Network profiling
    NetworkProfiler profiler;
    auto net_findings = profiler.profile(strings, {});

    auto findings = events_to_findings(events);
    findings.insert(findings.end(), net_findings.begin(), net_findings.end());

    auto end = std::chrono::steady_clock::now();
    double duration_ms =
        std::chrono::duration<double, std::milli>(end - start).count();

    AnalysisEngineResult result;
    result.engine = AnalysisEngine::kSandbox;
    result.success = true;
    result.findings = std::move(findings);
    result.duration_ms = duration_ms;
    result.raw_output = {
        {"total_events", events.size()},
        {"import_matches", import_events.size()},
        {"string_matches", string_events.size()},
        {"resource_anomalies", resource_events.size()},
        {"strings_extracted", strings.size()},
        {"file_size", file.size()},
        {"filename", file.filename},
    };

    return result;
}

std::vector<BehaviorEvent> SandboxEngine::analyze_import_behavior(
    const std::vector<std::string>& strings) {

    BehaviorSignatures sigs;
    std::vector<BehaviorEvent> events;

    for (const auto& pattern : sigs.import_patterns()) {
        bool all_found = true;
        std::vector<std::string> matched_apis;

        for (const auto& api : pattern.required_apis) {
            bool found = false;
            for (const auto& s : strings) {
                if (s == api) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                all_found = false;
                break;
            }
            matched_apis.push_back(api);
        }

        if (all_found) {
            json api_list = json::array();
            for (const auto& a : matched_apis) api_list.push_back(a);

            events.push_back({
                "import_match",
                pattern.description,
                {
                    {"pattern_name", pattern.name},
                    {"mitre_id", pattern.mitre_id},
                    {"matched_apis", api_list},
                },
                pattern.severity,
            });
        }
    }

    return events;
}

std::vector<BehaviorEvent> SandboxEngine::analyze_string_behavior(
    const std::vector<std::string>& strings) {

    BehaviorSignatures sigs;
    std::vector<BehaviorEvent> events;

    for (const auto& pattern : sigs.string_patterns()) {
        for (const auto& s : strings) {
            if (s.find(pattern.pattern) != std::string::npos) {
                events.push_back({
                    "string_match",
                    pattern.description,
                    {
                        {"pattern_name", pattern.name},
                        {"mitre_id", pattern.mitre_id},
                        {"matched_string", s.substr(0, 200)},
                    },
                    pattern.severity,
                });
                break;
            }
        }
    }

    return events;
}

std::vector<BehaviorEvent> SandboxEngine::analyze_resource_behavior(
    const FileBuffer& file) {

    std::vector<BehaviorEvent> events;
    const uint8_t* data = file.ptr();
    size_t size = file.size();

    if (size < 64) return events;

    // Scan for embedded PE files (MZ header followed by PE\0\0 at the e_lfanew offset)
    // Skip the first MZ at offset 0 — that's the file itself
    for (size_t i = 1; i + 4 < size; ++i) {
        if (data[i] == 'M' && data[i + 1] == 'Z') {
            // Check for PE signature at the offset stored at e_lfanew (offset 0x3C from MZ)
            if (i + 0x3C + 4 <= size) {
                uint32_t pe_offset = *reinterpret_cast<const uint32_t*>(data + i + 0x3C);
                if (pe_offset < 0x1000 && i + pe_offset + 4 <= size) {
                    if (data[i + pe_offset] == 'P' &&
                        data[i + pe_offset + 1] == 'E' &&
                        data[i + pe_offset + 2] == 0 &&
                        data[i + pe_offset + 3] == 0) {
                        events.push_back({
                            "resource_anomaly",
                            "Embedded PE executable found inside binary",
                            {
                                {"type", "embedded_pe"},
                                {"offset", i},
                            },
                            Severity::kHigh,
                        });
                        break;
                    }
                }
            }
        }
    }

    // Check for abnormally large non-code data regions and high-entropy sections
    // Divide file into 256KB chunks and analyze each
    constexpr size_t kChunkSize = 256 * 1024;
    size_t chunk_count = 0;
    size_t high_entropy_chunks = 0;

    for (size_t offset = 0; offset < size; offset += kChunkSize) {
        size_t chunk_len = std::min(kChunkSize, size - offset);
        double entropy = section_entropy(data + offset, chunk_len);
        chunk_count++;

        if (entropy > 7.0) {
            high_entropy_chunks++;
        }
    }

    if (high_entropy_chunks > 0) {
        double pct = 100.0 * static_cast<double>(high_entropy_chunks) /
                     static_cast<double>(chunk_count);
        events.push_back({
            "resource_anomaly",
            "High entropy sections detected — likely encrypted or packed content",
            {
                {"type", "high_entropy"},
                {"high_entropy_chunks", high_entropy_chunks},
                {"total_chunks", chunk_count},
                {"percentage", pct},
            },
            Severity::kMedium,
        });
    }

    // Flag files >1MB with the majority of data being high entropy (>50% chunks)
    if (size > 1024 * 1024 && high_entropy_chunks > chunk_count / 2) {
        events.push_back({
            "resource_anomaly",
            "Large binary with majority high-entropy content — strongly suggests packing or encryption",
            {
                {"type", "packed_binary"},
                {"file_size", size},
                {"high_entropy_ratio", static_cast<double>(high_entropy_chunks) /
                                       static_cast<double>(chunk_count)},
            },
            Severity::kHigh,
        });
    }

    return events;
}

std::vector<Finding> SandboxEngine::events_to_findings(
    const std::vector<BehaviorEvent>& events) {

    std::vector<Finding> findings;
    findings.reserve(events.size());

    for (const auto& event : events) {
        std::string title;
        if (event.type == "import_match") {
            std::string mitre = event.metadata.value("mitre_id", "");
            std::string name = event.metadata.value("pattern_name", "");
            title = "Behavioral: " + name;
            if (!mitre.empty()) title += " [" + mitre + "]";
        } else if (event.type == "string_match") {
            std::string mitre = event.metadata.value("mitre_id", "");
            std::string name = event.metadata.value("pattern_name", "");
            title = "String indicator: " + name;
            if (!mitre.empty()) title += " [" + mitre + "]";
        } else if (event.type == "resource_anomaly") {
            std::string anomaly_type = event.metadata.value("type", "unknown");
            title = "Resource anomaly: " + anomaly_type;
        } else {
            title = "Sandbox: " + event.type;
        }

        findings.push_back({
            title,
            event.detail,
            event.severity,
            AnalysisEngine::kSandbox,
            event.metadata,
        });
    }

    return findings;
}

}  // namespace shieldtier
