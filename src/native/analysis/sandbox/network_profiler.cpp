#include "analysis/sandbox/network_profiler.h"

#include <algorithm>
#include <regex>
#include <set>

#include "common/json.h"

namespace shieldtier {

namespace {

const std::regex kUrlPattern(R"(https?://[^\s\"'<>]+)");
const std::regex kIpPattern(R"(\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b)");

const std::vector<std::string> kC2Ports = {
    ":4444", ":8443", ":1337", ":9999", ":443", ":8080", ":8888",
    ":1234", ":5555", ":6666", ":7777", ":31337",
};

const std::vector<std::string> kMalwareUserAgents = {
    "Mozilla/4.0 (compatible; MSIE 6.0;",
    "Mozilla/4.0 (compatible; MSIE 7.0;",
    "Mozilla/5.0 (Windows; U; MSIE",
    "WinHTTP",
    "AutoIt",
    "Python-urllib",
};

// Network-related import APIs that indicate raw socket, WinINet, WinHTTP, or direct download
const std::vector<std::pair<std::string, std::string>> kNetworkImports = {
    {"WSAStartup",          "Winsock initialization — raw network socket usage"},
    {"socket",              "Raw socket creation"},
    {"connect",             "Outbound socket connection"},
    {"send",                "Socket data transmission"},
    {"recv",                "Socket data reception"},
    {"InternetOpenA",       "WinINet HTTP client initialization"},
    {"InternetOpenW",       "WinINet HTTP client initialization"},
    {"InternetOpen",        "WinINet HTTP client initialization"},
    {"HttpSendRequestA",    "WinINet HTTP request"},
    {"HttpSendRequestW",    "WinINet HTTP request"},
    {"HttpSendRequest",     "WinINet HTTP request"},
    {"WinHttpOpen",         "WinHTTP client initialization"},
    {"URLDownloadToFileA",  "Direct file download to disk via URLMon"},
    {"URLDownloadToFileW",  "Direct file download to disk via URLMon"},
    {"URLDownloadToFile",   "Direct file download to disk via URLMon"},
};

bool is_private_ip(const std::string& ip) {
    return ip.find("10.") == 0 ||
           ip.find("127.") == 0 ||
           ip.find("192.168.") == 0 ||
           ip.find("172.16.") == 0 ||
           ip.find("172.17.") == 0 ||
           ip.find("172.18.") == 0 ||
           ip.find("172.19.") == 0 ||
           ip.find("172.20.") == 0 ||
           ip.find("172.21.") == 0 ||
           ip.find("172.22.") == 0 ||
           ip.find("172.23.") == 0 ||
           ip.find("172.24.") == 0 ||
           ip.find("172.25.") == 0 ||
           ip.find("172.26.") == 0 ||
           ip.find("172.27.") == 0 ||
           ip.find("172.28.") == 0 ||
           ip.find("172.29.") == 0 ||
           ip.find("172.30.") == 0 ||
           ip.find("172.31.") == 0 ||
           ip == "0.0.0.0";
}

}  // namespace

std::vector<Finding> NetworkProfiler::profile(
    const std::vector<std::string>& strings,
    const std::vector<std::string>& imports) {

    std::vector<Finding> findings;

    auto c2 = detect_c2_indicators(strings);
    findings.insert(findings.end(), c2.begin(), c2.end());

    auto net = detect_network_imports(imports);
    findings.insert(findings.end(), net.begin(), net.end());

    return findings;
}

std::vector<Finding> NetworkProfiler::detect_c2_indicators(
    const std::vector<std::string>& strings) {

    std::vector<Finding> findings;
    std::set<std::string> urls;
    std::set<std::string> public_ips;
    std::set<std::string> c2_port_hits;
    std::set<std::string> agent_hits;

    for (const auto& s : strings) {
        std::sregex_iterator url_begin(s.begin(), s.end(), kUrlPattern);
        std::sregex_iterator url_end;
        for (auto it = url_begin; it != url_end; ++it) {
            urls.insert(it->str());
        }

        std::sregex_iterator ip_begin(s.begin(), s.end(), kIpPattern);
        std::sregex_iterator ip_end;
        for (auto it = ip_begin; it != ip_end; ++it) {
            std::string ip = (*it)[1].str();
            if (!is_private_ip(ip)) {
                public_ips.insert(ip);
            }
        }

        for (const auto& port : kC2Ports) {
            if (s.find(port) != std::string::npos) {
                c2_port_hits.insert(port);
            }
        }

        for (const auto& ua : kMalwareUserAgents) {
            if (s.find(ua) != std::string::npos) {
                agent_hits.insert(ua);
            }
        }
    }

    if (!urls.empty()) {
        json url_list = json::array();
        for (const auto& u : urls) url_list.push_back(u);
        findings.push_back({
            "Embedded URLs detected",
            std::to_string(urls.size()) + " URL(s) found in binary strings",
            Severity::kMedium,
            AnalysisEngine::kSandbox,
            {{"urls", url_list}, {"count", urls.size()}},
        });
    }

    if (!public_ips.empty()) {
        json ip_list = json::array();
        for (const auto& ip : public_ips) ip_list.push_back(ip);
        findings.push_back({
            "Public IP addresses found",
            std::to_string(public_ips.size()) +
                " public IP address(es) — potential C2 or exfil endpoints",
            Severity::kHigh,
            AnalysisEngine::kSandbox,
            {{"ips", ip_list}, {"count", public_ips.size()}},
        });
    }

    if (!c2_port_hits.empty()) {
        json port_list = json::array();
        for (const auto& p : c2_port_hits) port_list.push_back(p);
        findings.push_back({
            "Suspicious C2 port references",
            "References to ports commonly associated with C2 frameworks",
            Severity::kHigh,
            AnalysisEngine::kSandbox,
            {{"ports", port_list}, {"count", c2_port_hits.size()}},
        });
    }

    if (!agent_hits.empty()) {
        json ua_list = json::array();
        for (const auto& ua : agent_hits) ua_list.push_back(ua);
        findings.push_back({
            "Known malware user-agent strings",
            "User-Agent strings associated with malware or automated tools",
            Severity::kHigh,
            AnalysisEngine::kSandbox,
            {{"user_agents", ua_list}},
        });
    }

    return findings;
}

std::vector<Finding> NetworkProfiler::detect_network_imports(
    const std::vector<std::string>& imports) {

    std::vector<Finding> findings;
    std::vector<std::pair<std::string, std::string>> matched;

    for (const auto& imp : imports) {
        for (const auto& [api, desc] : kNetworkImports) {
            if (imp == api) {
                matched.emplace_back(api, desc);
            }
        }
    }

    if (!matched.empty()) {
        json api_list = json::array();
        for (const auto& [api, desc] : matched) {
            api_list.push_back({{"api", api}, {"description", desc}});
        }

        Severity sev = matched.size() >= 3 ? Severity::kHigh : Severity::kMedium;

        findings.push_back({
            "Network communication imports",
            std::to_string(matched.size()) +
                " network API import(s) — binary has outbound communication capability",
            sev,
            AnalysisEngine::kSandbox,
            {{"apis", api_list}, {"count", matched.size()}},
        });
    }

    return findings;
}

}  // namespace shieldtier
