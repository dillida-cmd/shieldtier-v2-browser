#include "analysis/sandbox/cloud_sandbox.h"

#include <chrono>
#include <cstdio>
#include <random>

namespace shieldtier {

namespace {

std::string random_hex(size_t bytes) {
    static std::mt19937 rng(std::random_device{}());
    std::uniform_int_distribution<int> dist(0, 15);
    std::string result;
    result.reserve(bytes * 2);
    for (size_t i = 0; i < bytes * 2; ++i) {
        result += "0123456789abcdef"[dist(rng)];
    }
    return result;
}

}  // namespace

CloudSandboxManager::CloudSandboxManager(const CloudSandboxConfig& config)
    : config_(config) {}

void CloudSandboxManager::set_config(const CloudSandboxConfig& config) {
    std::lock_guard<std::mutex> lock(config_mutex_);
    config_ = config;
}

int64_t CloudSandboxManager::now_ms() const {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

std::string CloudSandboxManager::build_multipart(
    const std::string& boundary,
    const std::string& field_name,
    const std::string& filename,
    const uint8_t* data, size_t size,
    const std::vector<std::pair<std::string, std::string>>& extra_fields) {
    std::string body;

    // Extra text fields first
    for (const auto& [name, value] : extra_fields) {
        body += "--" + boundary + "\r\n";
        body += "Content-Disposition: form-data; name=\"" + name + "\"\r\n\r\n";
        body += value + "\r\n";
    }

    // File field
    body += "--" + boundary + "\r\n";
    body += "Content-Disposition: form-data; name=\"" + field_name +
            "\"; filename=\"" + filename + "\"\r\n";
    body += "Content-Type: application/octet-stream\r\n\r\n";
    body.append(reinterpret_cast<const char*>(data), size);
    body += "\r\n";

    body += "--" + boundary + "--\r\n";
    return body;
}

std::vector<CloudSandboxResult> CloudSandboxManager::submit(
    const FileBuffer& file) {
    std::vector<CloudSandboxResult> results;

    if (file.size() > kMaxUploadSize) {
        CloudSandboxResult err;
        err.provider = "all";
        err.status = "error";
        err.error = "File exceeds 32MB upload limit";
        err.timestamp = now_ms();
        results.push_back(err);
        return results;
    }

    if (!config_.virustotal_api_key.empty()) {
        auto r = submit_virustotal(file);
        if (r.ok()) results.push_back(r.value());
        else {
            CloudSandboxResult err;
            err.provider = "virustotal";
            err.status = "error";
            err.error = r.error().message;
            err.timestamp = now_ms();
            results.push_back(err);
        }
    }

    if (!config_.hybridanalysis_api_key.empty()) {
        auto r = submit_hybridanalysis(file);
        if (r.ok()) results.push_back(r.value());
        else {
            CloudSandboxResult err;
            err.provider = "hybridanalysis";
            err.status = "error";
            err.error = r.error().message;
            err.timestamp = now_ms();
            results.push_back(err);
        }
    }

    if (!config_.joesandbox_api_key.empty()) {
        auto r = submit_joesandbox(file);
        if (r.ok()) results.push_back(r.value());
        else {
            CloudSandboxResult err;
            err.provider = "joesandbox";
            err.status = "error";
            err.error = r.error().message;
            err.timestamp = now_ms();
            results.push_back(err);
        }
    }

    if (!config_.cuckoo_url.empty() && !config_.cuckoo_token.empty()) {
        auto r = submit_cuckoo(file);
        if (r.ok()) results.push_back(r.value());
        else {
            CloudSandboxResult err;
            err.provider = "cuckoo";
            err.status = "error";
            err.error = r.error().message;
            err.timestamp = now_ms();
            results.push_back(err);
        }
    }

    return results;
}

// ── VirusTotal ──────────────────────────────────────────

Result<CloudSandboxResult> CloudSandboxManager::submit_virustotal(
    const FileBuffer& file) {
    std::string boundary = "----ShieldTier" + random_hex(16);
    std::string body = build_multipart(boundary, "file", file.filename,
                                        file.ptr(), file.size());

    std::lock_guard<std::mutex> lock(http_mutex_);
    auto result = http_.post_raw(
        "https://www.virustotal.com/api/v3/files",
        body,
        {{"x-apikey", config_.virustotal_api_key},
         {"Content-Type", "multipart/form-data; boundary=" + boundary}});

    if (!result.ok()) return result.error();

    auto& resp = result.value();
    if (resp.status_code != 200) {
        return Error("VirusTotal upload failed: HTTP " +
                     std::to_string(resp.status_code));
    }

    auto data = json::parse(resp.body, nullptr, false);
    if (data.is_discarded()) {
        return Error("VirusTotal: invalid JSON response");
    }

    CloudSandboxResult sr;
    sr.provider = "virustotal";
    sr.status = "submitted";
    sr.submission_id = data.value("/data/id"_json_pointer, "");
    sr.report_url = data.value("/data/links/self"_json_pointer, "");
    sr.details = {{"analysisId", sr.submission_id}};
    sr.timestamp = now_ms();
    return sr;
}

Result<CloudSandboxResult> CloudSandboxManager::poll_virustotal(
    const std::string& analysis_id) {
    std::string url =
        "https://www.virustotal.com/api/v3/analyses/" + analysis_id;

    std::lock_guard<std::mutex> lock(http_mutex_);
    auto result = http_.get_json(
        url, {{"x-apikey", config_.virustotal_api_key}});

    if (!result.ok()) return result.error();
    auto& data = result.value();

    CloudSandboxResult sr;
    sr.provider = "virustotal";
    sr.submission_id = analysis_id;
    sr.timestamp = now_ms();

    std::string status = data.value("/data/attributes/status"_json_pointer, "queued");
    if (status != "completed") {
        sr.status = "analyzing";
        return sr;
    }

    sr.status = "complete";
    auto& stats = data["data"]["attributes"]["stats"];
    int malicious = stats.value("malicious", 0);
    int suspicious = stats.value("suspicious", 0);
    int harmless = stats.value("harmless", 0);
    int undetected = stats.value("undetected", 0);
    int total = malicious + suspicious + harmless + undetected;

    sr.score = total > 0 ? (malicious + suspicious) * 100 / total : 0;
    sr.verdict = malicious > 5 ? "malicious"
               : suspicious > 0 ? "suspicious" : "clean";
    sr.details = {
        {"malicious", malicious}, {"suspicious", suspicious},
        {"harmless", harmless}, {"undetected", undetected},
    };
    return sr;
}

// ── Hybrid Analysis ─────────────────────────────────────

Result<CloudSandboxResult> CloudSandboxManager::submit_hybridanalysis(
    const FileBuffer& file) {
    std::string boundary = "----ShieldTier" + random_hex(16);
    std::string body = build_multipart(
        boundary, "file", file.filename, file.ptr(), file.size(),
        {{"environment_id", "160"}});  // Windows 10 64-bit

    std::lock_guard<std::mutex> lock(http_mutex_);
    auto result = http_.post_raw(
        "https://www.hybrid-analysis.com/api/v2/submit/file",
        body,
        {{"api-key", config_.hybridanalysis_api_key},
         {"User-Agent", "ShieldTier/2.0"},
         {"Accept", "application/json"},
         {"Content-Type", "multipart/form-data; boundary=" + boundary}});

    if (!result.ok()) return result.error();
    auto& resp = result.value();
    if (resp.status_code != 200 && resp.status_code != 201) {
        return Error("HybridAnalysis upload failed: HTTP " +
                     std::to_string(resp.status_code));
    }

    auto data = json::parse(resp.body, nullptr, false);
    if (data.is_discarded()) return Error("HybridAnalysis: invalid JSON");

    CloudSandboxResult sr;
    sr.provider = "hybridanalysis";
    sr.status = "submitted";
    sr.submission_id = data.value("job_id", "");
    std::string sha256 = data.value("sha256", "");
    sr.report_url = "https://www.hybrid-analysis.com/sample/" + sha256;
    sr.details = {
        {"jobId", sr.submission_id},
        {"sha256", sha256},
    };
    sr.timestamp = now_ms();
    return sr;
}

Result<CloudSandboxResult> CloudSandboxManager::poll_hybridanalysis(
    const std::string& sha256) {
    std::string url =
        "https://www.hybrid-analysis.com/api/v2/report/" + sha256 + "/summary";

    std::lock_guard<std::mutex> lock(http_mutex_);
    auto result = http_.get_raw(
        url,
        {{"api-key", config_.hybridanalysis_api_key},
         {"User-Agent", "ShieldTier/2.0"},
         {"Accept", "application/json"}});

    if (!result.ok()) return result.error();
    auto& resp = result.value();

    CloudSandboxResult sr;
    sr.provider = "hybridanalysis";
    sr.submission_id = sha256;
    sr.timestamp = now_ms();

    if (resp.status_code == 404) {
        sr.status = "queued";
        return sr;
    }

    auto data = json::parse(resp.body, nullptr, false);
    if (data.is_discarded()) return Error("HybridAnalysis: invalid JSON");

    std::string state = data.value("state", "");
    std::string verdict = data.value("verdict", "");
    if (state != "SUCCESS" && verdict.empty()) {
        sr.status = "analyzing";
        return sr;
    }

    sr.status = "complete";
    int threat_score = data.value("threat_score", 0);
    sr.score = threat_score;
    sr.verdict = verdict.empty()
        ? (threat_score >= 70 ? "malicious"
           : threat_score >= 30 ? "suspicious" : "clean")
        : verdict;
    sr.report_url = "https://www.hybrid-analysis.com/sample/" + sha256;
    sr.details = {
        {"threatScore", threat_score},
        {"avDetect", data.value("av_detect", "")},
        {"vxFamily", data.value("vx_family", "")},
        {"verdict", verdict},
    };
    return sr;
}

// ── Joe Sandbox ─────────────────────────────────────────

Result<CloudSandboxResult> CloudSandboxManager::submit_joesandbox(
    const FileBuffer& file) {
    std::string boundary = "----ShieldTier" + random_hex(16);
    std::string body = build_multipart(
        boundary, "sample", file.filename, file.ptr(), file.size(),
        {{"apikey", config_.joesandbox_api_key}, {"accept-tac", "1"}});

    std::lock_guard<std::mutex> lock(http_mutex_);
    auto result = http_.post_raw(
        "https://jbxcloud.joesecurity.org/api/v2/submission/new",
        body,
        {{"Content-Type", "multipart/form-data; boundary=" + boundary}});

    if (!result.ok()) return result.error();
    auto& resp = result.value();
    if (resp.status_code != 200) {
        return Error("JoeSandbox upload failed: HTTP " +
                     std::to_string(resp.status_code));
    }

    auto data = json::parse(resp.body, nullptr, false);
    if (data.is_discarded()) return Error("JoeSandbox: invalid JSON");

    CloudSandboxResult sr;
    sr.provider = "joesandbox";
    sr.status = "submitted";
    sr.submission_id = data.value("/data/submission_id"_json_pointer, "");
    std::string web_id;
    if (data.contains("data") && data["data"].contains("webids") &&
        data["data"]["webids"].is_array() && !data["data"]["webids"].empty()) {
        web_id = data["data"]["webids"][0].get<std::string>();
    }
    sr.details = {
        {"submissionId", sr.submission_id},
        {"webId", web_id},
    };
    sr.timestamp = now_ms();
    return sr;
}

Result<CloudSandboxResult> CloudSandboxManager::poll_joesandbox(
    const std::string& web_id) {
    std::string boundary = "----ShieldTier" + random_hex(16);
    std::string body;
    body += "--" + boundary + "\r\n";
    body += "Content-Disposition: form-data; name=\"apikey\"\r\n\r\n";
    body += config_.joesandbox_api_key + "\r\n";
    body += "--" + boundary + "\r\n";
    body += "Content-Disposition: form-data; name=\"webid\"\r\n\r\n";
    body += web_id + "\r\n";
    body += "--" + boundary + "--\r\n";

    std::lock_guard<std::mutex> lock(http_mutex_);
    auto result = http_.post_raw(
        "https://jbxcloud.joesecurity.org/api/v2/analysis/info",
        body,
        {{"Content-Type", "multipart/form-data; boundary=" + boundary}});

    if (!result.ok()) return result.error();
    auto data = json::parse(result.value().body, nullptr, false);
    if (data.is_discarded()) return Error("JoeSandbox: invalid JSON");

    CloudSandboxResult sr;
    sr.provider = "joesandbox";
    sr.submission_id = web_id;
    sr.timestamp = now_ms();

    std::string status = data.value("/data/status"_json_pointer, "");
    if (status != "finished") {
        sr.status = "analyzing";
        return sr;
    }

    sr.status = "complete";
    std::string detection = data.value("/data/detection"_json_pointer, "");
    int score = data.value("/data/score"_json_pointer, 0);
    sr.score = score;
    sr.verdict = detection.empty()
        ? (score >= 70 ? "malicious" : score >= 30 ? "suspicious" : "clean")
        : detection;
    sr.report_url = data.value("/data/reporturl"_json_pointer, "");
    sr.details = {
        {"score", score},
        {"confidence", data.value("/data/confidence"_json_pointer, 0)},
        {"detection", detection},
    };
    return sr;
}

// ── Cuckoo Sandbox ──────────────────────────────────────

Result<CloudSandboxResult> CloudSandboxManager::submit_cuckoo(
    const FileBuffer& file) {
    std::string boundary = "----ShieldTier" + random_hex(16);
    std::string body = build_multipart(
        boundary, "file", file.filename, file.ptr(), file.size());

    std::string url = config_.cuckoo_url + "/tasks/create/file";

    std::lock_guard<std::mutex> lock(http_mutex_);
    auto result = http_.post_raw(
        url, body,
        {{"Authorization", "Bearer " + config_.cuckoo_token},
         {"Content-Type", "multipart/form-data; boundary=" + boundary}});

    if (!result.ok()) return result.error();
    auto& resp = result.value();
    if (resp.status_code != 200) {
        return Error("Cuckoo upload failed: HTTP " +
                     std::to_string(resp.status_code));
    }

    auto data = json::parse(resp.body, nullptr, false);
    if (data.is_discarded()) return Error("Cuckoo: invalid JSON");

    CloudSandboxResult sr;
    sr.provider = "cuckoo";
    sr.status = "submitted";

    // task_id can be at top level or in data
    if (data.contains("task_id")) {
        sr.submission_id = std::to_string(data["task_id"].get<int>());
    } else if (data.contains("data") && data["data"].contains("task_id")) {
        sr.submission_id = std::to_string(data["data"]["task_id"].get<int>());
    }
    sr.details = {{"taskId", sr.submission_id},
                  {"baseUrl", config_.cuckoo_url}};
    sr.timestamp = now_ms();
    return sr;
}

Result<CloudSandboxResult> CloudSandboxManager::poll_cuckoo(
    const std::string& task_id) {
    // Step 1: Check task status
    std::string status_url = config_.cuckoo_url + "/tasks/view/" + task_id;

    std::lock_guard<std::mutex> lock(http_mutex_);
    auto status_result = http_.get_raw(
        status_url,
        {{"Authorization", "Bearer " + config_.cuckoo_token}});

    if (!status_result.ok()) return status_result.error();

    auto status_data = json::parse(status_result.value().body, nullptr, false);
    if (status_data.is_discarded()) return Error("Cuckoo: invalid status JSON");

    std::string task_status =
        status_data.value("/data/task/status"_json_pointer, "pending");

    CloudSandboxResult sr;
    sr.provider = "cuckoo";
    sr.submission_id = task_id;
    sr.timestamp = now_ms();

    if (task_status != "reported") {
        sr.status = "analyzing";
        return sr;
    }

    // Step 2: Fetch report
    std::string report_url = config_.cuckoo_url + "/tasks/report/" + task_id;
    auto report_result = http_.get_raw(
        report_url,
        {{"Authorization", "Bearer " + config_.cuckoo_token}});

    if (!report_result.ok()) return report_result.error();

    auto report_data = json::parse(report_result.value().body, nullptr, false);
    if (report_data.is_discarded()) return Error("Cuckoo: invalid report JSON");

    sr.status = "complete";

    // Cuckoo scores 0-10, normalize to 0-100
    double raw_score = report_data.value("/info/score"_json_pointer, 0.0);
    sr.score = static_cast<int>(std::min(raw_score, 10.0) * 10);
    sr.verdict = raw_score >= 7 ? "malicious"
               : raw_score >= 4 ? "suspicious" : "clean";

    // Extract key details
    json signatures = json::array();
    if (report_data.contains("signatures") && report_data["signatures"].is_array()) {
        int count = 0;
        for (const auto& sig : report_data["signatures"]) {
            if (count++ >= 10) break;
            signatures.push_back({
                {"name", sig.value("name", "")},
                {"severity", sig.value("severity", 0)},
                {"description", sig.value("description", "")},
            });
        }
    }

    sr.details = {
        {"score", sr.score},
        {"rawScore", raw_score},
        {"signatures", signatures},
    };

    if (report_data.contains("info")) {
        auto& info = report_data["info"];
        if (info.contains("duration")) {
            sr.details["duration"] = std::to_string(info["duration"].get<int>()) + "s";
        }
        if (info.contains("machine") && info["machine"].contains("name")) {
            sr.details["machine"] = info["machine"]["name"];
        }
    }

    return sr;
}

CloudSandboxResult CloudSandboxManager::poll(
    const std::string& provider,
    const std::string& submission_id,
    const std::string& sha256) {
    Result<CloudSandboxResult> result = Error("Unknown provider: " + provider);

    if (provider == "virustotal") {
        result = poll_virustotal(submission_id);
    } else if (provider == "hybridanalysis") {
        result = poll_hybridanalysis(sha256.empty() ? submission_id : sha256);
    } else if (provider == "joesandbox") {
        result = poll_joesandbox(submission_id);
    } else if (provider == "cuckoo") {
        result = poll_cuckoo(submission_id);
    }

    if (result.ok()) return result.value();

    CloudSandboxResult err;
    err.provider = provider;
    err.status = "error";
    err.error = result.error().message;
    err.timestamp = now_ms();
    return err;
}

}  // namespace shieldtier
