#include "cloud/cloud_client.h"

#include "analysis/enrichment/http_client.h"

namespace shieldtier {

CloudClient::CloudClient(const CloudConfig& config) : config_(config) {
    http_ = std::make_unique<HttpClient>();
    http_->set_timeout(config_.timeout_seconds);
    http_->set_user_agent("ShieldTier/2.0");
}

CloudClient::~CloudClient() = default;

Result<CloudAnalysisResponse> CloudClient::analyze(
    const CloudAnalysisRequest& request) {
    if (!is_configured()) {
        return Error("API key not configured", "auth_missing");
    }

    json payload = {
        {"sha256", request.sha256},
        {"file_type", request.file_type},
        {"file_size", request.file_size},
        {"yara_matches", request.yara_matches},
        {"pe_features", request.pe_features},
        {"behavior_features", request.behavior_features},
        {"network_features", request.network_features},
        {"script_features", request.script_features},
        {"local_threat_score", request.local_threat_score},
    };

    auto result = http_->post_json(
        config_.api_base_url + "/analyze", payload, auth_headers());
    if (!result.ok()) {
        return Error("Cloud analysis request failed: " + result.error().message,
                     "cloud_request_failed");
    }

    const auto& body = result.value();

    CloudAnalysisResponse response{};
    response.success = body.value("success", false);
    if (!response.success) {
        std::string msg = body.value("error", "unknown cloud error");
        return Error(msg, "cloud_analysis_failed");
    }

    response.verdict = body.value("verdict", Verdict::kUnknown);
    response.confidence = body.value("confidence", 0.0);
    response.cloud_threat_score = body.value("cloud_threat_score", 0);
    response.threat_intel = body.value("threat_intel", json::object());
    response.ml_scores = body.value("ml_scores", json::object());

    if (body.contains("mitre_techniques") && body["mitre_techniques"].is_array()) {
        for (const auto& t : body["mitre_techniques"]) {
            if (t.is_string()) {
                response.mitre_techniques.push_back(t.get<std::string>());
            }
        }
    }

    if (body.contains("additional_findings") &&
        body["additional_findings"].is_array()) {
        for (const auto& f : body["additional_findings"]) {
            Finding finding;
            finding.title = f.value("title", "");
            finding.description = f.value("description", "");
            finding.severity = f.value("severity", Severity::kInfo);
            finding.engine = f.value("engine", AnalysisEngine::kScoring);
            finding.metadata = f.value("metadata", json::object());
            response.additional_findings.push_back(std::move(finding));
        }
    }

    return response;
}

Result<bool> CloudClient::health_check() {
    auto result = http_->get(config_.api_base_url + "/health");
    if (!result.ok()) {
        return Error("Health check failed: " + result.error().message,
                     "health_check_failed");
    }
    return result.value().status_code == 200;
}

Result<json> CloudClient::get_threat_intel(const std::string& ioc_type,
                                           const std::string& ioc_value) {
    if (!is_configured()) {
        return Error("API key not configured", "auth_missing");
    }

    std::string url =
        config_.api_base_url + "/intel/" + ioc_type + "/" + ioc_value;
    auto result = http_->get_json(url, auth_headers());
    if (!result.ok()) {
        return Error("Threat intel lookup failed: " + result.error().message,
                     "intel_lookup_failed");
    }
    return result.value();
}

Result<bool> CloudClient::submit_verdict(const std::string& sha256,
                                         const ThreatVerdict& verdict) {
    if (!is_configured()) {
        return Error("API key not configured", "auth_missing");
    }

    json payload = {
        {"sha256", sha256},
        {"verdict", verdict},
    };

    auto result = http_->post_json(
        config_.api_base_url + "/verdicts", payload, auth_headers());
    if (!result.ok()) {
        return Error("Verdict submission failed: " + result.error().message,
                     "verdict_submit_failed");
    }
    return result.value().value("accepted", false);
}

void CloudClient::set_api_key(const std::string& key) {
    config_.api_key = key;
}

bool CloudClient::is_configured() const {
    return !config_.api_key.empty();
}

std::unordered_map<std::string, std::string> CloudClient::auth_headers() const {
    return {
        {"Authorization", "Bearer " + config_.api_key},
        {"Content-Type", "application/json"},
    };
}

}  // namespace shieldtier
