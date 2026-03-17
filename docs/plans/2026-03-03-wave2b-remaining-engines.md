# Wave 2b — Remaining Analysis Engines + Infrastructure

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task.

**Goal:** Build the remaining analysis engines (behavioral sandbox, advanced detection, email/content analysis, log analysis, capture, threat feed), infrastructure services (config, auth, chat, export, network policy), and the VM sandbox orchestration layer.

**Architecture:** All modules produce `AnalysisEngineResult` or `Finding` via `common/types.h`. Each module is a standalone C++ class with clean interfaces. The `ScoringEngine` from Wave 2a already handles weighted aggregation — Wave 2b engines just need to produce results in the same format.

**Tech Stack:** C++20, libsodium (chat crypto), wabt (WASM inspection), libarchive (archive handling), nlohmann_json

**Depends on:** Wave 2a (types, result, IPC, scoring, YARA, file analysis, enrichment)

---

## Execution Order

```
Tasks 1-3 (Vault)    ─┐
Tasks 4-5 (Havoc)    ─├── all independent of each other
Tasks 6-7 (Sentry-A) ─┘
         │
         ▼
Task 8 (Sentry-B: Capture) ← depends on CEF session access
         │
         ▼
Tasks 9-11 (Phantom) ← depends on nothing, but is largest
         │
         ▼
Task 12 (CMake integration + wiring)
```

---

### Task 1: Vault — Config Store + Auth + Network Policy

**Codename:** Vault-Core

**Files:**
- Create: `src/native/config/config_store.h`
- Create: `src/native/config/config_store.cpp`
- Create: `src/native/auth/auth_manager.h`
- Create: `src/native/auth/auth_manager.cpp`
- Create: `src/native/network/network_policy.h`
- Create: `src/native/network/network_policy.cpp`

**ConfigStore (`config_store.h`):**

```cpp
#pragma once

#include <mutex>
#include <string>
#include "common/json.h"
#include "common/result.h"

namespace shieldtier {

class ConfigStore {
public:
    explicit ConfigStore(const std::string& config_path);

    Result<json> load();
    Result<bool> save();

    json get(const std::string& key, const json& default_val = nullptr) const;
    void set(const std::string& key, const json& value);
    bool has(const std::string& key) const;
    void remove(const std::string& key);

    // Bulk get/set for UI settings panels
    json get_all() const;
    void merge(const json& overrides);

private:
    Result<bool> write_atomic(const std::string& path, const std::string& data);

    std::string config_path_;
    json config_;
    mutable std::mutex mutex_;
};

}  // namespace shieldtier
```

**Key behavior:**
- `load()`: Reads JSON file from disk, validates, stores in memory. Returns error if parse fails.
- `save()`: Atomic write via temp file + rename (POSIX `rename()` is atomic on same filesystem).
- Thread-safe: all accessors lock `mutex_`.
- No encryption yet (Wave 3 Aegis adds encrypted config).

**AuthManager (`auth_manager.h`):**

```cpp
#pragma once

#include <string>
#include "common/json.h"
#include "common/result.h"

namespace shieldtier {

enum class AuthTier { kFree, kPro, kTeam, kEnterprise };

struct AuthToken {
    std::string token;
    std::string user_id;
    AuthTier tier;
    int64_t expires_at;  // Unix timestamp
    bool is_expired() const;
};

class AuthManager {
public:
    AuthManager();

    Result<AuthToken> validate_token(const std::string& jwt);
    AuthTier current_tier() const;
    bool is_authenticated() const;
    void set_token(const AuthToken& token);
    void clear_token();

    // Feature gating
    bool has_feature(const std::string& feature) const;

private:
    Result<json> decode_jwt_payload(const std::string& jwt);
    static AuthTier tier_from_string(const std::string& s);

    AuthToken current_token_;
    mutable std::mutex mutex_;
};

}  // namespace shieldtier
```

**Key behavior:**
- `validate_token()`: Decodes JWT payload (base64url), extracts tier/expiry/user_id. Does NOT verify signature (server-side verification — client just reads claims).
- `has_feature()`: Maps tier to feature set. Free: basic analysis. Pro: +YARA premium +sandbox +email. Team: +collaboration. Enterprise: +server-side scoring.

**NetworkPolicy (`network_policy.h`):**

```cpp
#pragma once

#include <mutex>
#include <string>
#include <vector>
#include "common/result.h"

namespace shieldtier {

struct PolicyRule {
    std::string pattern;   // glob or regex
    bool allow;            // true = whitelist, false = blacklist
    std::string category;  // "malware", "ads", "tracking", etc.
};

class NetworkPolicy {
public:
    NetworkPolicy();

    bool should_allow(const std::string& url) const;
    void add_rule(const PolicyRule& rule);
    void remove_rule(const std::string& pattern);
    void load_defaults();

    std::vector<PolicyRule> get_rules() const;

private:
    std::vector<PolicyRule> rules_;
    mutable std::mutex mutex_;
};

}  // namespace shieldtier
```

**Key behavior:**
- `should_allow()`: Iterates rules in order, first match wins. Default: allow all.
- `load_defaults()`: Adds basic rules to block known malware C2 domains, tracking pixels.
- Integrated with `RequestHandler::OnBeforeResourceLoad()` in CEF (wiring in Task 12).

**Commit:** `feat(vault): add config store, auth manager, network policy`

---

### Task 2: Vault — Export Engine

**Codename:** Vault-Export

**Files:**
- Create: `src/native/export/export_manager.h`
- Create: `src/native/export/export_manager.cpp`
- Create: `src/native/export/defang.h`
- Create: `src/native/export/defang.cpp`

**ExportManager (`export_manager.h`):**

```cpp
#pragma once

#include <string>
#include <vector>
#include "common/types.h"
#include "common/result.h"

namespace shieldtier {

enum class ExportFormat { kJson, kHtml, kZip };

class ExportManager {
public:
    ExportManager();

    Result<std::string> export_json(const ThreatVerdict& verdict,
                                     const std::string& filename);
    Result<std::string> export_html(const ThreatVerdict& verdict,
                                     const std::string& filename);
    Result<std::string> export_zip(const ThreatVerdict& verdict,
                                    const std::string& filename,
                                    const std::string& output_dir);

    void set_template_dir(const std::string& dir);

private:
    std::string generate_html(const ThreatVerdict& verdict,
                               const std::string& filename);
    std::string severity_color(Severity sev);

    std::string template_dir_;
};

}  // namespace shieldtier
```

**Key behavior:**
- `export_json()`: Serialize ThreatVerdict to pretty-printed JSON string. All URLs/IPs/hashes defanged.
- `export_html()`: Generate self-contained HTML report with inline CSS. Shows verdict, threat score, findings table, MITRE techniques. No external dependencies.
- `export_zip()`: Writes JSON + HTML to a ZIP archive using libarchive.
- All exported strings pass through `Defang::defang()`.

**Defang (`defang.h`):**

```cpp
#pragma once
#include <string>

namespace shieldtier {

class Defang {
public:
    static std::string defang_url(const std::string& url);
    static std::string defang_ip(const std::string& ip);
    static std::string defang_email(const std::string& email);
    static std::string defang_all(const std::string& text);
};

}  // namespace shieldtier
```

**Key behavior:**
- `defang_url()`: `http://` → `hxxp://`, `https://` → `hxxps://`, `.` → `[.]` in domain portion.
- `defang_ip()`: `192.168.1.1` → `192[.]168[.]1[.]1`
- `defang_email()`: `user@domain.com` → `user[@]domain[.]com`
- `defang_all()`: Applies all defanging to arbitrary text (regex-based detection).

**Commit:** `feat(vault): add export manager — JSON/HTML/ZIP reports with defanging`

---

### Task 3: Vault — ShieldCrypt Chat

**Codename:** Vault-Chat

**Files:**
- Create: `src/native/chat/chat_manager.h`
- Create: `src/native/chat/chat_manager.cpp`
- Create: `src/native/chat/shieldcrypt.h`
- Create: `src/native/chat/shieldcrypt.cpp`

**ShieldCrypt (`shieldcrypt.h`):**

```cpp
#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include "common/result.h"

namespace shieldtier {

struct KeyPair {
    std::vector<uint8_t> public_key;   // 32 bytes (X25519)
    std::vector<uint8_t> secret_key;   // 32 bytes (X25519)
};

struct EncryptedMessage {
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> nonce;        // 24 bytes (XSalsa20-Poly1305)
    std::vector<uint8_t> sender_pubkey;
};

class ShieldCrypt {
public:
    static Result<bool> initialize();

    static Result<KeyPair> generate_keypair();
    static Result<EncryptedMessage> encrypt(
        const std::string& plaintext,
        const std::vector<uint8_t>& recipient_pubkey,
        const std::vector<uint8_t>& sender_secretkey);
    static Result<std::string> decrypt(
        const EncryptedMessage& message,
        const std::vector<uint8_t>& recipient_secretkey);

    static std::string encode_base64(const std::vector<uint8_t>& data);
    static Result<std::vector<uint8_t>> decode_base64(const std::string& b64);
};

}  // namespace shieldtier
```

**Key behavior:**
- Uses libsodium: `crypto_box_keypair()`, `crypto_box_easy()`, `crypto_box_open_easy()`.
- `initialize()`: Calls `sodium_init()`. Thread-safe (sodium_init is re-entrant).
- Base64 uses `sodium_bin2base64()` / `sodium_base642bin()`.

**ChatManager (`chat_manager.h`):**

```cpp
#pragma once

#include <mutex>
#include <string>
#include <vector>
#include "chat/shieldcrypt.h"
#include "common/json.h"
#include "common/result.h"

namespace shieldtier {

struct ChatMessage {
    std::string id;
    std::string sender_id;
    std::string content;      // plaintext (decrypted)
    int64_t timestamp;
    bool is_encrypted;
};

class ChatManager {
public:
    explicit ChatManager(const std::string& storage_path);

    Result<bool> initialize_keys();
    std::vector<uint8_t> get_public_key() const;

    Result<EncryptedMessage> send_message(
        const std::string& plaintext,
        const std::vector<uint8_t>& recipient_pubkey);

    Result<ChatMessage> receive_message(
        const EncryptedMessage& encrypted,
        const std::string& sender_id);

    std::vector<ChatMessage> get_history(int limit = 100) const;
    void clear_history();

private:
    KeyPair keypair_;
    std::vector<ChatMessage> history_;
    std::string storage_path_;
    mutable std::mutex mutex_;
};

}  // namespace shieldtier
```

**Commit:** `feat(vault): add ShieldCrypt E2E chat — libsodium X25519 + XSalsa20-Poly1305`

---

### Task 4: Havoc — Inline Behavioral Sandbox

**Codename:** Havoc-Sandbox

**Files:**
- Create: `src/native/analysis/sandbox/sandbox_engine.h`
- Create: `src/native/analysis/sandbox/sandbox_engine.cpp`
- Create: `src/native/analysis/sandbox/behavior_signatures.h`
- Create: `src/native/analysis/sandbox/behavior_signatures.cpp`
- Create: `src/native/analysis/sandbox/network_profiler.h`
- Create: `src/native/analysis/sandbox/network_profiler.cpp`

**SandboxEngine (`sandbox_engine.h`):**

```cpp
#pragma once

#include <string>
#include <vector>
#include "common/types.h"
#include "common/result.h"

namespace shieldtier {

struct BehaviorEvent {
    std::string type;       // "file_write", "registry_mod", "process_create", "network_connect", "api_call"
    std::string detail;     // human-readable description
    json metadata;          // structured data
    int64_t timestamp_ms;
    Severity severity;
};

class SandboxEngine {
public:
    SandboxEngine();

    // Analyze a file buffer for behavioral indicators (static behavioral analysis).
    // This is the inline sandbox — no VM needed. Analyzes imports, strings,
    // embedded resources, and code patterns to predict behavior.
    Result<AnalysisEngineResult> analyze(const FileBuffer& file);

private:
    std::vector<BehaviorEvent> analyze_import_behavior(const FileBuffer& file);
    std::vector<BehaviorEvent> analyze_string_behavior(const FileBuffer& file);
    std::vector<BehaviorEvent> analyze_resource_behavior(const FileBuffer& file);
    std::vector<Finding> events_to_findings(const std::vector<BehaviorEvent>& events);
};

}  // namespace shieldtier
```

**Key behavior:**
- This is a STATIC behavioral analyzer (no actual execution). It predicts behavior from imports, strings, embedded resources.
- `analyze_import_behavior()`: Detects API call patterns indicating: process injection, keylogging, screen capture, persistence, privilege escalation, anti-debug, network exfiltration.
- `analyze_string_behavior()`: Searches for suspicious strings: registry keys (Run, RunOnce), PowerShell commands, cmd.exe invocations, scheduled task creation, service installation.
- `analyze_resource_behavior()`: Checks for embedded PE files, scripts in resources, abnormal resource sizes.
- Produces `AnalysisEngine::kSandbox` results.

**BehaviorSignatures:** Pattern database mapping import combinations and string patterns to behavior classifications. Uses a vector of `BehaviorSignature` structs with pattern + severity + description + MITRE technique ID.

**NetworkProfiler:** Analyzes network-related strings and imports to profile expected network behavior (C2 patterns, data exfiltration, download-and-execute, DNS tunneling).

**Commit:** `feat(havoc): add inline behavioral sandbox — static behavior prediction from imports/strings/resources`

---

### Task 5: Havoc — Advanced Detection Suite

**Codename:** Havoc-Advanced

**Files:**
- Create: `src/native/analysis/advanced/pe_capability.h`
- Create: `src/native/analysis/advanced/pe_capability.cpp`
- Create: `src/native/analysis/advanced/shellcode_detector.h`
- Create: `src/native/analysis/advanced/shellcode_detector.cpp`
- Create: `src/native/analysis/advanced/script_analyzer.h`
- Create: `src/native/analysis/advanced/script_analyzer.cpp`
- Create: `src/native/analysis/advanced/heap_analyzer.h`
- Create: `src/native/analysis/advanced/heap_analyzer.cpp`
- Create: `src/native/analysis/advanced/advanced_engine.h`
- Create: `src/native/analysis/advanced/advanced_engine.cpp`

**AdvancedEngine (`advanced_engine.h`):**

```cpp
#pragma once

#include "common/types.h"
#include "common/result.h"

namespace shieldtier {

class AdvancedEngine {
public:
    AdvancedEngine();
    Result<AnalysisEngineResult> analyze(const FileBuffer& file);

private:
    // Sub-analyzers produce findings that get merged
    std::vector<Finding> run_pe_capability(const FileBuffer& file);
    std::vector<Finding> run_shellcode_detection(const FileBuffer& file);
    std::vector<Finding> run_script_analysis(const FileBuffer& file);
    std::vector<Finding> run_heap_analysis(const FileBuffer& file);
};

}  // namespace shieldtier
```

**PeCapability** analyzes PE import sequences to detect capabilities:
- Process injection (VirtualAllocEx + WriteProcessMemory + CreateRemoteThread)
- Token manipulation (OpenProcessToken + AdjustTokenPrivileges)
- Service installation (OpenSCManager + CreateService)
- Credential theft (CredEnumerate, LsaRetrievePrivateData)
- Screen capture (BitBlt + GetDC)
- Crypto operations (CryptEncrypt + CryptDecrypt — ransomware indicator)
- Anti-analysis (SleepEx with large values, GetTickCount timing checks)
Each pattern has MITRE ATT&CK technique ID in metadata.

**ShellcodeDetector** scans binary data for shellcode patterns:
- NOP sleds (0x90 runs > 16 bytes)
- Common shellcode opcodes (GetPC patterns: call $+5 / pop reg, fstenv)
- API hash resolution patterns (ROR-13 hash loops)
- Stack-based string construction

**ScriptAnalyzer** detects embedded scripts and macro patterns:
- PowerShell encoded commands (-EncodedCommand, -enc)
- VBA macro keywords (AutoOpen, Document_Open, Shell, WScript)
- JavaScript eval/Function obfuscation patterns
- Base64-encoded payloads

**HeapAnalyzer** examines binary for heap exploitation indicators:
- Heap spray patterns (repeated NOP+shellcode blocks)
- Use-after-free indicators in debug builds
- Double-free patterns

Produces `AnalysisEngine::kAdvanced` results.

**Commit:** `feat(havoc): add advanced detection suite — PE capability, shellcode, script, heap analysis`

---

### Task 6: Sentry — Email + Content Analysis

**Codename:** Sentry-Email

**Files:**
- Create: `src/native/analysis/email/email_analyzer.h`
- Create: `src/native/analysis/email/email_analyzer.cpp`
- Create: `src/native/analysis/content/content_analyzer.h`
- Create: `src/native/analysis/content/content_analyzer.cpp`

**EmailAnalyzer (`email_analyzer.h`):**

```cpp
#pragma once

#include <string>
#include <vector>
#include "common/types.h"
#include "common/result.h"

namespace shieldtier {

struct EmailHeader {
    std::string name;
    std::string value;
};

struct EmailAttachment {
    std::string filename;
    std::string content_type;
    std::vector<uint8_t> data;
    std::string sha256;
};

struct ParsedEmail {
    std::string subject;
    std::string from;
    std::vector<std::string> to;
    std::string date;
    std::string message_id;
    std::string body_text;
    std::string body_html;
    std::vector<EmailHeader> headers;
    std::vector<EmailAttachment> attachments;
    std::vector<std::string> urls_in_body;
};

class EmailAnalyzer {
public:
    EmailAnalyzer();

    Result<ParsedEmail> parse(const uint8_t* data, size_t size);
    Result<AnalysisEngineResult> analyze(const FileBuffer& file);

private:
    std::vector<Finding> analyze_headers(const ParsedEmail& email);
    std::vector<Finding> analyze_body(const ParsedEmail& email);
    std::vector<Finding> analyze_attachments(const ParsedEmail& email);
    std::vector<std::string> extract_urls(const std::string& text);

    void parse_mime_part(const std::string& part, const std::string& boundary,
                         ParsedEmail& result);
};

}  // namespace shieldtier
```

**Key behavior:**
- `parse()`: Parses RFC 5322 email format (headers + MIME multipart body).
- Header analysis: SPF/DKIM/DMARC validation indicators, received chain anomalies, reply-to != from.
- Body analysis: URL extraction and classification (shortened URLs, known phishing domains, IP-based URLs, homograph attacks).
- Attachment analysis: Dangerous file types (.exe, .scr, .bat, .js, .vbs, .hta, .lnk), double extensions, password-protected archives.
- Produces `AnalysisEngine::kEmail` results.

**ContentAnalyzer (`content_analyzer.h`):**

```cpp
#pragma once

#include "common/types.h"
#include "common/result.h"

namespace shieldtier {

class ContentAnalyzer {
public:
    ContentAnalyzer();
    Result<AnalysisEngineResult> analyze(const FileBuffer& file);

private:
    std::vector<Finding> analyze_html(const std::string& content);
    std::vector<Finding> analyze_javascript(const std::string& content);

    bool detect_phishing_form(const std::string& html);
    bool detect_drive_by_download(const std::string& html);
    bool detect_obfuscated_js(const std::string& js);
    int count_iframes(const std::string& html);
};

}  // namespace shieldtier
```

**Key behavior:**
- Analyzes HTML/JS content for threats.
- Phishing detection: forms with action pointing to external domains, hidden iframes, credential harvesting patterns.
- Drive-by download: auto-triggering downloads, obfuscated JS payloads, eval chains.
- Produces `AnalysisEngine::kContent` results.

**Commit:** `feat(sentry): add email + content analysis — MIME parsing, phishing/attachment detection`

---

### Task 7: Sentry — Log Analysis Framework

**Codename:** Sentry-Log

**Files:**
- Create: `src/native/analysis/loganalysis/log_manager.h`
- Create: `src/native/analysis/loganalysis/log_manager.cpp`
- Create: `src/native/analysis/loganalysis/log_normalizer.h`
- Create: `src/native/analysis/loganalysis/log_normalizer.cpp`
- Create: `src/native/analysis/loganalysis/log_detector.h`
- Create: `src/native/analysis/loganalysis/log_detector.cpp`

**LogManager (`log_manager.h`):**

```cpp
#pragma once

#include <string>
#include <vector>
#include "common/types.h"
#include "common/result.h"

namespace shieldtier {

enum class LogFormat {
    kCsv, kJson, kEvtx, kSyslog, kCef, kLeef,
    kW3c, kApache, kNginx, kPcap, kEml, kXlsx, kAuto
};

struct NormalizedEvent {
    int64_t timestamp;
    std::string source;
    std::string event_type;
    Severity severity;
    std::string message;
    json fields;  // key-value pairs from original log
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
```

**LogNormalizer:** Normalizes parsed events into common schema (timestamp, source, type, severity, fields). Handles timezone conversion, field name mapping.

**LogDetector:** Runs detection rules against normalized events:
- Brute force (N failed logins from same source in T seconds)
- Lateral movement (new login from internal IP not seen before)
- Privilege escalation (user added to admin group)
- Data exfiltration (large outbound transfer)
- Suspicious commands (PowerShell -enc, certutil -decode, bitsadmin)

Produces `AnalysisEngine::kLogAnalysis` results.

**Commit:** `feat(sentry): add log analysis framework — multi-format parser with detection rules`

---

### Task 8: Sentry — Threat Feed + Capture

**Codename:** Sentry-ThreatFeed

**Files:**
- Create: `src/native/analysis/threatfeed/threat_feed_manager.h`
- Create: `src/native/analysis/threatfeed/threat_feed_manager.cpp`
- Create: `src/native/capture/capture_manager.h`
- Create: `src/native/capture/capture_manager.cpp`
- Create: `src/native/capture/har_builder.h`
- Create: `src/native/capture/har_builder.cpp`

**ThreatFeedManager (`threat_feed_manager.h`):**

```cpp
#pragma once

#include <mutex>
#include <string>
#include <unordered_set>
#include <vector>
#include "analysis/enrichment/http_client.h"
#include "common/result.h"

namespace shieldtier {

struct ThreatIndicator {
    std::string type;     // "ip", "domain", "hash", "url"
    std::string value;
    std::string source;
    std::string description;
    int64_t first_seen;
    int64_t last_seen;
};

class ThreatFeedManager {
public:
    ThreatFeedManager();

    Result<bool> update_feeds();
    bool is_known_threat(const std::string& type, const std::string& value) const;
    std::vector<ThreatIndicator> lookup(const std::string& type,
                                         const std::string& value) const;
    size_t indicator_count() const;

private:
    Result<std::vector<ThreatIndicator>> fetch_abuse_ch_urls();
    Result<std::vector<ThreatIndicator>> fetch_abuse_ch_hashes();
    void index_indicators(const std::vector<ThreatIndicator>& indicators);

    std::unordered_set<std::string> ip_set_;
    std::unordered_set<std::string> domain_set_;
    std::unordered_set<std::string> hash_set_;
    std::unordered_set<std::string> url_set_;
    std::vector<ThreatIndicator> all_indicators_;
    mutable std::mutex mutex_;
    HttpClient http_client_;
};

}  // namespace shieldtier
```

**Key behavior:**
- Ingests threat intelligence from free feeds (abuse.ch URLhaus, abuse.ch malware hashes).
- `is_known_threat()`: O(1) lookup against hash sets.
- `update_feeds()`: Downloads latest indicators, indexes into sets.

**CaptureManager + HarBuilder:**

```cpp
// capture_manager.h
#pragma once

#include <mutex>
#include <string>
#include <vector>
#include "common/json.h"

namespace shieldtier {

struct CapturedRequest {
    std::string method;
    std::string url;
    std::unordered_map<std::string, std::string> request_headers;
    std::unordered_map<std::string, std::string> response_headers;
    int status_code;
    int64_t request_size;
    int64_t response_size;
    double duration_ms;
    int64_t timestamp;
    std::string mime_type;
};

class CaptureManager {
public:
    CaptureManager();

    void start_capture(int browser_id);
    void stop_capture(int browser_id);
    void record_request(int browser_id, const CapturedRequest& req);

    std::vector<CapturedRequest> get_requests(int browser_id) const;
    bool is_capturing(int browser_id) const;
    void clear(int browser_id);

private:
    std::unordered_map<int, std::vector<CapturedRequest>> captures_;
    std::unordered_set<int> active_;
    mutable std::mutex mutex_;
};

}  // namespace shieldtier
```

**HarBuilder:** Converts `CapturedRequest` vector into HAR 1.2 JSON format.

**Commit:** `feat(sentry): add threat feed manager + capture manager with HAR export`

---

### Task 9: Phantom — VM Core Lifecycle

**Codename:** Phantom-Core

**Files:**
- Create: `src/native/vm/vm_types.h`
- Create: `src/native/vm/vm_manager.h`
- Create: `src/native/vm/vm_manager.cpp`
- Create: `src/native/vm/qemu_launcher.h`
- Create: `src/native/vm/qemu_launcher.cpp`

**VmTypes (`vm_types.h`):**

```cpp
#pragma once

#include <string>
#include <vector>
#include "common/json.h"

namespace shieldtier {

enum class VmState {
    kCreating, kBooting, kReady, kAnalyzing, kShuttingDown, kStopped, kError
};

enum class VmPlatform { kWindows, kLinux, kMacOS };

struct VmConfig {
    VmPlatform platform;
    int cpu_cores = 2;
    int memory_mb = 2048;
    int disk_gb = 20;
    std::string snapshot_name;
    std::string image_path;
    int analysis_timeout_seconds = 300;
    bool enable_network = true;
    bool enable_inetsim = true;
};

struct VmInstance {
    std::string id;
    VmState state;
    VmConfig config;
    int pid = -1;               // QEMU process PID
    int monitor_port = -1;      // QMP port
    int serial_port = -1;       // serial console port
    std::string snapshot_path;
};

struct VmAnalysisResult {
    std::string vm_id;
    bool success;
    std::string error;
    std::vector<json> events;   // behavioral events from agent
    double duration_ms;
    json network_activity;      // from INetSim
};

}  // namespace shieldtier
```

**VmManager (`vm_manager.h`):**

```cpp
#pragma once

#include <mutex>
#include <string>
#include <unordered_map>
#include "common/result.h"
#include "vm/vm_types.h"
#include "vm/qemu_launcher.h"

namespace shieldtier {

class VmManager {
public:
    explicit VmManager(const std::string& vm_base_dir);

    Result<std::string> create_vm(const VmConfig& config);
    Result<bool> start_vm(const std::string& vm_id);
    Result<bool> stop_vm(const std::string& vm_id);
    Result<bool> destroy_vm(const std::string& vm_id);

    Result<VmAnalysisResult> submit_sample(
        const std::string& vm_id,
        const FileBuffer& file,
        int timeout_seconds = 300);

    VmState get_state(const std::string& vm_id) const;
    std::vector<VmInstance> list_vms() const;

private:
    Result<bool> wait_for_ready(const std::string& vm_id, int timeout_ms);
    Result<bool> inject_sample(const std::string& vm_id, const FileBuffer& file);
    Result<std::vector<json>> collect_events(const std::string& vm_id);

    std::string vm_base_dir_;
    std::unordered_map<std::string, VmInstance> vms_;
    mutable std::mutex mutex_;
    QemuLauncher launcher_;
};

}  // namespace shieldtier
```

**QemuLauncher:** Manages QEMU process lifecycle:
- Builds QEMU command line arguments for platform/config.
- Starts QEMU as subprocess, captures PID.
- Communicates via QMP (QEMU Machine Protocol) over TCP socket for VM control (snapshot restore, device hotplug).
- Monitors QEMU process state.

**Key behavior:**
- `create_vm()`: Generates unique VM ID, creates working directory, prepares config.
- `start_vm()`: Launches QEMU via `QemuLauncher`, waits for boot.
- `submit_sample()`: Injects sample file into VM (via shared folder or network), waits for analysis timeout, collects events from agent.
- `stop_vm()`: Sends QMP `quit` command, waits for process exit.
- `destroy_vm()`: Stops VM + removes working directory.

**Commit:** `feat(phantom): add VM core lifecycle — QEMU launcher, VM manager, sample submission`

---

### Task 10: Phantom — INetSim + Anti-Evasion

**Codename:** Phantom-INetSim

**Files:**
- Create: `src/native/vm/inetsim_server.h`
- Create: `src/native/vm/inetsim_server.cpp`
- Create: `src/native/vm/anti_evasion.h`
- Create: `src/native/vm/anti_evasion.cpp`

**INetSimServer (`inetsim_server.h`):**

```cpp
#pragma once

#include <atomic>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include "common/json.h"
#include "common/result.h"

namespace shieldtier {

struct INetSimConfig {
    int dns_port = 5553;
    int http_port = 8080;
    int https_port = 8443;
    std::string bind_address = "127.0.0.1";
    std::string fake_dns_ip = "10.0.0.1";
};

struct NetworkEvent {
    std::string protocol;  // "dns", "http", "https", "smtp"
    std::string detail;
    json metadata;
    int64_t timestamp;
};

class INetSimServer {
public:
    explicit INetSimServer(const INetSimConfig& config = {});
    ~INetSimServer();

    Result<bool> start();
    void stop();
    bool is_running() const;

    std::vector<NetworkEvent> get_events() const;
    void clear_events();

private:
    void dns_server_loop();
    void http_server_loop();

    void record_event(const NetworkEvent& event);

    INetSimConfig config_;
    std::atomic<bool> running_{false};
    std::vector<std::jthread> server_threads_;
    std::vector<NetworkEvent> events_;
    mutable std::mutex events_mutex_;
};

}  // namespace shieldtier
```

**Key behavior:**
- Fake DNS: resolves ALL queries to `fake_dns_ip`. Records query domains.
- Fake HTTP: accepts all requests, returns configurable response (200 OK with small HTML page). Records URLs, headers, POST data.
- All network activity logged as `NetworkEvent` for analysis.

**AntiEvasion (`anti_evasion.h`):**

```cpp
#pragma once

#include <string>
#include <vector>
#include "common/json.h"

namespace shieldtier {

struct AntiEvasionConfig {
    bool mask_cpuid = true;        // hide hypervisor bit
    bool randomize_mac = true;
    bool randomize_serial = true;
    bool realistic_disk_size = true;
    bool add_fake_processes = true;
    bool set_realistic_uptime = true;
};

class AntiEvasion {
public:
    explicit AntiEvasion(const AntiEvasionConfig& config = {});

    // Generate QEMU args for anti-evasion
    std::vector<std::string> get_qemu_args() const;

    // Generate registry/config patches for the guest OS
    json get_guest_patches(const std::string& platform) const;

private:
    std::string generate_serial() const;
    std::string generate_mac() const;
    std::string generate_bios_vendor() const;

    AntiEvasionConfig config_;
};

}  // namespace shieldtier
```

**Key behavior:**
- `get_qemu_args()`: Returns QEMU flags to hide hypervisor (e.g., `-cpu host,+hypervisor=off,-hv-*`, custom CPUID, SMBIOS strings).
- `get_guest_patches()`: Returns registry values to set in Windows guest (fake program installations, recent documents, browser history entries) to appear like a real user machine.

**Commit:** `feat(phantom): add INetSim fake network server + anti-evasion QEMU configuration`

---

### Task 11: Phantom — VM Agent Protocol

**Codename:** Phantom-Agent

**Files:**
- Create: `src/native/vm/vm_protocol.h`
- Create: `src/native/vm/vm_protocol.cpp`
- Create: `src/native/vm/vm_scoring.h`
- Create: `src/native/vm/vm_scoring.cpp`

**VmProtocol (`vm_protocol.h`):**

```cpp
#pragma once

#include <string>
#include <vector>
#include "common/json.h"
#include "common/result.h"

namespace shieldtier {

// Communication protocol between host (ShieldTier) and VM agent.
// Messages sent over serial console or TCP socket.
enum class AgentMessageType {
    kHeartbeat, kReady, kSampleReceived, kEvent, kComplete, kError
};

struct AgentMessage {
    AgentMessageType type;
    json payload;
    int64_t timestamp;
};

class VmProtocol {
public:
    static std::string serialize(const AgentMessage& msg);
    static Result<AgentMessage> deserialize(const std::string& line);

    // Parse a stream of newline-delimited JSON messages from agent
    static std::vector<AgentMessage> parse_stream(const std::string& data);

    // Extract behavioral events from agent messages
    static std::vector<json> extract_events(const std::vector<AgentMessage>& messages);
};

}  // namespace shieldtier
```

**VmScoring (`vm_scoring.h`):**

```cpp
#pragma once

#include "common/types.h"
#include "common/result.h"

namespace shieldtier {

class VmScoring {
public:
    // Convert VM analysis events into AnalysisEngineResult
    static Result<AnalysisEngineResult> score_vm_results(
        const std::vector<json>& events,
        const json& network_activity,
        double duration_ms);

private:
    static std::vector<Finding> events_to_findings(const std::vector<json>& events);
    static std::vector<Finding> network_to_findings(const json& network_activity);
};

}  // namespace shieldtier
```

**Key behavior:**
- `VmProtocol`: JSON-over-newline protocol. Agent sends heartbeats, events (file/registry/process/network activity), completion signal.
- `VmScoring`: Maps raw VM events to `Finding` objects with appropriate severity and MITRE technique IDs. Produces `AnalysisEngine::kVmSandbox` results.

**Commit:** `feat(phantom): add VM agent protocol + behavioral event scoring`

---

### Task 12: CMake Integration + MessageHandler Wiring

**Codename:** Integration

**Files:**
- Modify: `src/native/CMakeLists.txt`
- Modify: `src/native/ipc/message_handler.h`
- Modify: `src/native/ipc/message_handler.cpp`

Add ALL new sources to CMakeLists.txt. Add `sodium` to link targets.

Wire new engines into MessageHandler's analysis pipeline:
- Add `SandboxEngine`, `AdvancedEngine`, `EmailAnalyzer`, `ContentAnalyzer`, `LogManager` to `handle_analyze_download()` thread.
- Add new IPC actions: `get_config`, `set_config`, `export_report`, `get_threat_feeds`, `start_capture`, `stop_capture`, `get_capture`.

**Commit:** `feat(integration): wire Wave 2b engines into analysis pipeline and IPC`

---

## Source Files Summary

After Wave 2b, new files added:

```
config/config_store.{h,cpp}
auth/auth_manager.{h,cpp}
network/network_policy.{h,cpp}
export/export_manager.{h,cpp}
export/defang.{h,cpp}
chat/chat_manager.{h,cpp}
chat/shieldcrypt.{h,cpp}
analysis/sandbox/sandbox_engine.{h,cpp}
analysis/sandbox/behavior_signatures.{h,cpp}
analysis/sandbox/network_profiler.{h,cpp}
analysis/advanced/advanced_engine.{h,cpp}
analysis/advanced/pe_capability.{h,cpp}
analysis/advanced/shellcode_detector.{h,cpp}
analysis/advanced/script_analyzer.{h,cpp}
analysis/advanced/heap_analyzer.{h,cpp}
analysis/email/email_analyzer.{h,cpp}
analysis/content/content_analyzer.{h,cpp}
analysis/loganalysis/log_manager.{h,cpp}
analysis/loganalysis/log_normalizer.{h,cpp}
analysis/loganalysis/log_detector.{h,cpp}
analysis/threatfeed/threat_feed_manager.{h,cpp}
capture/capture_manager.{h,cpp}
capture/har_builder.{h,cpp}
vm/vm_types.h
vm/vm_manager.{h,cpp}
vm/qemu_launcher.{h,cpp}
vm/inetsim_server.{h,cpp}
vm/anti_evasion.{h,cpp}
vm/vm_protocol.{h,cpp}
vm/vm_scoring.{h,cpp}
```
