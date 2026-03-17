---
name: Rune
description: Use when building the YARA scanning engine — libyara integration, yr_rules_scan_mem, rule compilation, encrypted rule loading, and built-in open-source rules
---

# S3 — Rune: YARA Engine libyara Integration

## Overview

Port V1's custom JavaScript YARA parser to native libyara C library. Direct `yr_rules_scan_mem()` on in-memory file buffers. Supports both built-in open-source rules and encrypted proprietary rules delivered from ShieldTier Cloud.

## Dependencies

- **Requires:** S0 (foundation) — libyara ExternalProject_Add, shared types
- **Blocks:** S10 (scoring engine consumes YARA matches)

## File Ownership

```
src/native/analysis/yara/
  scanner.cpp/.h        (yr_rules_scan_mem wrapper, thread-safe scanning)
  rule_manager.cpp/.h   (load/compile rules, encrypted rule decryption hook)
  builtin_rules.cpp/.h  (open-source rules compiled in as string literals)
```

## Exit Criteria

Scan PE buffer with 24+ YARA rules, return matches as `std::vector<Finding>`. Thread-safe — multiple scans concurrent. Encrypted rules from cloud decrypt and compile in-memory only.

---

## libyara API Reference

### Initialization

```cpp
#include <yara.h>

// Call once at app startup (NOT per-scan)
yr_initialize();

// Call once at shutdown
yr_finalize();
```

### Rule Compilation

```cpp
YR_COMPILER* compiler = nullptr;
yr_compiler_create(&compiler);

// Set error callback
yr_compiler_set_callback(compiler, [](int error_level, const char* file_name,
    int line_number, const YR_RULE* rule, const char* message, void* user_data) {
    // Log compilation errors
}, nullptr);

// Add rules from string (in-memory — no disk access)
int errors = yr_compiler_add_string(compiler, rule_source, nullptr);
if (errors > 0) {
    yr_compiler_destroy(compiler);
    return Error("YARA compilation failed");
}

// Get compiled rules
YR_RULES* rules = nullptr;
yr_compiler_get_rules(compiler, &rules);

// Compiler must be destroyed AFTER get_rules (transfers ownership)
yr_compiler_destroy(compiler);
// compiler is now invalid — only use rules

// When done with rules:
yr_rules_destroy(rules);
```

### Scanning (Thread-Safe)

```cpp
// yr_rules is thread-safe for scanning (multiple threads can scan with same rules)
// yr_compiler is NOT thread-safe

struct ScanContext {
    std::vector<shieldtier::Finding>* findings;
    const std::string* filename;
};

int scan_callback(YR_SCAN_CONTEXT* context, int message,
                  void* message_data, void* user_data) {
    auto* ctx = static_cast<ScanContext*>(user_data);

    switch (message) {
        case CALLBACK_MSG_RULE_MATCHING: {
            YR_RULE* rule = static_cast<YR_RULE*>(message_data);
            shieldtier::Finding finding;
            finding.title = rule->identifier;
            finding.engine = "yara";
            finding.severity = "high"; // derive from rule metadata

            // Extract rule metadata
            YR_META* meta;
            yr_rule_metas_foreach(rule, meta) {
                if (meta->type == META_TYPE_STRING) {
                    finding.metadata[meta->identifier] = meta->string;
                    if (std::string(meta->identifier) == "severity") {
                        finding.severity = meta->string;
                    }
                }
            }

            // Extract matched strings
            YR_STRING* string;
            yr_rule_strings_foreach(rule, string) {
                YR_MATCH* match;
                yr_string_matches_foreach(context, string, match) {
                    finding.metadata["matches"].push_back({
                        {"offset", match->offset},
                        {"length", match->match_length},
                        {"identifier", string->identifier}
                    });
                }
            }

            finding.description = std::string("YARA rule matched: ") + rule->identifier;
            ctx->findings->push_back(std::move(finding));
            break;
        }
        case CALLBACK_MSG_RULE_NOT_MATCHING:
            break;
        case CALLBACK_MSG_SCAN_FINISHED:
            break;
        case CALLBACK_MSG_IMPORT_MODULE:
            break;
    }
    return CALLBACK_CONTINUE;
}

// Scan a buffer
Result<std::vector<Finding>> scan_buffer(
    YR_RULES* rules,
    const uint8_t* data,
    size_t size,
    const std::string& filename,
    int timeout_seconds = 60) {

    std::vector<Finding> findings;
    ScanContext ctx{&findings, &filename};

    int result = yr_rules_scan_mem(
        rules,
        data,
        size,
        SCAN_FLAGS_FAST_MODE,  // skip slow rules
        scan_callback,
        &ctx,
        timeout_seconds
    );

    if (result == ERROR_SCAN_TIMEOUT) {
        return Error("YARA scan timed out", "SCAN_TIMEOUT");
    }
    if (result != ERROR_SUCCESS) {
        return Error("YARA scan failed: " + std::to_string(result), "SCAN_ERROR");
    }

    return findings;
}
```

### Scanner API (Alternative — Newer)

```cpp
// yr_scanner is an alternative that supports per-scan settings
YR_SCANNER* scanner = nullptr;
yr_scanner_create(rules, &scanner);

yr_scanner_set_callback(scanner, scan_callback, &ctx);
yr_scanner_set_timeout(scanner, 60);
yr_scanner_set_flags(scanner, SCAN_FLAGS_FAST_MODE);

int result = yr_scanner_scan_mem(scanner, data, size);

yr_scanner_destroy(scanner);
```

## Rule Manager

### Compiled Built-in Rules

```cpp
// builtin_rules.cpp — open-source rules as string literals
static const char* kBuiltinRules[] = {
    // Rule 1: Suspicious PE imports
    R"(
    rule SuspiciousImports {
        meta:
            severity = "medium"
            description = "PE imports commonly used by malware"
        condition:
            pe.imports("kernel32.dll", "VirtualAlloc") and
            pe.imports("kernel32.dll", "WriteProcessMemory") and
            pe.imports("kernel32.dll", "CreateRemoteThread")
    }
    )",
    // ... 23 more rules ...
    nullptr  // sentinel
};
```

### Encrypted Rule Loading (Cloud Rules)

```cpp
// rule_manager.cpp
#include <sodium.h>

Result<YR_RULES*> load_encrypted_rules(
    const uint8_t* encrypted_blob,
    size_t blob_size,
    const uint8_t* decryption_key) {  // 32-byte key from S11

    // Verify Ed25519 signature (first 64 bytes)
    // ... signature verification (S11 provides verify function) ...

    // Parse header
    auto* pkg = reinterpret_cast<const EncryptedRulePackage*>(encrypted_blob);

    // Check expiry (7-day TTL)
    auto now = std::chrono::system_clock::now().time_since_epoch().count();
    if (now > pkg->expires_at) {
        return Error("Rule package expired", "RULES_EXPIRED");
    }

    // Decrypt AES-256-GCM
    std::vector<uint8_t> plaintext(pkg->payload_size);
    unsigned long long plaintext_len;

    if (crypto_aead_aes256gcm_decrypt(
            plaintext.data(), &plaintext_len,
            nullptr,  // nsec (unused)
            pkg->encrypted_payload, blob_size - sizeof(EncryptedRulePackage),
            nullptr, 0,  // additional data
            pkg->iv,
            decryption_key) != 0) {
        return Error("Rule decryption failed", "DECRYPT_ERROR");
    }

    // Compile decrypted rules in memory
    YR_COMPILER* compiler = nullptr;
    yr_compiler_create(&compiler);
    std::string rule_text(plaintext.begin(), plaintext.begin() + plaintext_len);

    // Zero plaintext immediately
    sodium_memzero(plaintext.data(), plaintext.size());
    sodium_memzero(rule_text.data(), rule_text.size());

    int errors = yr_compiler_add_string(compiler, rule_text.c_str(), nullptr);

    YR_RULES* rules = nullptr;
    yr_compiler_get_rules(compiler, &rules);
    yr_compiler_destroy(compiler);

    return rules;
}
```

### Thread-Safe Rule Access

```cpp
class RuleManager {
    std::shared_mutex mutex_;
    YR_RULES* builtin_rules_ = nullptr;
    YR_RULES* premium_rules_ = nullptr;  // from cloud, may be null

public:
    // Compile built-in rules (call once at startup)
    void initialize() {
        YR_COMPILER* compiler = nullptr;
        yr_compiler_create(&compiler);
        for (int i = 0; kBuiltinRules[i]; ++i) {
            yr_compiler_add_string(compiler, kBuiltinRules[i], nullptr);
        }
        yr_compiler_get_rules(compiler, &builtin_rules_);
        yr_compiler_destroy(compiler);
    }

    // Hot-reload premium rules (called when cloud delivers new package)
    void update_premium_rules(YR_RULES* new_rules) {
        std::unique_lock lock(mutex_);
        if (premium_rules_) yr_rules_destroy(premium_rules_);
        premium_rules_ = new_rules;
    }

    // Scan with all available rules
    Result<std::vector<Finding>> scan(const FileBuffer& file) {
        std::shared_lock lock(mutex_);
        std::vector<Finding> all_findings;

        auto builtin = scan_buffer(builtin_rules_, file.ptr(), file.size(), file.filename);
        if (builtin.ok()) {
            all_findings.insert(all_findings.end(),
                builtin.value().begin(), builtin.value().end());
        }

        if (premium_rules_) {
            auto premium = scan_buffer(premium_rules_, file.ptr(), file.size(), file.filename);
            if (premium.ok()) {
                all_findings.insert(all_findings.end(),
                    premium.value().begin(), premium.value().end());
            }
        }

        return all_findings;
    }
};
```

## Module Support

YARA modules extend scanning capabilities. Key modules for malware analysis:

```cpp
// Compile with module support:
// yr_compiler_add_string with rules that use:
//   pe module:     pe.imports(), pe.sections, pe.entry_point
//   elf module:    elf.type, elf.machine
//   math module:   math.entropy(), math.deviation()
//   hash module:   hash.md5(), hash.sha256()
//   dotnet module: dotnet.assembly.name

// Modules are built into libyara — no extra config needed
// Just ensure libyara was built with -DYARA_ENABLE_MODULES=ON (default)
```

## CMake Integration

```cmake
# In src/native/CMakeLists.txt:
target_sources(shieldtier PRIVATE
    analysis/yara/scanner.cpp
    analysis/yara/rule_manager.cpp
    analysis/yara/builtin_rules.cpp
)

target_link_libraries(shieldtier PRIVATE yara)  # from S0's ExternalProject
target_include_directories(shieldtier PRIVATE ${YARA_INCLUDE_DIR})
```

## Common Mistakes

| Mistake | Fix |
|---------|-----|
| Calling yr_initialize per scan | Call once at app startup, yr_finalize at shutdown |
| Using yr_compiler from multiple threads | yr_compiler is NOT thread-safe — create per thread or mutex |
| Forgetting yr_compiler_destroy after get_rules | Memory leak — destroy compiler, keep rules |
| Using rules after yr_rules_destroy | UAF — ensure all scans complete before destroying rules |
| Not zeroing decrypted rule text | Plaintext rules in memory — sodium_memzero immediately |
| Building libyara without modules | PE/ELF modules won't work — ensure configure --enable-modules |
| Ignoring SCAN_TIMEOUT | Malware can craft files that trigger exponential rule matching |
| Not setting SCAN_FLAGS_FAST_MODE | Some rules with complex conditions are extremely slow |
