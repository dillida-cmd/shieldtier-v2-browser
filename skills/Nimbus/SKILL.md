---
name: Nimbus
description: Use when building the ShieldTier Cloud backend — license server (/auth/activate, /auth/validate, /license/heartbeat), encrypted rule packaging service, /analyze feature vector API, tier gating middleware, and bloom filter generation for known-bad hashes
---

# S12 — Nimbus: Cloud Backend

## Overview

Server-side infrastructure on ShieldTier Cloud (Hetzner). License lifecycle management, encrypted YARA rule packaging, feature-vector-based threat scoring API, tier gating, and bloom filter generation for 100M+ known-bad hashes.

## Dependencies

- **Requires:** S10 (scoring interfaces), S11 (license crypto, rule crypto formats)
- **Blocks:** S13 (final integration tests need cloud endpoints)

## File Ownership

```
server/
  cmd/server/main.go          (HTTP server entry point)
  internal/
    auth/
      handler.go              (/auth/activate, /auth/validate)
      license.go              (license blob generation, Ed25519 signing)
      fingerprint.go          (fingerprint verification)
    rules/
      packager.go             (YARA compile → AES-256-GCM encrypt → Ed25519 sign)
      handler.go              (/rules/download endpoint)
      store.go                (rule version management)
    analyze/
      handler.go              (/analyze endpoint — feature vector → verdict)
      scoring.go              (server-side proprietary scoring)
      yara_server.go          (server-side YARA with proprietary rules)
    middleware/
      tier.go                 (free/pro/team/enterprise gating)
      ratelimit.go            (per-tier rate limiting)
      auth.go                 (JWT validation middleware)
    bloom/
      generator.go            (bloom filter from known-bad hash feeds)
      handler.go              (/bloom/download endpoint)
  deploy/
    Dockerfile
    docker-compose.yml
    nginx.conf
```

## Exit Criteria

Activate license → receive signed blob. Download encrypted rules (AES-256-GCM + Ed25519). Submit feature vector → receive server-side verdict. Bloom filter download (50MB, 100M+ hashes).

---

## License API

### POST /auth/activate

```json
// Request
{
    "license_key": "STIER-XXXX-XXXX-XXXX",
    "fingerprint": {
        "cpu_id": "...",
        "board_serial": "...",
        "disk_serial": "...",
        "mac_address": "...",
        "os_install_id": "..."
    },
    "app_version": "2.0.0"
}

// Response (200 OK)
{
    "license_id": "lic_abc123",
    "tier": "pro",
    "features": ["yara_premium", "sandbox", "enrichment", "email"],
    "machine_fingerprint_hash": "sha256...",
    "issued_at": 1709500000,
    "expires_at": 1741036000,
    "max_offline_days": 30,
    "signature": "ed25519_base64...",  // Ed25519 over all above fields
    "access_token": "jwt...",
    "refresh_token": "rt_..."
}
```

### POST /auth/validate (Heartbeat)

```json
// Request
{
    "license_id": "lic_abc123",
    "fingerprint_hash": "sha256...",
    "app_version": "2.0.0",
    "code_attestation_hash": "sha256..."  // hash of .text section
}

// Response (200 OK)
{
    "valid": true,
    "tier": "pro",
    "token_expires_at": 1709600000,
    "rules_version": 42,       // client checks if it needs new rules
    "bloom_version": 15,       // client checks if it needs new bloom filter
    "message": ""              // optional server message to display
}
```

### POST /license/heartbeat (24h check)

```json
// Request
{
    "license_id": "lic_abc123",
    "access_token": "jwt..."
}

// Response (200 OK)
{
    "valid": true,
    "next_heartbeat_seconds": 86400,
    "offline_days_remaining": 30
}
```

## Rule Packaging Service

```go
// Server-side: compile YARA → encrypt → sign → serve

type RulePackage struct {
    Version      uint32 `json:"version"`
    Timestamp    int64  `json:"timestamp"`
    ExpiresAt    int64  `json:"expires_at"`  // 7-day TTL
    PayloadSize  uint32 `json:"payload_size"`
    IV           []byte `json:"iv"`           // 12 bytes AES-256-GCM nonce
    AuthTag      []byte `json:"auth_tag"`     // 16 bytes GCM tag
    Signature    []byte `json:"signature"`    // 64 bytes Ed25519
    KeyID        string `json:"key_id"`
    Payload      []byte `json:"payload"`      // encrypted YARA rules
}

func PackageRules(rules []byte, licenseKey []byte, serverSigningKey ed25519.PrivateKey) (*RulePackage, error) {
    pkg := &RulePackage{
        Version:   42,
        Timestamp: time.Now().Unix(),
        ExpiresAt: time.Now().Add(7 * 24 * time.Hour).Unix(),
    }

    // Derive encryption key from license
    derivedKey := deriveRuleKey(licenseKey)

    // Encrypt with AES-256-GCM
    block, _ := aes.NewCipher(derivedKey)
    aead, _ := cipher.NewGCM(block)
    nonce := make([]byte, aead.NonceSize())
    rand.Read(nonce)

    ciphertext := aead.Seal(nil, nonce, rules, nil)

    pkg.IV = nonce
    pkg.Payload = ciphertext[:len(ciphertext)-aead.Overhead()]
    pkg.AuthTag = ciphertext[len(ciphertext)-aead.Overhead():]
    pkg.PayloadSize = uint32(len(rules))

    // Sign everything with Ed25519
    sigData := serializeForSigning(pkg)
    pkg.Signature = ed25519.Sign(serverSigningKey, sigData)

    return pkg, nil
}
```

## Feature Vector Analysis API

### POST /analyze

```json
// Request — feature vector (NOT raw file)
{
    "sha256": "abc123...",
    "md5": "def456...",
    "ssdeep": "48:...",
    "imphash": "789abc...",
    "file_size": 245760,
    "pe_sections": [
        {"name": ".text", "entropy": 6.2, "size": 102400, "virtual_size": 102400},
        {"name": ".rdata", "entropy": 5.1, "size": 40960, "virtual_size": 40960},
        {"name": ".data", "entropy": 7.8, "size": 81920, "virtual_size": 81920}
    ],
    "imports": {
        "kernel32.dll": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
        "advapi32.dll": ["RegSetValueExA"]
    },
    "strings": {
        "total": 1523,
        "suspicious_count": 42,
        "urls": ["http://evil-c2.com/beacon"],
        "ips": ["185.92.73.100"]
    },
    "pe_header": {
        "timestamp": 1709500000,
        "machine": 332,
        "subsystem": 2,
        "characteristics": 258
    },
    "behavioral": {
        "process_injection": true,
        "network_communication": true,
        "anti_analysis": false,
        "file_encryption": false
    }
}

// Response
{
    "verdict": "malicious",
    "confidence": 0.92,
    "threat_score": 87,
    "risk_level": "critical",
    "findings": [
        {
            "title": "Known Malware Family: AgentTesla",
            "description": "Matches proprietary YARA signature for AgentTesla stealer",
            "severity": "critical",
            "engine": "server_yara"
        },
        {
            "title": "ML Score: High Risk",
            "description": "ML model confidence: 0.94 malicious",
            "severity": "critical",
            "engine": "ml_scoring"
        }
    ],
    "mitre_techniques": ["T1055", "T1071", "T1547.001"],
    "fleet_reputation": {
        "seen_by_users": 47,
        "first_seen": "2026-02-15T10:30:00Z",
        "consensus": "malicious"
    }
}
```

## Bloom Filter (Known-Bad Hashes)

```go
// Generate bloom filter from threat intel feeds
// 100M+ SHA-256 hashes → ~50MB bloom filter with 0.01% false positive rate

import "github.com/bits-and-blooms/bloom/v3"

func GenerateBloomFilter(hashes []string) *bloom.BloomFilter {
    // Parameters for 100M entries, 0.01% FP rate:
    // m ≈ 1.44 * n * log2(1/p) ≈ 1.44 * 100M * 13.29 ≈ 1.9 billion bits ≈ 228 MB
    // For 50MB target, accept ~0.1% FP rate:
    // m ≈ 1.44 * 100M * 9.97 ≈ 1.4B bits ≈ 175 MB
    // For ~50MB: use ~400M bits with 7 hash functions for 10M hashes
    // Actual size depends on hash count

    n := uint(len(hashes))
    fpRate := 0.001  // 0.1% false positive
    filter := bloom.NewWithEstimates(n, fpRate)

    for _, hash := range hashes {
        filter.AddString(hash)
    }

    return filter
}

// Client-side: fast hash lookup
// Download bloom filter once, check locally
func CheckHash(filter *bloom.BloomFilter, sha256 string) bool {
    return filter.TestString(sha256)  // true = possibly malicious, false = definitely clean
}
```

## Tier Gating Middleware

```go
var tierPermissions = map[string][]string{
    "free":       {"basic_analysis", "bloom_lookup"},
    "pro":        {"basic_analysis", "bloom_lookup", "premium_yara", "sandbox",
                   "enrichment", "email", "ml_scoring"},
    "team":       {"basic_analysis", "bloom_lookup", "premium_yara", "sandbox",
                   "enrichment", "email", "ml_scoring", "fleet_reputation",
                   "api_access", "shared_intel"},
    "enterprise": {"basic_analysis", "bloom_lookup", "premium_yara", "sandbox",
                   "enrichment", "email", "ml_scoring", "fleet_reputation",
                   "api_access", "shared_intel", "custom_rules", "sla",
                   "dedicated_scoring"},
}

func TierGate(requiredFeature string) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            tier := r.Context().Value("tier").(string)
            allowed := tierPermissions[tier]
            for _, f := range allowed {
                if f == requiredFeature {
                    next.ServeHTTP(w, r)
                    return
                }
            }
            http.Error(w, "Feature requires higher tier", http.StatusForbidden)
        })
    }
}
```

## Deployment

```yaml
# docker-compose.yml
services:
  api:
    build: .
    ports:
      - "8443:8443"
    environment:
      - DATABASE_URL=postgres://...
      - ED25519_PRIVATE_KEY_PATH=/secrets/signing.key
      - YARA_RULES_PATH=/data/rules/
      - BLOOM_DATA_PATH=/data/bloom/
    volumes:
      - ./secrets:/secrets:ro
      - ./data:/data

  postgres:
    image: postgres:16
    environment:
      - POSTGRES_DB=shieldtier
    volumes:
      - pgdata:/var/lib/postgresql/data

  redis:
    image: redis:7
    # Rate limiting, session cache
```

## Common Mistakes

| Mistake | Fix |
|---------|-----|
| Sending raw files to /analyze | Only feature vectors — protects user privacy |
| Not validating JWT on every request | Every API call must validate token, not just /auth |
| Rule package without expiry | Always set 7-day TTL, enforce server-side |
| Bloom filter without versioning | Client must know when to re-download — version + delta support |
| Storing Ed25519 private key in code | Must be in secure secrets management, not in binary |
| Not rate-limiting free tier | Free tier must be rate-limited to prevent abuse |
| License activation without fingerprint binding | License must be bound to hardware — prevent sharing |
| heartbeat without code attestation | Verify code_attestation_hash matches known-good values |
