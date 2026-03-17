# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ShieldTier V2 is a **SOC malware analysis browser** replacing an Electron-based V1 with a CEF (Chromium Embedded Framework) C++ shell. The primary motivation is gaining native streaming response interception (`CefResponseFilter`) to capture downloads in-memory without the limitations of Electron's CDP Fetch hacks (OOM on large files, base64 overhead, blob/service worker bypasses).

**Current state**: Planning phase. The repo contains `PLAN.md` (the full architecture document) and no implementation code yet.

## Architecture (V2 Target)

```
CEF C++ Shell (browser engine)
  ├── CefResponseFilter     → streaming download interception (replaces CDP Fetch)
  ├── CefDownloadHandler    → download lifecycle control
  ├── CefRequestHandler     → network policy enforcement
  └── CefCookieManager      → per-tab session isolation

Native C++ Analysis Engine (all detection logic)
  ├── libyara integration   → YARA scanning (replaces custom JS parser)
  ├── pe-parse              → PE analysis (replaces pe-library npm)
  ├── libsodium             → crypto (replaces node-forge/libsodium-wrappers)
  ├── libcurl               → HTTP enrichment (replaces Node.js HTTP)
  └── All V1 analysis subsystems ported from TypeScript to C++

React UI (renderer)
  └── Loaded by CEF, communicates via CefMessageRouter IPC
```

**Key design principle**: Nothing from V1's analysis code is discarded — it's all ported to C++. The React renderer UI is reused as-is, loaded by CEF instead of Electron.

## Build System (Planned)

```bash
# CEF SDK setup
scripts/download-cef.sh          # Fetch CEF SDK for platform

# Build
cmake -G "Ninja" -DCEF_ROOT=/path/to/cef ..
ninja

# Post-link (production builds)
scripts/vmprotect-post-link.sh   # VMProtect on critical functions
scripts/sign-and-package.sh      # Code signing + packaging
```

- **CMake + Ninja** for native C++ (CEF + analysis engine + all dependencies)
- **Vite** for React renderer build
- **O-LLVM/Hikari/Pluto** LLVM passes for obfuscation in production builds
- **VMProtect** post-link step for virtualizing scoring/license/integrity functions

## Source Tree (Planned)

- `src/native/` — All C++ code (compiles to single native binary)
  - `app/` — CEF initialization, entry point
  - `browser/` — CEF handlers (response filter, downloads, requests, cookies, navigation)
  - `analysis/` — All analysis engines (yara, fileanalysis, sandbox, advanced, enrichment, email, content, loganalysis, threatfeed)
  - `scoring/` — VMProtect-virtualized threat scoring engine
  - `security/` — License, fingerprint, attestation, integrity mesh, anti-debug, encrypted pages, rule crypto
  - `vm/` — QEMU VM sandbox orchestration
  - `ipc/` — CEF message router handler (native <-> renderer bridge)
- `src/renderer/` — V2's own React UI (forked from V1, independently maintained)
  - `src/` — React source (TSX components, hooks, styles, shared types)
  - `dist/` — Vite build output (served by CEF SchemeHandler)
  - Build: `cd src/renderer && npm run build`
- `third_party/` — CEF SDK, libyara, libsodium, libcurl, pe-parse, libarchive, wabt
- `agents/vm-agent/` — Go agent for QEMU VMs (carried from V1)
- `cmake/` — FindCEF, ObfuscationPasses, VMProtect CMake modules

## Five-Layer Protection Model

1. **Code Attestation** — Self-hashing, integrity guard mesh, silent corruption on tamper (never crash)
2. **Hardware-Bound Licensing** — 5-factor machine fingerprint, Secure Enclave/DPAPI/Secret Service key storage, 30-day offline grace
3. **Native C++ Binary** — VMProtect virtualization on critical functions, LLVM obfuscation (CFF+MBA+BCF+string encryption) on everything else, anti-debug mesh (12 methods), encrypted code pages with lazy decryption
4. **Encrypted Rule Delivery** — AES-256-GCM rule packages from ShieldTier Cloud, 7-day TTL, decryption key derived from license + hardware
5. **Server-Side Crown Jewels** — Proprietary YARA rules, ML models, threat intel scoring run only on server; client sends feature vectors, never raw files

## V1 Context (ShieldTier V1 — Electron)

V1 is a separate repository. Key V1 workaround that V2 replaces:
- `src/main/fileanalysis/fetch-gateway.ts` — CDP `Fetch.requestPaused` interception
- Known Electron bugs motivating V2: #23594, #27768, #37491, #36261, #46048

V1 analysis subsystems being ported: PE capability analyzer, script detonation chamber, shellcode emulator, YARA engine (24 rules), heap forensics, static analyzers, hash enrichment (VT/AbuseIPDB/OTX/URLhaus/WHOIS), sandbox submission, email analysis, inline behavioral sandbox, network capture, VPN integration, config store, export.

## Implementation Phases

| Phase | Scope | Weeks |
|-------|-------|-------|
| A | CEF shell + native core + initial analysis ports | 1-6 |
| B | Remaining analysis engine migration | 7-12 |
| C | LLVM obfuscation integration | 13 |
| D | VMProtect integration | 14 |
| E | Encrypted rule delivery (cloud + client) | 15-16 |
| F | Server-side analysis API | 17-18 |
| G | Licensing + hardware binding | 19-20 |
| H | Anti-debug + integrity + encrypted pages | 21-22 |
| I | Renderer protection + final integration | 23 |

VM sandbox upgrade phases (VM-1 through VM-8) add ~20 weeks for agentless VMI, direct hypervisor integration, and anti-evasion.

## Key Dependencies

| Library | Purpose |
|---------|---------|
| CEF SDK | Browser embedding (Chromium) |
| libyara | YARA rule compilation and scanning |
| libsodium | Cryptography (ShieldCrypt E2E chat, rule decryption) |
| libcurl | HTTP client for enrichment providers |
| pe-parse | PE file analysis |
| libarchive | Archive handling |
| wabt | WebAssembly binary toolkit |
| BoringSSL | TLS (bundled with CEF) |

## Conventions

- C++ code uses snake_case for files and functions
- Native source paths mirror V1 TypeScript structure (e.g., `src/main/yara/` → `src/native/analysis/yara/`)
- IPC between native and renderer uses JSON messages via CefMessageRouter
- Silent corruption (not crashes) is the response to all tamper/debug detection
- Tier model: Free (local basic analysis) → Pro → Team → Enterprise (server-side scoring + custom rules)
