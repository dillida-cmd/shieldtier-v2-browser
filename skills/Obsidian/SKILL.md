---
name: Obsidian
description: Use when hardening and packaging the final release — LLVM obfuscation (Polaris-Obfuscator CFF/MBA/BCF/string encryption), VMProtect post-link virtualization, code signing (Apple notarization, Windows Authenticode, Linux GPG), platform packaging (DMG/NSIS/AppImage), renderer protection (javascript-obfuscator), and integrity hash embedding
---

# S13 — Obsidian: Build Hardening & Release Packaging

## Overview

Final overlay agent. Applies LLVM obfuscation to all code, VMProtect virtualization to marked critical functions, code signing for all platforms, and platform-specific packaging. Also protects the React renderer with javascript-obfuscator.

## Dependencies

- **Requires:** ALL other agents complete — this is the last wave
- **Blocks:** Nothing — this is the final deliverable

## File Ownership

```
cmake/
  ObfuscationPasses.cmake  (fills in S0's stub — LLVM flags)
  VMProtect.cmake          (fills in S0's stub — post-link processing)
scripts/
  vmprotect-post-link.sh   (VMProtect CLI invocation)
  sign-and-package.sh      (code signing + packaging orchestration)
  embed-integrity-hashes.py (SHA-256 of code sections → read-only data)
vite.config.production.ts  (renderer build with javascript-obfuscator)
```

## Exit Criteria

Obfuscated + VMProtect'd + signed + notarized binary for macOS/Windows/Linux. Renderer protected with CFF + string encryption + self-defending. All analysis engines produce correct results after obfuscation. Performance benchmark: <2x overhead.

---

## LLVM Obfuscation (Polaris-Obfuscator)

Polaris-Obfuscator is the actively maintained successor to the dead O-LLVM/Hikari/Pluto projects.

### cmake/ObfuscationPasses.cmake

```cmake
option(ENABLE_OBFUSCATION "Enable LLVM obfuscation passes" OFF)

if(ENABLE_OBFUSCATION)
    # Polaris-Obfuscator clang++ replaces system clang
    set(OBFUSCATOR_ROOT "" CACHE PATH "Path to Polaris-Obfuscator installation")

    if(NOT OBFUSCATOR_ROOT)
        message(FATAL_ERROR "ENABLE_OBFUSCATION=ON but OBFUSCATOR_ROOT not set")
    endif()

    set(CMAKE_C_COMPILER "${OBFUSCATOR_ROOT}/bin/clang")
    set(CMAKE_CXX_COMPILER "${OBFUSCATOR_ROOT}/bin/clang++")

    # Obfuscation flags applied globally
    set(OBFUSCATION_FLAGS
        "-mllvm -fla"     # Control Flow Flattening
        "-mllvm -mba"     # Mixed Boolean Arithmetic
        "-mllvm -bcf"     # Bogus Control Flow
        "-mllvm -sobf"    # String Obfuscation (encrypts string literals)
        "-mllvm -sub"     # Instruction Substitution
    )

    string(REPLACE ";" " " OBFUSCATION_FLAGS_STR "${OBFUSCATION_FLAGS}")

    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OBFUSCATION_FLAGS_STR}")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OBFUSCATION_FLAGS_STR}")

    message(STATUS "LLVM obfuscation: ENABLED")
    message(STATUS "  Compiler: ${CMAKE_CXX_COMPILER}")
    message(STATUS "  Flags: ${OBFUSCATION_FLAGS_STR}")
endif()
```

### Per-Function Annotation (Optional Granularity)

```cpp
// Fine-grained control: annotate specific functions
// Useful for excluding hot loops from expensive obfuscation

__attribute__((annotate("fla")))     // only CFF on this function
void sensitive_function() { }

__attribute__((annotate("nobcf")))   // skip BCF on this function
void hot_loop() { }
```

## VMProtect Post-Link Processing

### cmake/VMProtect.cmake

```cmake
option(ENABLE_VMPROTECT "Enable VMProtect post-link processing" OFF)

if(ENABLE_VMPROTECT)
    set(VMPROTECT_ROOT "" CACHE PATH "Path to VMProtect SDK")
    set(VMPROTECT_LICENSE "" CACHE STRING "VMProtect license key")

    if(NOT VMPROTECT_ROOT)
        message(FATAL_ERROR "ENABLE_VMPROTECT=ON but VMPROTECT_ROOT not set")
    endif()

    function(vmprotect_post_link TARGET)
        add_custom_command(TARGET ${TARGET} POST_BUILD
            COMMAND ${CMAKE_SOURCE_DIR}/scripts/vmprotect-post-link.sh
                "$<TARGET_FILE:${TARGET}>"
                "${VMPROTECT_ROOT}"
            COMMENT "Applying VMProtect to ${TARGET}"
        )
    endfunction()
else()
    function(vmprotect_post_link TARGET)
        # No-op when VMProtect disabled
    endfunction()
endif()
```

### VMProtect SDK Integration in Code

```cpp
// Include VMProtect SDK header
#ifdef ENABLE_VMPROTECT
    #include <VMProtectSDK.h>
#else
    // Stubs when VMProtect not available
    #define VMProtectBeginUltra(name)
    #define VMProtectEnd()
    #define VMProtectBeginMutation(name)
    #define VMProtectBeginVirtualization(name)
#endif

// Usage in scoring engine:
int threat_score_compute(const std::vector<Finding>& findings) {
    VMProtectBeginUltra("threat_score_compute");

    // ... scoring algorithm ...
    // This entire function will be virtualized by VMProtect
    // Each build gets unique VM bytecode + unique opcode mapping

    VMProtectEnd();
    return score;
}

// Different protection levels:
// VMProtectBeginUltra()          — Maximum: virtualization + mutation (10-50x slower)
// VMProtectBeginVirtualization() — Virtualization only (5-20x slower)
// VMProtectBeginMutation()       — Code mutation only (2-5x slower)
```

### scripts/vmprotect-post-link.sh

```bash
#!/usr/bin/env bash
set -euo pipefail

BINARY="$1"
VMPROTECT_ROOT="$2"
VMPROTECT_CLI="${VMPROTECT_ROOT}/bin/VMProtect"

if [ ! -f "$VMPROTECT_CLI" ]; then
    echo "VMProtect CLI not found at $VMPROTECT_CLI"
    exit 1
fi

# Create VMProtect project file
PROJECT="${BINARY}.vmp"
cat > "$PROJECT" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<VMProtect version="3.0">
  <InputFile>${BINARY}</InputFile>
  <OutputFile>${BINARY}.protected</OutputFile>
  <Options>
    <StripDebugInfo>true</StripDebugInfo>
    <DetectDebugger>false</DetectDebugger>
    <!-- Our anti-debug mesh handles this -->
  </Options>
</VMProtect>
EOF

# Run VMProtect
"$VMPROTECT_CLI" "$PROJECT"

# Replace original with protected
mv "${BINARY}.protected" "$BINARY"
rm -f "$PROJECT"

echo "VMProtect applied to $BINARY"
```

## Code Signing

### macOS: Apple Notarization

```bash
#!/usr/bin/env bash
# sign-macos.sh

APP_BUNDLE="$1"
IDENTITY="Developer ID Application: ShieldTier Inc (TEAMID)"
ENTITLEMENTS="entitlements.plist"

# Sign all frameworks and helpers first (inside-out)
codesign --force --options runtime --timestamp \
    --sign "$IDENTITY" \
    --entitlements "$ENTITLEMENTS" \
    "${APP_BUNDLE}/Contents/Frameworks/Chromium Embedded Framework.framework"

# Sign helper executables
for helper in "${APP_BUNDLE}/Contents/Frameworks/"*.app; do
    codesign --force --options runtime --timestamp \
        --sign "$IDENTITY" "$helper"
done

# Sign the main app bundle
codesign --force --options runtime --timestamp \
    --sign "$IDENTITY" \
    --entitlements "$ENTITLEMENTS" \
    "$APP_BUNDLE"

# Verify
codesign --verify --deep --strict "$APP_BUNDLE"

# Notarize
xcrun notarytool submit "$APP_BUNDLE" \
    --apple-id "$APPLE_ID" \
    --password "$APP_SPECIFIC_PASSWORD" \
    --team-id "$TEAM_ID" \
    --wait

# Staple
xcrun stapler staple "$APP_BUNDLE"

# Create DMG (universal binary)
hdiutil create -volname "ShieldTier" \
    -srcfolder "$APP_BUNDLE" \
    -ov -format UDZO \
    "ShieldTier-$(cat VERSION).dmg"
```

### Entitlements

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "...">
<plist version="1.0">
<dict>
    <key>com.apple.security.app-sandbox</key>
    <true/>
    <key>com.apple.security.network.client</key>
    <true/>
    <key>com.apple.security.hypervisor</key>
    <true/>
    <key>com.apple.security.cs.allow-unsigned-executable-memory</key>
    <true/>
</dict>
</plist>
```

### Windows: Authenticode

```bash
# sign-windows.sh
signtool sign /f "shieldtier-ev.pfx" /p "$PFX_PASSWORD" \
    /tr http://timestamp.digicert.com /td sha256 \
    /fd sha256 \
    "ShieldTier.exe"

# Verify
signtool verify /pa "ShieldTier.exe"
```

### Linux: GPG Signature

```bash
gpg --armor --detach-sign --default-key "$GPG_KEY_ID" ShieldTier.AppImage
```

## Platform Packaging

### macOS: .app Bundle → DMG

Already handled by CMake (MACOSX_BUNDLE) + signing script above.

### Windows: NSIS Installer

```nsis
!include "MUI2.nsh"

Name "ShieldTier"
OutFile "ShieldTier-Setup.exe"
InstallDir "$PROGRAMFILES64\ShieldTier"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "LICENSE.txt"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

Section "Install"
    SetOutPath "$INSTDIR"
    File "ShieldTier.exe"
    File "*.dll"
    File /r "locales"
    File /r "renderer"
    File "icudtl.dat"
    File "v8_context_snapshot.bin"

    CreateShortCut "$DESKTOP\ShieldTier.lnk" "$INSTDIR\ShieldTier.exe"
    CreateShortCut "$SMPROGRAMS\ShieldTier\ShieldTier.lnk" "$INSTDIR\ShieldTier.exe"

    WriteUninstaller "$INSTDIR\Uninstall.exe"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ShieldTier" \
        "DisplayName" "ShieldTier"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ShieldTier" \
        "UninstallString" "$INSTDIR\Uninstall.exe"
SectionEnd

Section "Uninstall"
    Delete "$INSTDIR\*.*"
    RMDir /r "$INSTDIR"
    Delete "$DESKTOP\ShieldTier.lnk"
    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ShieldTier"
SectionEnd
```

### Linux: AppImage

```bash
# Build AppImage using linuxdeploy
linuxdeploy \
    --appdir AppDir \
    --executable build/shieldtier \
    --desktop-file shieldtier.desktop \
    --icon-file shieldtier.png \
    --output appimage

# The AppDir structure:
# AppDir/
#   usr/bin/shieldtier
#   usr/lib/libcef.so
#   usr/share/shieldtier/renderer/
#   usr/share/shieldtier/locales/
#   usr/share/shieldtier/icudtl.dat
```

## Renderer Protection (javascript-obfuscator)

### vite.config.production.ts

```typescript
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import JavaScriptObfuscator from 'javascript-obfuscator';

export default defineConfig({
  plugins: [
    react(),
    {
      name: 'javascript-obfuscator',
      enforce: 'post',
      generateBundle(options, bundle) {
        for (const [fileName, chunk] of Object.entries(bundle)) {
          if (chunk.type === 'chunk' && fileName.endsWith('.js')) {
            const obfuscated = JavaScriptObfuscator.obfuscate(chunk.code, {
              compact: true,
              controlFlowFlattening: true,
              controlFlowFlatteningThreshold: 0.75,
              deadCodeInjection: true,
              deadCodeInjectionThreshold: 0.4,
              debugProtection: true,
              debugProtectionInterval: 2000,
              disableConsoleOutput: true,
              identifierNamesGenerator: 'hexadecimal',
              log: false,
              numbersToExpressions: true,
              renameGlobals: false,
              selfDefending: true,
              simplify: true,
              splitStrings: true,
              splitStringsChunkLength: 10,
              stringArray: true,
              stringArrayCallsTransform: true,
              stringArrayEncoding: ['rc4'],
              stringArrayIndexShift: true,
              stringArrayRotate: true,
              stringArrayShuffle: true,
              stringArrayWrappersCount: 2,
              stringArrayWrappersChainedCalls: true,
              stringArrayWrappersParametersMaxCount: 4,
              stringArrayWrappersType: 'function',
              stringArrayThreshold: 0.75,
              transformObjectKeys: true,
              unicodeEscapeSequence: false,
            });
            chunk.code = obfuscated.getObfuscatedCode();
          }
        }
      },
    },
  ],
  root: 'src/renderer',
  build: {
    outDir: '../../dist/renderer',
    emptyDirOnBuild: true,
    minify: 'terser',
  },
  base: './',
});
```

## Integrity Hash Embedding

```python
#!/usr/bin/env python3
# scripts/embed-integrity-hashes.py
# Run after compilation, before VMProtect

import hashlib
import struct
import sys

def hash_text_section(binary_path):
    """Extract and hash .text section of the binary."""
    with open(binary_path, 'rb') as f:
        data = f.read()

    # Find .text section (platform-specific parsing)
    # For ELF: parse section headers
    # For Mach-O: parse load commands
    # For PE: parse section table

    text_hash = hashlib.sha256(text_section_data).digest()
    return text_hash

def embed_hash(binary_path, hash_bytes):
    """Replace placeholder in .rodata with actual hash."""
    # The C++ code has: static const uint8_t expected_text_hash[32] = { 0 };
    # Find this 32-byte zero block in .rodata and replace with actual hash
    pass

if __name__ == '__main__':
    binary = sys.argv[1]
    h = hash_text_section(binary)
    embed_hash(binary, h)
    print(f"Embedded integrity hash: {h.hex()}")
```

## Build Pipeline Order

```
1. cmake -G Ninja -DENABLE_OBFUSCATION=ON -DOBFUSCATOR_ROOT=... ..
2. ninja                              (compile with LLVM obfuscation)
3. scripts/embed-integrity-hashes.py  (hash .text section → embed in .rodata)
4. scripts/vmprotect-post-link.sh     (virtualize marked functions)
5. scripts/sign-and-package.sh        (code sign + package)
```

## Common Mistakes

| Mistake | Fix |
|---------|-----|
| Running VMProtect before integrity hash embedding | Must hash first, then VMProtect (VMProtect changes the code) |
| Obfuscating third-party libraries | Only obfuscate src/native/ — exclude CEF, libyara, libsodium |
| Not testing correctness after obfuscation | Full test suite must pass after every obfuscation level |
| macOS: signing before notarization | Sign → notarize → staple (order matters) |
| macOS: not signing inside-out | Sign frameworks first, then helpers, then main app |
| VMProtect Ultra on hot paths | 10-50x overhead — only use on security-critical, non-hot code |
| javascript-obfuscator self-defending breaks debugging | Only enable in production builds, not dev |
| NSIS: not including CEF resources | CEF needs icudtl.dat, v8_context_snapshot.bin, locales/ at runtime |
| Polaris-Obfuscator version mismatch | Pin exact Polaris version — different versions produce different output |
