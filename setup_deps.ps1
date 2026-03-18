# =============================================================================
# ShieldTier V2 — Windows Dependency Setup
# Run: powershell -ExecutionPolicy Bypass -File setup_deps.ps1
# =============================================================================

$ErrorActionPreference = "Stop"
$ROOT = Split-Path -Parent $MyInvocation.MyCommand.Path
$THIRD_PARTY = Join-Path $ROOT "third_party"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host " ShieldTier V2 — Dependency Setup" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Create third_party directory
if (-not (Test-Path $THIRD_PARTY)) {
    New-Item -ItemType Directory -Path $THIRD_PARTY | Out-Null
}

# ---------------------------------------------------------------------------
# CEF SDK (Chromium Embedded Framework) — ~300MB
# ---------------------------------------------------------------------------
$CEF_DIR = Join-Path $THIRD_PARTY "cef"
$CEF_VERSION = "145.0.27+g4ddda2e+chromium-145.0.7632.117"
# CEF distributes as cef_binary_VERSION_PLATFORM
# URL pattern: https://cef-builds.spotifycdn.com/cef_binary_VERSION_windows64.tar.bz2
$CEF_URL = "https://cef-builds.spotifycdn.com/cef_binary_145.0.27%2Bg4ddda2e%2Bchromium-145.0.7632.117_windows64.tar.bz2"
$CEF_ARCHIVE = Join-Path $THIRD_PARTY "cef_windows64.tar.bz2"

if (-not (Test-Path (Join-Path $CEF_DIR "include"))) {
    Write-Host "[1/7] Downloading CEF SDK ($CEF_VERSION)..." -ForegroundColor Yellow
    Write-Host "       This is ~300MB, please wait..."

    # Try downloading
    try {
        Invoke-WebRequest -Uri $CEF_URL -OutFile $CEF_ARCHIVE -UseBasicParsing
    } catch {
        Write-Host "       Auto-download failed. Please download manually:" -ForegroundColor Red
        Write-Host "       1. Go to: https://cef-builds.spotifycdn.com/index.html" -ForegroundColor Red
        Write-Host "       2. Find version 145.0.27 for Windows 64-bit" -ForegroundColor Red
        Write-Host "       3. Download 'Standard Distribution'" -ForegroundColor Red
        Write-Host "       4. Extract to: $CEF_DIR" -ForegroundColor Red
        Write-Host ""
        Write-Host "       The extracted folder should contain: include/, Release/, Debug/, cmake/, CMakeLists.txt" -ForegroundColor Red
        $CEF_ARCHIVE = $null
    }

    if ($CEF_ARCHIVE -and (Test-Path $CEF_ARCHIVE)) {
        Write-Host "       Extracting..."
        # Need 7zip or tar to extract .tar.bz2
        if (Get-Command 7z -ErrorAction SilentlyContinue) {
            & 7z x $CEF_ARCHIVE -o"$THIRD_PARTY" -y | Out-Null
            $tarFile = $CEF_ARCHIVE -replace '\.bz2$', ''
            & 7z x $tarFile -o"$THIRD_PARTY" -y | Out-Null
            Remove-Item $tarFile -ErrorAction SilentlyContinue
        } elseif (Get-Command tar -ErrorAction SilentlyContinue) {
            & tar xjf $CEF_ARCHIVE -C "$THIRD_PARTY"
        } else {
            Write-Host "       Need 7zip or tar to extract. Install: winget install 7zip.7zip" -ForegroundColor Red
        }

        # Rename extracted folder to 'cef'
        $extracted = Get-ChildItem $THIRD_PARTY -Directory | Where-Object { $_.Name -like "cef_binary_*" } | Select-Object -First 1
        if ($extracted) {
            if (Test-Path $CEF_DIR) { Remove-Item $CEF_DIR -Recurse -Force }
            Rename-Item $extracted.FullName "cef"
        }
        Remove-Item $CEF_ARCHIVE -ErrorAction SilentlyContinue
        Write-Host "       Done." -ForegroundColor Green
    }
} else {
    Write-Host "[1/7] CEF SDK — already present" -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# nlohmann/json (header-only)
# ---------------------------------------------------------------------------
$JSON_DIR = Join-Path $THIRD_PARTY "nlohmann_json"
if (-not (Test-Path (Join-Path $JSON_DIR "include"))) {
    Write-Host "[2/7] Cloning nlohmann/json..." -ForegroundColor Yellow
    git clone --depth 1 --branch v3.11.3 https://github.com/nlohmann/json.git $JSON_DIR 2>&1 | Out-Null
    Write-Host "       Done." -ForegroundColor Green
} else {
    Write-Host "[2/7] nlohmann/json — already present" -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# pe-parse
# ---------------------------------------------------------------------------
$PE_DIR = Join-Path $THIRD_PARTY "pe-parse"
if (-not (Test-Path (Join-Path $PE_DIR "CMakeLists.txt"))) {
    Write-Host "[3/7] Cloning pe-parse..." -ForegroundColor Yellow
    git clone --depth 1 https://github.com/trailofbits/pe-parse.git $PE_DIR 2>&1 | Out-Null
    Write-Host "       Done." -ForegroundColor Green
} else {
    Write-Host "[3/7] pe-parse — already present" -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# curl
# ---------------------------------------------------------------------------
$CURL_DIR = Join-Path $THIRD_PARTY "curl"
if (-not (Test-Path (Join-Path $CURL_DIR "CMakeLists.txt"))) {
    Write-Host "[4/7] Cloning curl..." -ForegroundColor Yellow
    git clone --depth 1 --branch curl-8_11_1 https://github.com/curl/curl.git $CURL_DIR 2>&1 | Out-Null
    Write-Host "       Done." -ForegroundColor Green
} else {
    Write-Host "[4/7] curl — already present" -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# libarchive
# ---------------------------------------------------------------------------
$ARCHIVE_DIR = Join-Path $THIRD_PARTY "libarchive"
if (-not (Test-Path (Join-Path $ARCHIVE_DIR "CMakeLists.txt"))) {
    Write-Host "[5/7] Cloning libarchive..." -ForegroundColor Yellow
    git clone --depth 1 --branch v3.7.7 https://github.com/libarchive/libarchive.git $ARCHIVE_DIR 2>&1 | Out-Null
    Write-Host "       Done." -ForegroundColor Green
} else {
    Write-Host "[5/7] libarchive — already present" -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# libsodium
# ---------------------------------------------------------------------------
$SODIUM_DIR = Join-Path $THIRD_PARTY "libsodium"
if (-not (Test-Path (Join-Path $SODIUM_DIR "CMakeLists.txt")) -and -not (Test-Path (Join-Path $SODIUM_DIR "configure"))) {
    Write-Host "[6/7] Cloning libsodium..." -ForegroundColor Yellow
    git clone --depth 1 --branch 1.0.20-RELEASE https://github.com/jedisct1/libsodium.git $SODIUM_DIR 2>&1 | Out-Null
    Write-Host "       Done." -ForegroundColor Green
} else {
    Write-Host "[6/7] libsodium — already present" -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# wabt (WebAssembly Binary Toolkit) — optional
# ---------------------------------------------------------------------------
$WABT_DIR = Join-Path $THIRD_PARTY "wabt"
if (-not (Test-Path (Join-Path $WABT_DIR "CMakeLists.txt"))) {
    Write-Host "[7/7] Cloning wabt..." -ForegroundColor Yellow
    git clone --depth 1 --recurse-submodules https://github.com/WebAssembly/wabt.git $WABT_DIR 2>&1 | Out-Null
    Write-Host "       Done." -ForegroundColor Green
} else {
    Write-Host "[7/7] wabt — already present" -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# Node.js dependencies for renderer
# ---------------------------------------------------------------------------
$RENDERER_DIR = Join-Path $ROOT "src\renderer"
if (-not (Test-Path (Join-Path $RENDERER_DIR "node_modules"))) {
    Write-Host ""
    Write-Host "[+] Installing renderer npm dependencies..." -ForegroundColor Yellow
    Push-Location $RENDERER_DIR
    npm install 2>&1 | Out-Null
    Pop-Location
    Write-Host "    Done." -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Setup Complete!" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host " Next steps:" -ForegroundColor White
Write-Host "   mkdir build" -ForegroundColor Gray
Write-Host "   cd build" -ForegroundColor Gray
Write-Host '   cmake .. -G "Visual Studio 17 2022" -A x64' -ForegroundColor Gray
Write-Host "   cmake --build . --config Release" -ForegroundColor Gray
Write-Host ""

# Check for Visual Studio
$vsWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (Test-Path $vsWhere) {
    $vsPath = & $vsWhere -latest -property installationPath
    Write-Host " Visual Studio: $vsPath" -ForegroundColor Green
} else {
    Write-Host " WARNING: Visual Studio not found. Install VS2022 with 'Desktop development with C++'" -ForegroundColor Red
}
