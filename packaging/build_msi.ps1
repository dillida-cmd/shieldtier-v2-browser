# =============================================================================
# ShieldTier V2 — Windows MSI Builder
# Usage: powershell -ExecutionPolicy Bypass -File packaging\build_msi.ps1
# Requires: WiX Toolset v4+ (dotnet tool install --global wix)
# Output: packaging\dist\ShieldTier-2.0.0-windows-x64-setup.msi
# =============================================================================

$ErrorActionPreference = "Stop"
$ROOT = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$VERSION = "2.0.0"
$ARCH = "x64"
$APP_NAME = "ShieldTier"
$DIST_DIR = Join-Path $ROOT "packaging\dist"
$BUILD_DIR = Join-Path $ROOT "build"
$RELEASE_DIR = Join-Path $BUILD_DIR "src\native\Release"

Write-Host "=======================================" -ForegroundColor Cyan
Write-Host " ShieldTier MSI Builder" -ForegroundColor Cyan
Write-Host " Version: $VERSION" -ForegroundColor Cyan
Write-Host " Arch:    $ARCH" -ForegroundColor Cyan
Write-Host "=======================================" -ForegroundColor Cyan

# 1. Verify build exists
if (-not (Test-Path (Join-Path $RELEASE_DIR "shieldtier.exe"))) {
    Write-Host "[1/4] Building Release..." -ForegroundColor Yellow
    Push-Location $BUILD_DIR
    cmake --build . --config Release -- /p:DefineConstants=NDEBUG
    Pop-Location
}

# Check for WiX
if (-not (Get-Command "wix" -ErrorAction SilentlyContinue)) {
    Write-Host "WiX Toolset not found. Installing..." -ForegroundColor Yellow
    dotnet tool install --global wix
}

# 2. Collect files
Write-Host "[2/4] Collecting release files..." -ForegroundColor Yellow
$STAGING = Join-Path $ROOT "packaging\staging_msi"
if (Test-Path $STAGING) { Remove-Item -Recurse -Force $STAGING }
New-Item -ItemType Directory -Path $STAGING | Out-Null

# Copy main exe and all DLLs/resources from Release
Copy-Item "$RELEASE_DIR\*" -Destination $STAGING -Recurse -Force

# Copy renderer dist
$RENDERER_DEST = Join-Path $STAGING "renderer"
New-Item -ItemType Directory -Path $RENDERER_DEST -Force | Out-Null
Copy-Item (Join-Path $ROOT "src\renderer\dist\*") -Destination $RENDERER_DEST -Recurse -Force
Copy-Item (Join-Path $ROOT "src\renderer\shim\preload-shim.js") -Destination $RENDERER_DEST -Force

# 3. Generate WiX source
Write-Host "[3/4] Generating MSI..." -ForegroundColor Yellow
$WXS_PATH = Join-Path $ROOT "packaging\shieldtier.wxs"

# Generate component list from ALL files in staging dir
$GUID_UPGRADE = "7B2D4F5E-8A1C-4D3E-9F6B-1A2B3C4D5E6F"

# Collect all files and build WiX components dynamically
$allFiles = Get-ChildItem -Path $STAGING -Recurse -File
$components = ""
$directories = @{}
$fileIndex = 0

foreach ($file in $allFiles) {
    $fileIndex++
    $relPath = $file.FullName.Substring($STAGING.Length + 1)
    $relDir = Split-Path $relPath -Parent
    $compId = "Comp_$fileIndex"
    $fileId = "File_$fileIndex"
    $dirId = "INSTALLFOLDER"

    # Map subdirectories
    if ($relDir) {
        $dirId = "Dir_" + ($relDir -replace '[\\/ .\-]', '_')
        if (-not $directories.ContainsKey($relDir)) {
            $directories[$relDir] = $dirId
        }
    }

    $sourcePath = $file.FullName
    $components += "      <Component Id=`"$compId`" Directory=`"$dirId`" Guid=`"*`">`n"
    $components += "        <File Id=`"$fileId`" Source=`"$sourcePath`" KeyPath=`"yes`" />`n"
    $components += "      </Component>`n"
}

# Build nested directory tree — WiX requires children inside parents
# Use StandardDirectory + nested Directory elements
function Build-DirTree($dirs) {
    # Build a tree structure: parent -> children
    $tree = @{}  # parentPath -> @(childName, childPath, childId)
    $allPaths = @{}

    $sorted = $dirs.Keys | Sort-Object
    foreach ($dir in $sorted) {
        $parts = $dir -split '\\'
        for ($i = 0; $i -lt $parts.Length; $i++) {
            $partial = ($parts[0..$i] -join '\')
            if ($allPaths.ContainsKey($partial)) { continue }

            $thisName = $parts[$i]
            $thisId = if ($dirs.ContainsKey($partial)) { $dirs[$partial] } else { "Dir_" + ($partial -replace '[\\/ .\-]', '_') }
            if (-not $dirs.ContainsKey($partial)) { $dirs[$partial] = $thisId }
            $allPaths[$partial] = $thisId

            $parentPath = if ($i -eq 0) { "" } else { ($parts[0..($i-1)] -join '\') }
            if (-not $tree.ContainsKey($parentPath)) { $tree[$parentPath] = @() }
            $tree[$parentPath] += ,@($thisName, $partial, $thisId)
        }
    }

    # Recursive XML generation
    function Render-Children($parentPath, $indent) {
        $xml = ""
        if ($tree.ContainsKey($parentPath)) {
            foreach ($child in $tree[$parentPath]) {
                $name = $child[0]
                $path = $child[1]
                $id = $child[2]
                $childXml = Render-Children $path "$indent  "
                if ($childXml) {
                    $xml += "${indent}<Directory Id=`"$id`" Name=`"$name`">`n"
                    $xml += $childXml
                    $xml += "${indent}</Directory>`n"
                } else {
                    $xml += "${indent}<Directory Id=`"$id`" Name=`"$name`" />`n"
                }
            }
        }
        return $xml
    }

    return Render-Children "" "        "
}

$dirXml = Build-DirTree $directories

Write-Host "  Packaging $fileIndex files..." -ForegroundColor Gray

$wxsContent = @"
<?xml version="1.0" encoding="UTF-8"?>
<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs">
  <Package Name="ShieldTier" Version="$VERSION" Manufacturer="ShieldTier"
           UpgradeCode="$GUID_UPGRADE" Compressed="yes"
           InstallerVersion="500" Scope="perMachine">

    <MajorUpgrade DowngradeErrorMessage="A newer version of ShieldTier is already installed." />
    <MediaTemplate EmbedCab="yes" />

    <StandardDirectory Id="ProgramFiles64Folder">
      <Directory Id="INSTALLFOLDER" Name="ShieldTier">
$dirXml
      </Directory>
    </StandardDirectory>

    <ComponentGroup Id="ProductComponents">
$components
    </ComponentGroup>

    <!-- Desktop shortcut -->
    <StandardDirectory Id="DesktopFolder">
      <Component Id="DesktopShortcut" Guid="*">
        <Shortcut Id="DesktopShortcut" Name="ShieldTier" Target="[INSTALLFOLDER]shieldtier.exe"
                  WorkingDirectory="INSTALLFOLDER" Icon="ShieldTierIcon.exe" />
        <RegistryValue Root="HKCU" Key="Software\ShieldTier" Name="DesktopShortcut"
                       Type="integer" Value="1" KeyPath="yes" />
      </Component>
    </StandardDirectory>

    <!-- Start Menu shortcut -->
    <StandardDirectory Id="ProgramMenuFolder">
      <Directory Id="ProgramMenuDir" Name="ShieldTier">
        <Component Id="StartMenuShortcut" Guid="*">
          <Shortcut Id="StartMenuShortcut" Name="ShieldTier" Target="[INSTALLFOLDER]shieldtier.exe"
                    WorkingDirectory="INSTALLFOLDER" Icon="ShieldTierIcon.exe" />
          <RemoveFolder Id="ProgramMenuDir" On="uninstall" />
          <RegistryValue Root="HKCU" Key="Software\ShieldTier" Name="StartMenuShortcut"
                         Type="integer" Value="1" KeyPath="yes" />
        </Component>
      </Directory>
    </StandardDirectory>

    <Icon Id="ShieldTierIcon.exe" SourceFile="$STAGING\shieldtier.exe" />

    <Feature Id="ProductFeature" Title="ShieldTier" Level="1">
      <ComponentGroupRef Id="ProductComponents" />
      <ComponentRef Id="DesktopShortcut" />
      <ComponentRef Id="StartMenuShortcut" />
    </Feature>
  </Package>
</Wix>
"@

$wxsContent | Out-File -FilePath $WXS_PATH -Encoding UTF8

New-Item -ItemType Directory -Path $DIST_DIR -Force | Out-Null
$MSI_PATH = Join-Path $DIST_DIR "${APP_NAME}-${VERSION}-windows-${ARCH}-setup.msi"

try {
    wix build $WXS_PATH -o $MSI_PATH -arch x64
    Write-Host ""
    Write-Host "=======================================" -ForegroundColor Green
    Write-Host " MSI created: $MSI_PATH" -ForegroundColor Green
    $msiSize = (Get-Item $MSI_PATH).Length / 1MB
    Write-Host (" Size: {0:N1} MB" -f $msiSize) -ForegroundColor Green
    Write-Host "=======================================" -ForegroundColor Green
} catch {
    Write-Host "WiX build failed. Falling back to ZIP package..." -ForegroundColor Yellow
    $ZIP_PATH = Join-Path $DIST_DIR "${APP_NAME}-${VERSION}-windows-${ARCH}.zip"
    Compress-Archive -Path "$STAGING\*" -DestinationPath $ZIP_PATH -Force
    Write-Host "ZIP created: $ZIP_PATH" -ForegroundColor Green
}

# 4. Cleanup
Write-Host "[4/4] Cleanup..." -ForegroundColor Yellow
Remove-Item -Recurse -Force $STAGING -ErrorAction SilentlyContinue
Remove-Item $WXS_PATH -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "Done." -ForegroundColor Green
