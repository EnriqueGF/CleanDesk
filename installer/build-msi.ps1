<#
.SYNOPSIS
  Build RotoDesk.msi with the WiX 3.x toolset.

.DESCRIPTION
  1. cargo build --release (app, signal server, relay) into ./target/release
     (the local .cargo/config.toml may redirect target-dir; pass -TargetDir).
  2. candle + light on installer/rotodesk.wxs.

  WiX is located from -WixBin, $env:WIX_BIN, or "wix314\" next to this script.
  Portable binaries: https://github.com/wixtoolset/wix3/releases (wix314-binaries.zip).

.EXAMPLE
  .\installer\build-msi.ps1
  .\installer\build-msi.ps1 -WixBin C:\tools\wix314 -TargetDir F:\rotodesk-target
#>
[CmdletBinding()]
param(
    [string]$WixBin = $env:WIX_BIN,
    [string]$TargetDir = "",
    [string]$Version = "",
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"
$root = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $root

if (-not $WixBin) { $WixBin = Join-Path $PSScriptRoot "wix314" }
$candle = Join-Path $WixBin "candle.exe"
$light  = Join-Path $WixBin "light.exe"
if (-not (Test-Path $candle)) { throw "WiX not found at $WixBin (candle.exe missing). Set -WixBin or WIX_BIN." }

if (-not $Version) {
    $Version = (Select-String -Path "$root\Cargo.toml" -Pattern '^version\s*=\s*"([^"]+)"' | Select-Object -First 1).Matches[0].Groups[1].Value
}
# MSI versions are numeric x.y.z; strip any pre-release suffix.
$Version = ($Version -split '-')[0]

if (-not $SkipBuild) {
    Write-Host "== cargo build --release" -ForegroundColor Cyan
    $args = @("build", "--release", "-p", "rotodesk-app", "-p", "rotodesk-signal-server", "-p", "rotodesk-relay-server")
    if ($TargetDir) { $args += @("--target-dir", $TargetDir) }
    & cargo @args
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }
}

# Stage binaries where the .wxs expects them (target\release under the repo).
$release = Join-Path $root "target\release"
New-Item -ItemType Directory -Force $release | Out-Null
$src = if ($TargetDir) { Join-Path $TargetDir "release" } else { $release }
foreach ($exe in "rotodesk.exe", "rotodesk-signal-server.exe", "rotodesk-relay-server.exe") {
    $from = Join-Path $src $exe
    if (-not (Test-Path $from)) { throw "missing $from" }
    if ($from -ne (Join-Path $release $exe)) { Copy-Item $from $release -Force }
}

$out = Join-Path $root "target\msi"
New-Item -ItemType Directory -Force $out | Out-Null
$obj = Join-Path $out "rotodesk.wixobj"
$msi = Join-Path $out "RotoDesk-$Version-x64.msi"

Write-Host "== candle" -ForegroundColor Cyan
& $candle -nologo -arch x64 -ext WixFirewallExtension -ext WixUIExtension -ext WixUtilExtension `
    "-dVersion=$Version" "-dSourceDir=$root" `
    -out $obj (Join-Path $PSScriptRoot "rotodesk.wxs")
if ($LASTEXITCODE -ne 0) { throw "candle failed" }

Write-Host "== light" -ForegroundColor Cyan
& $light -nologo -ext WixFirewallExtension -ext WixUIExtension -ext WixUtilExtension -cultures:en-US `
    -sice:ICE61 -out $msi $obj
if ($LASTEXITCODE -ne 0) { throw "light failed" }

# Portable application and server binaries, matching the installer build.
Copy-Item -LiteralPath (Join-Path $root "crates\gui\assets\BRAND.txt"), (Join-Path $root "crates\gui\assets\fonts\OFL-BarlowCondensed.txt") -Destination $release -Force
$zip = Join-Path $out "RotoDesk-$Version-x64-binaries.zip"
Compress-Archive -Path (Join-Path $release "rotodesk.exe"), (Join-Path $release "rotodesk-signal-server.exe"), (Join-Path $release "rotodesk-relay-server.exe"), (Join-Path $release "BRAND.txt"), (Join-Path $release "OFL-BarlowCondensed.txt") -DestinationPath $zip -Force

# Checksums the in-app updater verifies against (one line per release file).
# Older updaters select an exact installer name. This identical alias is only
# an upgrade bridge; the MSI installs RotoDesk and preserves the UpgradeCode.
$legacyProduct = "CleanDesk"
$upgradeBridge = Join-Path $out "$legacyProduct-$Version-x64.msi"
Copy-Item -LiteralPath $msi -Destination $upgradeBridge -Force
$sums = Join-Path $out "SHA256SUMS"
$lines = @()
foreach ($f in (Get-Item -LiteralPath $msi, $zip, $upgradeBridge)) {
    $h = (Get-FileHash -Algorithm SHA256 $f.FullName).Hash.ToLowerInvariant()
    $lines += "$h *$($f.Name)"
}
[IO.File]::WriteAllText($sums, ($lines -join "`n") + "`n")
Write-Host "MSI: $msi" -ForegroundColor Green
Write-Host "SUMS: $sums" -ForegroundColor Green
