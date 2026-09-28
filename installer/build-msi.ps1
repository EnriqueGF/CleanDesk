<#
.SYNOPSIS
  Build CleanDesk.msi with the WiX 3.x toolset.

.DESCRIPTION
  1. cargo build --release (app, signal server, relay) into ./target/release
     (the local .cargo/config.toml may redirect target-dir; pass -TargetDir).
  2. candle + light on installer/cleandesk.wxs.

  WiX is located from -WixBin, $env:WIX_BIN, or "wix314\" next to this script.
  Portable binaries: https://github.com/wixtoolset/wix3/releases (wix314-binaries.zip).

.EXAMPLE
  .\installer\build-msi.ps1
  .\installer\build-msi.ps1 -WixBin C:\tools\wix314 -TargetDir F:\cleandesk-target
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
    $args = @("build", "--release", "-p", "cleandesk-app", "-p", "cleandesk-signal-server", "-p", "cleandesk-relay-server")
    if ($TargetDir) { $args += @("--target-dir", $TargetDir) }
    & cargo @args
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }
}

# Stage binaries where the .wxs expects them (target\release under the repo).
$release = Join-Path $root "target\release"
New-Item -ItemType Directory -Force $release | Out-Null
$src = if ($TargetDir) { Join-Path $TargetDir "release" } else { $release }
foreach ($exe in "cleandesk.exe", "cleandesk-signal-server.exe", "cleandesk-relay-server.exe") {
    $from = Join-Path $src $exe
    if (-not (Test-Path $from)) { throw "missing $from" }
    if ($from -ne (Join-Path $release $exe)) { Copy-Item $from $release -Force }
}

$out = Join-Path $root "target\msi"
New-Item -ItemType Directory -Force $out | Out-Null
$obj = Join-Path $out "cleandesk.wixobj"
$msi = Join-Path $out "CleanDesk-$Version-x64.msi"

Write-Host "== candle" -ForegroundColor Cyan
& $candle -nologo -arch x64 -ext WixFirewallExtension -ext WixUIExtension `
    "-dVersion=$Version" "-dSourceDir=$root" `
    -out $obj (Join-Path $PSScriptRoot "cleandesk.wxs")
if ($LASTEXITCODE -ne 0) { throw "candle failed" }

Write-Host "== light" -ForegroundColor Cyan
& $light -nologo -ext WixFirewallExtension -ext WixUIExtension -cultures:es-ES `
    -sice:ICE61 -out $msi $obj
if ($LASTEXITCODE -ne 0) { throw "light failed" }

Write-Host "MSI: $msi" -ForegroundColor Green
