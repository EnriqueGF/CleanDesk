<#
.SYNOPSIS
  Capture RotoDesk's own framebuffer using a debug build, without capturing other windows.
#>
param(
    [string]$Exe = "D:\rotodesk-target\debug\rotodesk.exe",
    [string]$Out = "docs\screenshots\main-window.png",
    [string]$DataDir = "$env:TEMP\rotodesk-shot",
    [int]$WaitSeconds = 15,
    [int]$Width = 960,
    [int]$Height = 740,
    [switch]$Maximized,
    [switch]$Settings,
    [switch]$Showcase,
    [switch]$Request,
    [int]$Section = 0,
    [string]$Connect = ""
)
$ErrorActionPreference = "Stop"
$folder = [IO.Path]::GetFullPath((Split-Path $Out))
New-Item -ItemType Directory -Force $folder | Out-Null
$destination = Join-Path $folder (Split-Path $Out -Leaf)
$vars = @{
    ROTODESK_SCREENSHOT = $destination
    ROTODESK_PREVIEW_SIZE = "$Width,$Height"
    ROTODESK_PREVIEW_MAXIMIZED = $(if ($Maximized) { "1" } else { $null })
    ROTODESK_OPEN_SETTINGS = $(if ($Settings) { "1" } else { $null })
    ROTODESK_SETTINGS_SECTION = "$Section"
    ROTODESK_SHOWCASE = $(if ($Showcase) { "1" } else { $null })
    ROTODESK_PREVIEW_REQUEST = $(if ($Request) { "1" } else { $null })
}
$previous = @{}
$p = $null
try {
    foreach ($key in $vars.Keys) {
        $previous[$key] = [Environment]::GetEnvironmentVariable($key, "Process")
        [Environment]::SetEnvironmentVariable($key, $vars[$key], "Process")
    }
    $arguments = @("--data-dir", $DataDir)
    if ($Connect) { $arguments += @("--connect", $Connect) }
    $p = Start-Process -FilePath $Exe -ArgumentList $arguments -WindowStyle Hidden -PassThru
    if (-not $p.WaitForExit($WaitSeconds * 1000)) { throw "framebuffer capture timed out (use a debug build)" }
    if ($p.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $destination)) { throw "capture failed" }
    Write-Host "saved $destination"
} finally {
    if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
    foreach ($key in $previous.Keys) { [Environment]::SetEnvironmentVariable($key, $previous[$key], "Process") }
}
