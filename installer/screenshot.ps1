<#
.SYNOPSIS
  Launch cleandesk.exe with a scratch data dir and capture its main window to a PNG.
  Used to refresh docs/screenshots/*.png.
#>
param(
    [string]$Exe = "D:\cleandesk-target\release\cleandesk.exe",
    [string]$Out = "docs\screenshots\main-window.png",
    [string]$DataDir = "$env:TEMP\cleandesk-shot",
    [int]$WaitSeconds = 12
)
$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Drawing
Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class Win {
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int L, T, R, B; }
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int cmd);
  [DllImport("dwmapi.dll")] public static extern int DwmGetWindowAttribute(IntPtr h, int attr, out RECT r, int size);
}
"@
$p = Start-Process -FilePath $Exe -ArgumentList "--data-dir", $DataDir -PassThru
try {
    Start-Sleep -Seconds $WaitSeconds
    $p.Refresh()
    $h = $p.MainWindowHandle
    if ($h -eq [IntPtr]::Zero) { throw "no main window" }
    [Win]::ShowWindow($h, 9) | Out-Null
    [Win]::SetForegroundWindow($h) | Out-Null
    Start-Sleep -Milliseconds 800
    $r = New-Object Win+RECT
    # DWMWA_EXTENDED_FRAME_BOUNDS = 9: excludes the invisible resize borders.
    if ([Win]::DwmGetWindowAttribute($h, 9, [ref]$r, 16) -ne 0) { [Win]::GetWindowRect($h, [ref]$r) | Out-Null }
    $w = $r.R - $r.L; $hgt = $r.B - $r.T
    $bmp = New-Object System.Drawing.Bitmap($w, $hgt)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.CopyFromScreen($r.L, $r.T, 0, 0, (New-Object System.Drawing.Size($w, $hgt)))
    $g.Dispose()
    New-Item -ItemType Directory -Force (Split-Path $Out) | Out-Null
    $bmp.Save((Resolve-Path (Split-Path $Out)).Path + "\" + (Split-Path $Out -Leaf), [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Host "saved $Out ($w x $hgt)"
} finally {
    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
}
