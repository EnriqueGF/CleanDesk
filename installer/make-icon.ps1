<#
.SYNOPSIS
  Package the generated RotoDesk logo as transparent PNGs and a multi-size Windows ICO.
#>
[CmdletBinding()]
param(
    [int[]]$Sizes = @(16,24,32,48,64,128,256),
    [string]$IcoPath = "",
    [string]$AssetsDir = "",
    [string]$PreviewPath = "",
    [bool]$Preview = $true
)
$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Drawing
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
if (-not $AssetsDir) { $AssetsDir = Join-Path $root "crates\gui\assets" }
if (-not $IcoPath) { $IcoPath = Join-Path $PSScriptRoot "rotodesk.ico" }
if (-not $PreviewPath) { $PreviewPath = Join-Path $PSScriptRoot "icon-preview.png" }
$DetailThreshold = 0
$source = [System.Drawing.Image]::FromFile((Join-Path $AssetsDir "logo.png"))
function Render-Icon([int]$px, [bool]$detail) {
    $out = New-Object System.Drawing.Bitmap $px, $px, ([System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [System.Drawing.Graphics]::FromImage($out)
    $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $g.Clear([System.Drawing.Color]::Transparent)
    $g.DrawImage($source, (New-Object System.Drawing.Rectangle 0, 0, $px, $px))
    $g.Dispose()
    return $out
}

function Get-PngBytes([System.Drawing.Bitmap]$bmp) {
    $ms = New-Object System.IO.MemoryStream
    $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    $bytes = $ms.ToArray(); $ms.Dispose()
    # Comma operator: keep the byte[] intact instead of unrolling it.
    return ,$bytes
}

# ICO container: ICONDIR + ICONDIRENTRY[] + PNG blobs (Vista+ format).
function Write-Ico([string]$path, [hashtable]$pngBySize) {
    $sizes = @($pngBySize.Keys | Sort-Object)
    $ms = New-Object System.IO.MemoryStream
    $bw = New-Object System.IO.BinaryWriter $ms
    $bw.Write([uint16]0); $bw.Write([uint16]1); $bw.Write([uint16]$sizes.Count)
    $offset = 6 + 16 * $sizes.Count
    foreach ($s in $sizes) {
        [byte[]]$data = $pngBySize[$s]
        $bw.Write([byte]($(if ($s -ge 256) { 0 } else { $s })))   # width  (0 = 256)
        $bw.Write([byte]($(if ($s -ge 256) { 0 } else { $s })))   # height
        $bw.Write([byte]0)                                         # palette
        $bw.Write([byte]0)                                         # reserved
        $bw.Write([uint16]1)                                       # planes
        $bw.Write([uint16]32)                                      # bpp
        $bw.Write([uint32]$data.Length)
        $bw.Write([uint32]$offset)
        $offset += $data.Length
    }
    foreach ($s in $sizes) { [byte[]]$blob = $pngBySize[$s]; $bw.Write($blob, 0, $blob.Length) }
    $bw.Flush()
    [System.IO.File]::WriteAllBytes($path, $ms.ToArray())
    $bw.Dispose(); $ms.Dispose()
}

New-Item -ItemType Directory -Force $AssetsDir | Out-Null

$rendered = @{}
$png = @{}
foreach ($s in ($Sizes | Sort-Object -Unique)) {
    $bmp = Render-Icon $s ($s -gt $DetailThreshold)
    $rendered[$s] = $bmp
    $png[$s] = Get-PngBytes $bmp
}

Write-Ico $IcoPath $png
Write-Host "ICO : $IcoPath ($($png.Keys.Count) sizes)"

foreach ($s in 256, 32) {
    if (-not $rendered.ContainsKey($s)) { $rendered[$s] = Render-Icon $s ($s -gt $DetailThreshold) }
    $target = Join-Path $AssetsDir "icon-$s.png"
    $rendered[$s].Save($target, [System.Drawing.Imaging.ImageFormat]::Png)
    Write-Host "PNG : $target"
}

if ($Preview) {
    # 256 and 32 px on a light neutral card, plus the 16 px variant so the
    # small-size rendering can be judged too.
    $pad = 24
    $w = $pad + 256 + $pad + 32 + $pad + 16 + $pad
    $h = 256 + 2 * $pad
    $pv = New-Object System.Drawing.Bitmap $w, $h, ([System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [System.Drawing.Graphics]::FromImage($pv)
    $g.Clear([System.Drawing.Color]::FromArgb(255, 243, 244, 246))
    $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::NearestNeighbor
    $g.DrawImage($rendered[256], $pad, $pad, 256, 256)
    $g.DrawImage($rendered[32], $pad + 256 + $pad, $h - $pad - 32, 32, 32)
    if (-not $rendered.ContainsKey(16)) { $rendered[16] = Render-Icon 16 $false }
    $g.DrawImage($rendered[16], $pad + 256 + $pad + 32 + $pad, $h - $pad - 16, 16, 16)
    $g.Dispose()
    $pv.Save($PreviewPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $pv.Dispose()
    Write-Host "PREVIEW: $PreviewPath"
}

foreach ($b in $rendered.Values) { $b.Dispose() }

$source.Dispose()
