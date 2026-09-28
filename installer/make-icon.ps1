<#
.SYNOPSIS
  Render the CleanDesk application icon with System.Drawing (no external tools).

.DESCRIPTION
  Draws a rounded green gradient tile with a white monitor and a leaf-like
  check mark, then writes:
    installer/cleandesk.ico          (16, 24, 32, 48, 64, 128, 256; PNG entries)
    crates/gui/assets/icon-256.png
    crates/gui/assets/icon-32.png
    installer/icon-preview.png       (256 px and 32 px side by side, for review)

  Every size is rendered at 4x and downsampled with bicubic filtering so edges
  stay anti-aliased; at 16/24 px the leaf detail is dropped and the monitor is
  kept, which is what remains readable in the tray and in Explorer lists.

.EXAMPLE
  .\installer\make-icon.ps1
  .\installer\make-icon.ps1 -Sizes 16,32,256 -Preview:$false
#>
[CmdletBinding()]
param(
    [int[]]$Sizes = @(16, 24, 32, 48, 64, 128, 256),
    [string]$IcoPath = "",
    [string]$AssetsDir = "",
    [string]$PreviewPath = "",
    [bool]$Preview = $true,
    # Palette (hex RGB). Tile gradient runs top -> bottom.
    [string]$GradientTop = "#0b6b3a",
    [string]$GradientBottom = "#22c55e",
    [string]$LeafColor = "#16a34a",
    # Corner radius as a fraction of the tile size.
    [double]$CornerRadius = 0.22,
    # Monitor width as a fraction of the tile size.
    [double]$MonitorWidth = 0.60,
    # Sizes at or below this drop the leaf detail.
    [int]$DetailThreshold = 24,
    [int]$Supersample = 4
)

$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Drawing

$root = Resolve-Path (Join-Path $PSScriptRoot "..")
if (-not $IcoPath)     { $IcoPath = Join-Path $PSScriptRoot "cleandesk.ico" }
if (-not $AssetsDir)   { $AssetsDir = Join-Path $root "crates\gui\assets" }
if (-not $PreviewPath) { $PreviewPath = Join-Path $PSScriptRoot "icon-preview.png" }

function ConvertTo-Color([string]$hex, [int]$alpha = 255) {
    $c = [System.Drawing.ColorTranslator]::FromHtml($hex)
    return [System.Drawing.Color]::FromArgb($alpha, $c.R, $c.G, $c.B)
}

function New-RoundedRect([float]$x, [float]$y, [float]$w, [float]$h, [float]$r) {
    $p = New-Object System.Drawing.Drawing2D.GraphicsPath
    $d = [Math]::Min($r * 2, [Math]::Min($w, $h))
    if ($d -le 0) { $p.AddRectangle((New-Object System.Drawing.RectangleF $x, $y, $w, $h)); return $p }
    $p.AddArc($x, $y, $d, $d, 180, 90)
    $p.AddArc($x + $w - $d, $y, $d, $d, 270, 90)
    $p.AddArc($x + $w - $d, $y + $h - $d, $d, $d, 0, 90)
    $p.AddArc($x, $y + $h - $d, $d, $d, 90, 90)
    $p.CloseFigure()
    return $p
}

# Draw the icon at $px pixels into a fresh 32bpp ARGB bitmap.
function Render-Icon([int]$px, [bool]$detail) {
    $ss = $Supersample
    $S = $px * $ss
    $big = New-Object System.Drawing.Bitmap $S, $S, ([System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [System.Drawing.Graphics]::FromImage($big)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $g.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality
    $g.Clear([System.Drawing.Color]::Transparent)

    # --- Tile: rounded square with vertical gradient -------------------------
    $radius = [float]($S * $CornerRadius)
    $tile = New-RoundedRect 0 0 $S $S $radius
    $grad = New-Object System.Drawing.Drawing2D.LinearGradientBrush(
        (New-Object System.Drawing.RectangleF 0, 0, $S, $S),
        (ConvertTo-Color $GradientTop), (ConvertTo-Color $GradientBottom),
        [System.Drawing.Drawing2D.LinearGradientMode]::Vertical)
    $g.FillPath($grad, $tile)

    # Subtle diagonal highlight in the upper-left so the tile reads as glossy
    # rather than flat; clipped to the tile.
    $g.SetClip($tile)
    $hl = New-Object System.Drawing.Drawing2D.LinearGradientBrush(
        (New-Object System.Drawing.PointF 0, 0),
        (New-Object System.Drawing.PointF $S, $S),
        [System.Drawing.Color]::FromArgb(56, 255, 255, 255),
        [System.Drawing.Color]::FromArgb(0, 255, 255, 255))
    $g.FillRectangle($hl, 0, 0, $S, $S)
    $g.ResetClip()

    # Faint darker inner border for depth. Drawn inset so the AA edge of the
    # tile is not doubled up.
    $bw = [float]([Math]::Max(1.0, $S * 0.025))
    $inner = New-RoundedRect ($bw / 2) ($bw / 2) ($S - $bw) ($S - $bw) ($radius - $bw / 2)
    $pen = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(70, 0, 40, 20)), $bw
    $g.DrawPath($pen, $inner)
    $pen.Dispose(); $inner.Dispose()

    # --- Monitor ---------------------------------------------------------------
    $mw = [float]($S * $MonitorWidth)
    $mh = [float]($mw * 0.68)                       # screen aspect ~ 3:2
    $mx = [float](($S - $mw) / 2)
    $standH = [float]($S * 0.07)
    $baseH  = [float]([Math]::Max(1.0, $S * 0.045))
    $total  = $mh + $standH + $baseH
    $my = [float](($S - $total) / 2 - $S * 0.01)   # nudge up: the base is visually heavy
    $white = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::White)
    $screenR = [float]($mw * 0.11)

    # Soft drop shadow under the monitor.
    $shadow = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(50, 0, 30, 15))
    $shPath = New-RoundedRect $mx ($my + $S * 0.02) $mw $mh $screenR
    $g.FillPath($shadow, $shPath)
    $shPath.Dispose(); $shadow.Dispose()

    $screen = New-RoundedRect $mx $my $mw $mh $screenR
    $g.FillPath($white, $screen)
    $screen.Dispose()

    # Stand neck + base.
    $neckW = [float]($mw * 0.14)
    $neckX = [float](($S - $neckW) / 2)
    $g.FillRectangle($white, $neckX, ($my + $mh - 1), $neckW, ($standH + 1))
    $baseW = [float]($mw * 0.48)
    $baseX = [float](($S - $baseW) / 2)
    $basePath = New-RoundedRect $baseX ($my + $mh + $standH) $baseW $baseH ($baseH / 2)
    $g.FillPath($white, $basePath)
    $basePath.Dispose()

    if ($detail) {
        # Leaf-like check mark: a short stroke down-right and a longer stroke
        # up-right, round caps so it reads as a leaf/sprout rather than a tick
        # glyph. Coordinates are relative to the screen rectangle.
        $lw = [float]($mw * 0.075)
        $leafPen = New-Object System.Drawing.Pen (ConvertTo-Color $LeafColor), $lw
        $leafPen.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
        $leafPen.EndCap   = [System.Drawing.Drawing2D.LineCap]::Round
        $leafPen.LineJoin = [System.Drawing.Drawing2D.LineJoin]::Round
        $p1 = New-Object System.Drawing.PointF ($mx + $mw * 0.30), ($my + $mh * 0.52)
        $p2 = New-Object System.Drawing.PointF ($mx + $mw * 0.45), ($my + $mh * 0.70)
        $p3 = New-Object System.Drawing.PointF ($mx + $mw * 0.72), ($my + $mh * 0.30)
        $g.DrawLines($leafPen, [System.Drawing.PointF[]]@($p1, $p2, $p3))
        $leafPen.Dispose()

        # A light gradient on the screen so it is not a flat white block.
        $scr = New-RoundedRect $mx $my $mw $mh $screenR
        $g.SetClip($scr)
        $sheen = New-Object System.Drawing.Drawing2D.LinearGradientBrush(
            (New-Object System.Drawing.PointF $mx, $my),
            (New-Object System.Drawing.PointF ($mx + $mw), ($my + $mh)),
            [System.Drawing.Color]::FromArgb(0, 220, 245, 230),
            [System.Drawing.Color]::FromArgb(70, 200, 235, 215))
        $g.FillRectangle($sheen, $mx, $my, $mw, $mh)
        $g.ResetClip(); $scr.Dispose(); $sheen.Dispose()
    }

    $white.Dispose(); $grad.Dispose(); $hl.Dispose(); $tile.Dispose(); $g.Dispose()

    # Downsample to the target size.
    $out = New-Object System.Drawing.Bitmap $px, $px, ([System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g2 = [System.Drawing.Graphics]::FromImage($out)
    $g2.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $g2.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $g2.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality
    $g2.Clear([System.Drawing.Color]::Transparent)
    $g2.DrawImage($big, (New-Object System.Drawing.Rectangle 0, 0, $px, $px))
    $g2.Dispose(); $big.Dispose()
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
