<#
.SYNOPSIS
Generates Mina's application icon — SVG, PNG and ICO — from one geometry description.

.DESCRIPTION
The icon is a tunnel portal seen head-on, with the light on at its far end: the analyst's
traffic leaving through the protected path. No text, no wordmark; the silhouette alone has to
carry it, because the same shape is drawn by hand in the tray (Mina.EndpointAgent.Tray/TrayGlyph.cs)
where the light is the protected-path state. Change the silhouette here and there together.

Everything is emitted from the `$Design` table below: the SVG is written from it and the rasters
are drawn from the same numbers with GDI+ (System.Drawing), so the two cannot drift. GDI+ rather
than WPF's RenderTargetBitmap deliberately — it is a pure software rasteriser that needs no
compositor, so it produces the same bytes on a CI runner, in a disconnected RDP session, or under
a service account, none of which WPF's off-screen rendering survives. No external tool is
involved, which keeps this reproducible on any Windows box without ImageMagick, Inkscape or a
Node toolchain.

Outputs (all deterministic for a given script revision):
  branding/mina.svg            vector master, viewBox 0 0 256 256
  branding/mina.ico            16 20 24 32 40 48 64 128 (32-bit BMP entries) + 256 (PNG entry)
  branding/mina-256.png        for Intune's Company Portal large icon and anywhere a PNG is asked for
  management-ui/.../wwwroot/favicon.ico   16 32 48
  management-ui/.../wwwroot/icon.svg      the same SVG; browsers that take an SVG favicon prefer it

.PARAMETER PreviewPath
Also writes a contact sheet (the icon at each rendered size on a light and a dark ground) to this
path. For eyeballing a change; not a repository asset.

.EXAMPLE
.\New-MinaIcons.ps1
.\New-MinaIcons.ps1 -PreviewPath $env:TEMP\mina-icon-preview.png
#>
[CmdletBinding()]
param(
    [Parameter()] [string] $OutputDirectory,
    [Parameter()] [string] $ManagementUiWwwroot,
    [Parameter()] [switch] $SkipManagementUi,
    [Parameter()] [string] $PreviewPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Resolved here rather than as parameter defaults: a dot-sourced script evaluates its defaults in
# the caller's scope, where $PSScriptRoot is empty, and dot-sourcing is how the functions below are
# reached for a diagnosis.
if (-not $OutputDirectory) { $OutputDirectory = $PSScriptRoot }
if (-not $ManagementUiWwwroot) { $ManagementUiWwwroot = Join-Path $PSScriptRoot '..\management-ui\src\Mina.ManagementUi\wwwroot' }

Add-Type -AssemblyName System.Drawing

# ------------------------------------------------------------------------------------------------
# The design. One table, two renderers.
#
# Coordinates are in a 256 x 256 space. Colours are the management UI / tray palette (app.css,
# App.xaml): the plate is Ground->Panel, the wall is the Line/Muted slate family, the light is
# Accent. Alpha is a separate 0..1 value so the SVG and GDI+ emitters agree on it exactly.
#
# Shapes are drawn in order. `Detail` marks strokes and glows that only earn their pixels at
# larger sizes; rasters at or below `DetailCutoff` skip them so a 16 px icon stays a clean plate,
# arch and light rather than a smear of one-pixel ribs.
# ------------------------------------------------------------------------------------------------

$DetailCutoff = 32

# Vanishing point: where the tunnel converges and the light sits. A little below centre, so the
# road reads as running away from the viewer rather than the arch floating.
$VP = @{ X = 128; Y = 150 }

function F { param([double] $Value) return $Value.ToString('0.##', [Globalization.CultureInfo]::InvariantCulture) }

function New-Arch {
    # The portal: straight sides from the floor up to the springing line, a semicircle over the
    # top whose radius is half the width. Defaults are the mouth; the wall's outer face is the same
    # shape 20 units further out. `Scale` shrinks it about the vanishing point for the receding
    # ribs. Numbers only — each emitter draws them its own way.
    param(
        [double] $Left = 74, [double] $Right = 182, [double] $Spring = 118, [double] $Floor = 196,
        [double] $Scale = 1.0, [switch] $Open
    )
    return @{
        Left   = $VP.X + ($Left   - $VP.X) * $Scale
        Right  = $VP.X + ($Right  - $VP.X) * $Scale
        Spring = $VP.Y + ($Spring - $VP.Y) * $Scale
        Floor  = $VP.Y + ($Floor  - $VP.Y) * $Scale
        Open   = [bool] $Open
    }
}

$Mouth = New-Arch

$Design = @(
    @{ Name = 'plate';  Kind = 'RoundedRect'; X = 0; Y = 0; W = 256; H = 256; R = 56
       Fill = @{ Type = 'Linear'; X1 = 0.15; Y1 = 0; X2 = 0.85; Y2 = 1
                 Stops = @(@{ At = 0; Color = '#1E2D3D' }, @{ At = 1; Color = '#0F1720' }) } }

    # The ground the portal stands on, so it reads as a tunnel mouth and not a magnet.
    @{ Name = 'ground'; Kind = 'RoundedRect'; X = 34; Y = 196; W = 188; H = 12; R = 5
       Fill = @{ Type = 'Linear'; X1 = 0; Y1 = 0; X2 = 0; Y2 = 1
                 Stops = @(@{ At = 0; Color = '#2B3948' }, @{ At = 1; Color = '#1B2632' }) } }

    # Wall = outer face minus the mouth (even-odd), lit from above.
    @{ Name = 'wall';   Kind = 'Ring'; Outer = (New-Arch -Left 54 -Right 202 -Spring 118); Inner = $Mouth
       Fill = @{ Type = 'Linear'; X1 = 0; Y1 = 0; X2 = 0; Y2 = 1
                 Stops = @(@{ At = 0; Color = '#55677A' }, @{ At = 1; Color = '#34424F' }) } }

    @{ Name = 'mouth';  Kind = 'Arch'; Arch = $Mouth; Fill = @{ Type = 'Solid'; Color = '#0A1118' } }

    # Receding ribs give the bore its depth. Strokes only, so the light still owns the mouth.
    @{ Name = 'rib-1';  Kind = 'Arch'; Arch = (New-Arch -Scale 0.74 -Open); Detail = $true
       Stroke = @{ Color = '#1C2835'; Width = 3.5 } }
    @{ Name = 'rib-2';  Kind = 'Arch'; Arch = (New-Arch -Scale 0.52 -Open); Detail = $true
       Stroke = @{ Color = '#1C2835'; Width = 3 } }
    @{ Name = 'rib-3';  Kind = 'Arch'; Arch = (New-Arch -Scale 0.34 -Open); Detail = $true
       Stroke = @{ Color = '#1C2835'; Width = 2.5 } }

    # Light spilling onto the road. Clipped to the mouth so it never paints the wall.
    @{ Name = 'spill';  Kind = 'Ellipse'; CX = 128; CY = 184; RX = 48; RY = 16; Clip = $Mouth; Detail = $true
       Fill = @{ Type = 'Radial'; CX = 128; CY = 184; R = 48
                 Stops = @(@{ At = 0; Color = '#4DA3FF'; Alpha = 0.40 }, @{ At = 1; Color = '#4DA3FF'; Alpha = 0 }) } }

    # The light itself: a white-hot core falling off through the accent blue to nothing.
    @{ Name = 'glow';   Kind = 'Ellipse'; CX = $VP.X; CY = $VP.Y; RX = 52; RY = 52; Clip = $Mouth
       Fill = @{ Type = 'Radial'; CX = $VP.X; CY = $VP.Y; R = 52
                 Stops = @(@{ At = 0;    Color = '#FFFFFF' },
                           @{ At = 0.18; Color = '#DCEDFF' },
                           @{ At = 0.45; Color = '#4DA3FF'; Alpha = 0.85 },
                           @{ At = 0.75; Color = '#4DA3FF'; Alpha = 0.30 },
                           @{ At = 1;    Color = '#4DA3FF'; Alpha = 0 }) } }

    @{ Name = 'core';   Kind = 'Ellipse'; CX = $VP.X; CY = $VP.Y; RX = 11; RY = 11
       Fill = @{ Type = 'Solid'; Color = '#FFFFFF' } }

    # The portal's inner edge catching the light — the one cue that survives every size.
    @{ Name = 'edge';   Kind = 'Arch'; Arch = (New-Arch -Open)
       Stroke = @{ Color = '#4DA3FF'; Width = 3; Alpha = 0.55 } }
)

# ------------------------------------------------------------------------------------------------
# SVG emitter
# ------------------------------------------------------------------------------------------------

function Get-ArchPathData {
    param([hashtable] $Arch)
    $r = ($Arch.Right - $Arch.Left) / 2
    $d = 'M {0},{1} L {0},{2} A {3},{3} 0 0 1 {4},{2} L {4},{1}' -f (F $Arch.Left), (F $Arch.Floor), (F $Arch.Spring), (F $r), (F $Arch.Right)
    if (-not $Arch.Open) { $d += ' Z' }
    return $d
}

function Get-SvgStop {
    param([hashtable] $Stop)
    $opacity = ''
    if ($Stop.ContainsKey('Alpha')) { $opacity = ' stop-opacity="{0}"' -f (F $Stop.Alpha) }
    return '      <stop offset="{0}" stop-color="{1}"{2}/>' -f (F $Stop.At), $Stop.Color, $opacity
}

function ConvertTo-Svg {
    param([object[]] $Shapes)

    $defs = New-Object Text.StringBuilder
    $body = New-Object Text.StringBuilder
    $gradientIndex = 0

    foreach ($shape in $Shapes) {
        $attrs = ''
        if ($shape.ContainsKey('Fill')) {
            $fill = $shape.Fill
            switch ($fill.Type) {
                'Solid' {
                    $attrs += (' fill="{0}"' -f $fill.Color)
                    if ($fill.ContainsKey('Alpha')) { $attrs += (' fill-opacity="{0}"' -f (F $fill.Alpha)) }
                }
                'Linear' {
                    $id = 'g{0}' -f (++$gradientIndex)
                    [void]$defs.AppendLine(('    <linearGradient id="{0}" x1="{1}" y1="{2}" x2="{3}" y2="{4}">' -f $id, (F $fill.X1), (F $fill.Y1), (F $fill.X2), (F $fill.Y2)))
                    foreach ($stop in $fill.Stops) { [void]$defs.AppendLine((Get-SvgStop $stop)) }
                    [void]$defs.AppendLine('    </linearGradient>')
                    $attrs += (' fill="url(#{0})"' -f $id)
                }
                'Radial' {
                    $id = 'g{0}' -f (++$gradientIndex)
                    [void]$defs.AppendLine(('    <radialGradient id="{0}" gradientUnits="userSpaceOnUse" cx="{1}" cy="{2}" r="{3}">' -f $id, (F $fill.CX), (F $fill.CY), (F $fill.R)))
                    foreach ($stop in $fill.Stops) { [void]$defs.AppendLine((Get-SvgStop $stop)) }
                    [void]$defs.AppendLine('    </radialGradient>')
                    $attrs += (' fill="url(#{0})"' -f $id)
                }
            }
        } else {
            $attrs += ' fill="none"'
        }
        if ($shape.ContainsKey('Stroke')) {
            $s = $shape.Stroke
            $attrs += (' stroke="{0}" stroke-width="{1}" stroke-linecap="round" stroke-linejoin="round"' -f $s.Color, (F $s.Width))
            if ($s.ContainsKey('Alpha')) { $attrs += (' stroke-opacity="{0}"' -f (F $s.Alpha)) }
        }
        if ($shape.ContainsKey('Clip')) {
            $clipId = 'clip-{0}' -f $shape.Name
            [void]$defs.AppendLine(('    <clipPath id="{0}"><path d="{1}"/></clipPath>' -f $clipId, (Get-ArchPathData $shape.Clip)))
            $attrs += (' clip-path="url(#{0})"' -f $clipId)
        }

        $element = switch ($shape.Kind) {
            'RoundedRect' { '<rect x="{0}" y="{1}" width="{2}" height="{3}" rx="{4}"{5}/>' -f (F $shape.X), (F $shape.Y), (F $shape.W), (F $shape.H), (F $shape.R), $attrs }
            'Ellipse'     { '<ellipse cx="{0}" cy="{1}" rx="{2}" ry="{3}"{4}/>' -f (F $shape.CX), (F $shape.CY), (F $shape.RX), (F $shape.RY), $attrs }
            'Arch'        { '<path d="{0}"{1}/>' -f (Get-ArchPathData $shape.Arch), $attrs }
            'Ring'        { '<path d="{0} {1}" fill-rule="evenodd"{2}/>' -f (Get-ArchPathData $shape.Outer), (Get-ArchPathData $shape.Inner), $attrs }
        }
        [void]$body.AppendLine('  ' + $element)
    }

    $svg = New-Object Text.StringBuilder
    [void]$svg.AppendLine('<?xml version="1.0" encoding="UTF-8"?>')
    [void]$svg.AppendLine('<!-- Generated by branding/New-MinaIcons.ps1. Edit the script, not this file. -->')
    [void]$svg.AppendLine('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 256 256" width="256" height="256">')
    [void]$svg.AppendLine('  <defs>')
    [void]$svg.Append($defs.ToString())
    [void]$svg.AppendLine('  </defs>')
    [void]$svg.Append($body.ToString())
    [void]$svg.AppendLine('</svg>')
    return $svg.ToString()
}

# ------------------------------------------------------------------------------------------------
# GDI+ emitter (rasters)
# ------------------------------------------------------------------------------------------------

function Get-GdiColor {
    param([string] $Hex, [double] $Alpha = 1.0)
    $c = [System.Drawing.ColorTranslator]::FromHtml($Hex)
    return [System.Drawing.Color]::FromArgb([int][math]::Round(255 * $Alpha), $c)
}

function Get-ArchPath {
    param([hashtable] $Arch)
    $r = ($Arch.Right - $Arch.Left) / 2
    $path = New-Object System.Drawing.Drawing2D.GraphicsPath
    $path.StartFigure()
    $path.AddLine([single]$Arch.Left, [single]$Arch.Floor, [single]$Arch.Left, [single]$Arch.Spring)
    $path.AddArc([single]$Arch.Left, [single]($Arch.Spring - $r), [single](2 * $r), [single](2 * $r), [single]180, [single]180)
    $path.AddLine([single]$Arch.Right, [single]$Arch.Spring, [single]$Arch.Right, [single]$Arch.Floor)
    if (-not $Arch.Open) { $path.CloseFigure() }
    return $path
}

function Get-ShapePath {
    param([hashtable] $Shape)
    switch ($Shape.Kind) {
        'RoundedRect' {
            $path = New-Object System.Drawing.Drawing2D.GraphicsPath
            $d = [single](2 * $Shape.R)
            $x = [single]$Shape.X; $y = [single]$Shape.Y; $w = [single]$Shape.W; $h = [single]$Shape.H
            $path.AddArc($x, $y, $d, $d, [single]180, [single]90)
            $path.AddArc([single]($x + $w - $d), $y, $d, $d, [single]270, [single]90)
            $path.AddArc([single]($x + $w - $d), [single]($y + $h - $d), $d, $d, [single]0, [single]90)
            $path.AddArc($x, [single]($y + $h - $d), $d, $d, [single]90, [single]90)
            $path.CloseFigure()
            return $path
        }
        'Ellipse' {
            $path = New-Object System.Drawing.Drawing2D.GraphicsPath
            $path.AddEllipse([single]($Shape.CX - $Shape.RX), [single]($Shape.CY - $Shape.RY), [single](2 * $Shape.RX), [single](2 * $Shape.RY))
            return $path
        }
        'Arch' { return Get-ArchPath $Shape.Arch }
        'Ring' {
            $path = Get-ArchPath $Shape.Outer
            $inner = Get-ArchPath $Shape.Inner
            $path.AddPath($inner, $false)
            $path.FillMode = [System.Drawing.Drawing2D.FillMode]::Alternate   # even-odd
            $inner.Dispose()
            return $path
        }
    }
}

function Get-GdiBrush {
    param([hashtable] $Fill, [System.Drawing.Drawing2D.GraphicsPath] $Path)
    switch ($Fill.Type) {
        'Solid' {
            $alpha = 1.0; if ($Fill.ContainsKey('Alpha')) { $alpha = $Fill.Alpha }
            return New-Object System.Drawing.SolidBrush (Get-GdiColor $Fill.Color $alpha)
        }
        'Linear' {
            # SVG's default objectBoundingBox units: the gradient vector is relative to the shape.
            $b = $Path.GetBounds()
            $p1 = New-Object System.Drawing.PointF ([single]($b.X + $Fill.X1 * $b.Width)), ([single]($b.Y + $Fill.Y1 * $b.Height))
            $p2 = New-Object System.Drawing.PointF ([single]($b.X + $Fill.X2 * $b.Width)), ([single]($b.Y + $Fill.Y2 * $b.Height))
            $stops = @($Fill.Stops)
            $brush = New-Object System.Drawing.Drawing2D.LinearGradientBrush -ArgumentList $p1, $p2, (Get-GdiStopColor $stops[0]), (Get-GdiStopColor $stops[-1])
            if ($stops.Count -gt 2) { $brush.InterpolationColors = Get-ColorBlend -Stops $stops -Reverse:$false }
            # Corners that project past the vector's ends mirror back to the end colours instead of
            # tiling from the other end.
            $brush.WrapMode = [System.Drawing.Drawing2D.WrapMode]::TileFlipXY
            return $brush
        }
        'Radial' {
            $circle = New-Object System.Drawing.Drawing2D.GraphicsPath
            $circle.AddEllipse([single]($Fill.CX - $Fill.R), [single]($Fill.CY - $Fill.R), [single](2 * $Fill.R), [single](2 * $Fill.R))
            $brush = New-Object System.Drawing.Drawing2D.PathGradientBrush $circle
            $brush.CenterPoint = New-Object System.Drawing.PointF ([single]$Fill.CX), ([single]$Fill.CY)
            # A path gradient runs from the boundary (0) to the centre (1) — the reverse of SVG.
            $brush.InterpolationColors = Get-ColorBlend -Stops @($Fill.Stops) -Reverse:$true
            $circle.Dispose()
            return $brush
        }
    }
}

function Get-GdiStopColor {
    param([hashtable] $Stop)
    $alpha = 1.0; if ($Stop.ContainsKey('Alpha')) { $alpha = $Stop.Alpha }
    return Get-GdiColor $Stop.Color $alpha
}

function Get-ColorBlend {
    param([object[]] $Stops, [switch] $Reverse)
    $ordered = $Stops | Sort-Object { [double]$_.At }
    if ($Reverse) { [array]::Reverse($ordered) }
    $blend = New-Object System.Drawing.Drawing2D.ColorBlend $ordered.Count
    $positions = New-Object single[] $ordered.Count
    $colors = New-Object System.Drawing.Color[] $ordered.Count
    for ($i = 0; $i -lt $ordered.Count; $i++) {
        $positions[$i] = if ($Reverse) { [single](1 - $ordered[$i].At) } else { [single]$ordered[$i].At }
        $colors[$i] = Get-GdiStopColor $ordered[$i]
    }
    $blend.Positions = $positions
    $blend.Colors = $colors
    return $blend
}

function New-IconBitmap {
    # Renders the design at `Size` pixels, natively — every size is a fresh vector rasterisation,
    # never a downsample, so the small entries stay crisp.
    param([int] $Size, [object[]] $Shapes)

    $bitmap = New-Object System.Drawing.Bitmap $Size, $Size, ([System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [System.Drawing.Graphics]::FromImage($bitmap)
    try {
        $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
        $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
        $g.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality
        $g.Clear([System.Drawing.Color]::Transparent)
        $scale = [single]($Size / 256.0)
        $g.ScaleTransform($scale, $scale)

        foreach ($shape in $Shapes) {
            if ($shape.ContainsKey('Detail') -and $shape.Detail -and $Size -le $DetailCutoff) { continue }

            $path = Get-ShapePath $shape
            $clipped = $shape.ContainsKey('Clip')
            if ($clipped) {
                $clip = Get-ArchPath $shape.Clip
                $g.SetClip($clip)
                $clip.Dispose()
            }

            if ($shape.ContainsKey('Fill')) {
                $brush = Get-GdiBrush -Fill $shape.Fill -Path $path
                $g.FillPath($brush, $path)
                $brush.Dispose()
            }
            if ($shape.ContainsKey('Stroke')) {
                $s = $shape.Stroke
                $alpha = 1.0; if ($s.ContainsKey('Alpha')) { $alpha = $s.Alpha }
                $pen = New-Object System.Drawing.Pen (Get-GdiColor $s.Color $alpha), ([single]$s.Width)
                $pen.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
                $pen.EndCap = [System.Drawing.Drawing2D.LineCap]::Round
                $pen.LineJoin = [System.Drawing.Drawing2D.LineJoin]::Round
                $g.DrawPath($pen, $path)
                $pen.Dispose()
            }

            if ($clipped) { $g.ResetClip() }
            $path.Dispose()
        }
    } finally {
        $g.Dispose()
    }
    return $bitmap
}

function ConvertTo-Png {
    param([System.Drawing.Bitmap] $Bitmap)
    $stream = New-Object IO.MemoryStream
    $Bitmap.Save($stream, [System.Drawing.Imaging.ImageFormat]::Png)
    # The leading comma keeps the byte[] intact: a bare array return is unrolled into the pipeline
    # and comes back as object[], which BinaryWriter.Write then binds to a one-byte overload.
    return ,$stream.ToArray()
}

function Get-Pixels {
    # BGRA rows, top-down, straight (non-premultiplied) alpha — what a 32bppArgb bitmap holds.
    param([System.Drawing.Bitmap] $Bitmap)
    $rect = New-Object System.Drawing.Rectangle 0, 0, $Bitmap.Width, $Bitmap.Height
    $data = $Bitmap.LockBits($rect, [System.Drawing.Imaging.ImageLockMode]::ReadOnly, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    try {
        $bytes = New-Object byte[] ($data.Stride * $Bitmap.Height)
        [System.Runtime.InteropServices.Marshal]::Copy($data.Scan0, $bytes, 0, $bytes.Length)
        return @{ Bytes = $bytes; Stride = $data.Stride }
    } finally {
        $Bitmap.UnlockBits($data)
    }
}

function ConvertTo-IconDib {
    # A 32-bit BGRA device-independent bitmap with the AND mask the ICO format still requires:
    # the classic entry format, read by everything from the shell to third-party packagers.
    param([System.Drawing.Bitmap] $Bitmap)

    $w = $Bitmap.Width; $h = $Bitmap.Height
    $pixels = Get-Pixels $Bitmap
    $src = $pixels.Bytes; $stride = $pixels.Stride
    $rowBytes = $w * 4

    $maskStride = [int][math]::Ceiling($w / 32.0) * 4
    $mask = New-Object byte[] ($maskStride * $h)

    $stream = New-Object IO.MemoryStream
    $writer = New-Object IO.BinaryWriter $stream
    $writer.Write([int32]40)            # BITMAPINFOHEADER
    $writer.Write([int32]$w)
    $writer.Write([int32]($h * 2))      # XOR + AND
    $writer.Write([int16]1)
    $writer.Write([int16]32)
    $writer.Write([int32]0)             # BI_RGB
    $writer.Write([int32]($rowBytes * $h + $maskStride * $h))
    $writer.Write([int32]0); $writer.Write([int32]0); $writer.Write([int32]0); $writer.Write([int32]0)

    for ($y = $h - 1; $y -ge 0; $y--) {          # DIB rows are bottom-up
        $writer.Write($src, $y * $stride, $rowBytes)
        for ($x = 0; $x -lt $w; $x++) {
            if ($src[$y * $stride + $x * 4 + 3] -eq 0) {
                # -shr, not [int]($x / 8): PowerShell's [int] cast rounds to nearest, it does not truncate.
                $index = ($h - 1 - $y) * $maskStride + ($x -shr 3)
                $mask[$index] = $mask[$index] -bor (0x80 -shr ($x % 8))
            }
        }
    }
    $writer.Write($mask)
    $writer.Flush()
    return ,$stream.ToArray()
}

function New-Ico {
    # ICONDIR + ICONDIRENTRY[] + images. 256 px is stored PNG-compressed, as Vista onwards expects
    # for that size; everything smaller is a DIB for maximum reader compatibility.
    param([int[]] $Sizes, [object[]] $Shapes)

    $images = foreach ($size in $Sizes) {
        $bitmap = New-IconBitmap -Size $size -Shapes $Shapes
        if ($size -ge 256) { [pscustomobject]@{ Size = $size; Bytes = (ConvertTo-Png $bitmap) } }
        else               { [pscustomobject]@{ Size = $size; Bytes = (ConvertTo-IconDib $bitmap) } }
        $bitmap.Dispose()
    }

    $stream = New-Object IO.MemoryStream
    $writer = New-Object IO.BinaryWriter $stream
    $writer.Write([int16]0); $writer.Write([int16]1); $writer.Write([int16]$images.Count)
    $offset = 6 + 16 * $images.Count
    foreach ($image in $images) {
        $dim = if ($image.Size -ge 256) { 0 } else { $image.Size }   # 0 means 256 in a one-byte field
        $writer.Write([byte]$dim); $writer.Write([byte]$dim)
        $writer.Write([byte]0); $writer.Write([byte]0)
        $writer.Write([int16]1); $writer.Write([int16]32)
        $writer.Write([int32]$image.Bytes.Length)
        $writer.Write([int32]$offset)
        $offset += $image.Bytes.Length
    }
    foreach ($image in $images) { $writer.Write([byte[]]$image.Bytes) }
    $writer.Flush()
    return ,$stream.ToArray()
}

function Write-Preview {
    # Contact sheet: each size rendered natively, on a light and a dark ground.
    param([string] $Path, [object[]] $Shapes)
    $sizes = 256, 128, 64, 48, 32, 24, 16
    $gap = 24
    $width = ($sizes | Measure-Object -Sum).Sum + $gap * ($sizes.Count + 1)
    $rowHeight = 256 + $gap * 2
    $grounds = '#F3F4F6', '#0F1720'
    $sheet = New-Object System.Drawing.Bitmap $width, ($rowHeight * $grounds.Count), ([System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [System.Drawing.Graphics]::FromImage($sheet)
    try {
        for ($row = 0; $row -lt $grounds.Count; $row++) {
            $ground = New-Object System.Drawing.SolidBrush (Get-GdiColor $grounds[$row])
            $g.FillRectangle($ground, 0, ($row * $rowHeight), $width, $rowHeight)
            $ground.Dispose()
            $x = $gap
            foreach ($size in $sizes) {
                $bitmap = New-IconBitmap -Size $size -Shapes $Shapes
                $g.DrawImageUnscaled($bitmap, $x, ($row * $rowHeight + $rowHeight - $gap - $size))
                $bitmap.Dispose()
                $x += $size + $gap
            }
        }
    } finally {
        $g.Dispose()
    }
    [IO.File]::WriteAllBytes($Path, (ConvertTo-Png $sheet))
    $sheet.Dispose()
}

# ------------------------------------------------------------------------------------------------
# Emit
# ------------------------------------------------------------------------------------------------

$OutputDirectory = (Resolve-Path $OutputDirectory).Path
$utf8NoBom = New-Object Text.UTF8Encoding $false

$svg = ConvertTo-Svg -Shapes $Design
[IO.File]::WriteAllText((Join-Path $OutputDirectory 'mina.svg'), $svg, $utf8NoBom)
[IO.File]::WriteAllBytes((Join-Path $OutputDirectory 'mina.ico'), (New-Ico -Sizes 16, 20, 24, 32, 40, 48, 64, 128, 256 -Shapes $Design))
$full = New-IconBitmap -Size 256 -Shapes $Design
[IO.File]::WriteAllBytes((Join-Path $OutputDirectory 'mina-256.png'), (ConvertTo-Png $full))
$full.Dispose()
Write-Host ('Wrote mina.svg, mina.ico, mina-256.png to {0}' -f $OutputDirectory)

if (-not $SkipManagementUi) {
    $wwwroot = (Resolve-Path $ManagementUiWwwroot).Path
    [IO.File]::WriteAllBytes((Join-Path $wwwroot 'favicon.ico'), (New-Ico -Sizes 16, 32, 48 -Shapes $Design))
    [IO.File]::WriteAllText((Join-Path $wwwroot 'icon.svg'), $svg, $utf8NoBom)
    Write-Host ('Wrote favicon.ico, icon.svg to {0}' -f $wwwroot)
}

if ($PreviewPath) {
    Write-Preview -Path $PreviewPath -Shapes $Design
    Write-Host ('Wrote preview sheet to {0}' -f $PreviewPath)
}
