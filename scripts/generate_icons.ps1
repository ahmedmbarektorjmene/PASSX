# generate_icons.ps1
# Generates multiple icon sizes from logo.png for use throughout the app.
# Sizes: 16x16, 32x32, 48x48, 256x256
# Also generates a multi-resolution .ico file containing all sizes.
#
# Usage: powershell -ExecutionPolicy Bypass -File scripts/generate_icons.ps1

param(
    [string]$SourceImage = "assets/logo.png",
    [string]$OutputDir = "assets/icons"
)

$ErrorActionPreference = "Stop"

# Resolve paths relative to project root (script is in scripts/)
$ProjectRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$SourcePath = Join-Path $ProjectRoot $SourceImage
$OutputPath = Join-Path $ProjectRoot $OutputDir

# Validate source exists
if (-not (Test-Path $SourcePath)) {
    Write-Error "Source image not found: $SourcePath"
    exit 1
}

# Create output directory
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    Write-Host "[+] Created directory: $OutputPath"
}

# Load System.Drawing assembly
Add-Type -AssemblyName System.Drawing

# Load source image
$source = [System.Drawing.Image]::FromFile($SourcePath)
Write-Host "[*] Loaded source image: $($source.Width)x$($source.Height) px"

# Define icon sizes:
#   16x16  - title bar icons (small)
#   32x32  - desktop icons, Explorer list views
#   48x48  - larger Explorer views
#   256x256 - Extra-large icon view in Explorer, taskbar at high DPI
$sizes = @(16, 32, 48, 256)

# High-quality resize function
function Resize-Image {
    param(
        [System.Drawing.Image]$Source,
        [int]$Width,
        [int]$Height,
        [string]$OutputFile
    )
    
    $bitmap = New-Object System.Drawing.Bitmap($Width, $Height)
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    
    # High-quality rendering settings
    $graphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
    $graphics.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $graphics.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality
    
    $graphics.DrawImage($Source, 0, 0, $Width, $Height)
    
    $bitmap.Save($OutputFile, [System.Drawing.Imaging.ImageFormat]::Png)
    
    $graphics.Dispose()
    $bitmap.Dispose()
    
    Write-Host "[+] Generated: $OutputFile ($Width x $Height)"
}

# Generate PNG icons at each size
$bitmaps = @()
foreach ($size in $sizes) {
    $outFile = Join-Path $OutputPath "icon-${size}x${size}.png"
    Resize-Image -Source $source -Width $size -Height $size -OutputFile $outFile
    
    # Keep bitmaps for ICO generation
    $bitmap = New-Object System.Drawing.Bitmap($size, $size)
    $g = [System.Drawing.Graphics]::FromImage($bitmap)
    $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
    $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $g.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality
    $g.DrawImage($source, 0, 0, $size, $size)
    $g.Dispose()
    $bitmaps += $bitmap
}

# Generate multi-resolution .ico file
# ICO format: Header (6 bytes) + Directory Entries (16 bytes each) + Image Data (PNG encoded)
$icoPath = Join-Path $OutputPath "logo.ico"

$ms = New-Object System.IO.MemoryStream
$writer = New-Object System.IO.BinaryWriter($ms)

# ICO Header: reserved(2) + type(2, 1=icon) + count(2)
$writer.Write([UInt16]0)        # Reserved
$writer.Write([UInt16]1)        # Type: 1 = ICO
$writer.Write([UInt16]$bitmaps.Count) # Number of images

# We need to calculate offsets after writing all directory entries
# Directory entry size = 16 bytes per entry
$headerSize = 6
$directorySize = 16 * $bitmaps.Count
$dataOffset = $headerSize + $directorySize

# First pass: collect image data as PNG streams
$imageStreams = @()
foreach ($bmp in $bitmaps) {
    $pngStream = New-Object System.IO.MemoryStream
    $bmp.Save($pngStream, [System.Drawing.Imaging.ImageFormat]::Png)
    $imageStreams += $pngStream
}

# Write directory entries
$currentOffset = $dataOffset
for ($i = 0; $i -lt $bitmaps.Count; $i++) {
    $bmp = $bitmaps[$i]
    $imgData = $imageStreams[$i]
    
    $w = $bmp.Width
    $h = $bmp.Height
    
    # Width and Height: 0 means 256
    $writer.Write([byte]$(if ($w -ge 256) { 0 } else { $w }))
    $writer.Write([byte]$(if ($h -ge 256) { 0 } else { $h }))
    $writer.Write([byte]0)          # Color palette count (0 for >256 colors)
    $writer.Write([byte]0)          # Reserved
    $writer.Write([UInt16]1)        # Color planes
    $writer.Write([UInt16]32)       # Bits per pixel
    $writer.Write([UInt32]$imgData.Length) # Image data size
    $writer.Write([UInt32]$currentOffset) # Offset to image data
    
    $currentOffset += $imgData.Length
}

# Write image data (PNG streams)
foreach ($imgStream in $imageStreams) {
    $imgBytes = $imgStream.ToArray()
    $writer.Write($imgBytes)
    $imgStream.Dispose()
}

# Save ICO file
$writer.Flush()
[System.IO.File]::WriteAllBytes($icoPath, $ms.ToArray())

$writer.Dispose()
$ms.Dispose()

Write-Host "[+] Generated multi-resolution ICO: $icoPath (contains $($sizes -join ', ') px)"

# Cleanup
foreach ($bmp in $bitmaps) {
    $bmp.Dispose()
}
$source.Dispose()

Write-Host ""
Write-Host "=== Icon generation complete ==="
Write-Host "  Source: $SourcePath"
Write-Host "  Output: $OutputPath"
Write-Host "  Sizes:  $($sizes | ForEach-Object { "${_}x${_}" }) + multi-res .ico"
