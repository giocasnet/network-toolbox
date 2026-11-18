<#
.SYNOPSIS
  Full project backup into a zip next to the project folder:
  ..\nettoolbox-desktop-backup-<versione>.zip

.DESCRIPTION
  The zip contains the whole working tree, the git history (.git) and release\ with the files of
  the current version. Left out: target\ (rebuilt by the build, several GB) and the installers
  of previous versions in release\.
  The version is the one in src-tauri\tauri.conf.json.

.EXAMPLE
  .\backup.ps1            # stops if the zip for this version already exists
  .\backup.ps1 -Force     # replaces it
#>
param(
    [switch]$Force
)
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

$root = (Get-Item $PSScriptRoot).FullName.TrimEnd('\')
$name = Split-Path $root -Leaf
$ver = (Get-Content 'src-tauri\tauri.conf.json' -Raw | ConvertFrom-Json).version
$zip = Join-Path (Split-Path $root -Parent) "$name-backup-$ver.zip"
if ((Test-Path $zip) -and -not $Force) {
    throw "${zip} already exists: use -Force to replace it"
}

$dirty = @(git status --porcelain)
if ($dirty.Count) {
    Write-Host "Warning: $($dirty.Count) modified or untracked files (they go into the zip as they are)" -ForegroundColor Yellow
}

$tmp = "$zip.tmp"
if (Test-Path $tmp) { Remove-Item $tmp -Force }
$count = 0
$bytes = [long]0
$fs = [System.IO.File]::Open($tmp, 'CreateNew')
try {
    $za = New-Object System.IO.Compression.ZipArchive($fs, [System.IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($f in [System.IO.Directory]::EnumerateFiles($root, '*', 'AllDirectories')) {
            $rel = $f.Substring($root.Length + 1)
            if ($rel -like 'target\*') { continue }
            # in release\ only the installers of this version
            if ($rel -like 'release\Network Toolbox_*' -and $rel -notlike "release\Network Toolbox_${ver}_*") { continue }
            $entry = "$name/" + $rel.Replace('\', '/')
            [void][System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($za, $f, $entry, [System.IO.Compression.CompressionLevel]::Optimal)
            $count++
            $bytes += (New-Object System.IO.FileInfo($f)).Length
        }
    }
    finally { $za.Dispose() }
}
finally { $fs.Dispose() }

Move-Item $tmp $zip -Force
$h = (Get-FileHash $zip -Algorithm SHA256).Hash
$desc = git describe --tags --always
$mb = [math]::Round((Get-Item $zip).Length / 1MB, 1)
$srcMb = [math]::Round($bytes / 1MB, 1)
Write-Host "Backup $ver ($desc): $count files, $srcMb MB -> $mb MB" -ForegroundColor Green
Write-Host $zip
Write-Host "SHA256 $h"
