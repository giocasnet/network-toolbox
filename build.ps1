<#
.SYNOPSIS
  Release build of Network Toolbox: tests, compilation, MSI/NSIS installers, optional signing.

.EXAMPLE
  .\build.ps1                                   # unsigned build
  .\build.ps1 -Thumbprint 0123ABCD...           # build signed with the given certificate
  .\build.ps1 -SkipTests

.NOTES
  The code signing certificate must be in Cert:\CurrentUser\My with its private key.
  To find its thumbprint:
    Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Select-Object Thumbprint, Subject, NotAfter
#>
param(
    [string]$Thumbprint,
    [switch]$SkipTests
)
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

if (-not $SkipTests) {
    Write-Host "==> Network library tests" -ForegroundColor Cyan
    cargo test -p ntb-core --quiet
    if ($LASTEXITCODE) { throw "Tests failed: build aborted" }
}

$cfgArgs = @()
if ($Thumbprint) {
    $Thumbprint = $Thumbprint -replace '\s', ''
    $cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Where-Object Thumbprint -eq $Thumbprint
    if (-not $cert) { throw "Signing certificate $Thumbprint not found in Cert:\CurrentUser\My" }
    if (-not $cert.HasPrivateKey) { throw "Certificate $Thumbprint has no private key" }
    $tmp = Join-Path $env:TEMP 'ntb-sign.json'
    @{ bundle = @{ windows = @{ certificateThumbprint = $Thumbprint } } } | ConvertTo-Json -Depth 5 | Set-Content $tmp -Encoding utf8
    $cfgArgs = @('--config', $tmp)
    Write-Host "==> Signing with: $($cert.Subject) (expires $($cert.NotAfter.ToString('d')))" -ForegroundColor Cyan
}

Write-Host "==> Build and installers" -ForegroundColor Cyan
cargo tauri build @cfgArgs
if ($LASTEXITCODE) { throw "Build failed" }

$out = Join-Path $PSScriptRoot 'release'
New-Item -ItemType Directory -Force -Path $out | Out-Null
# Only the installers of this version: target\release\bundle also keeps those of previous builds
$ver = (Get-Content 'src-tauri\tauri.conf.json' -Raw | ConvertFrom-Json).version
$installers = @(Get-ChildItem "target\release\bundle\msi\*_${ver}_*.msi", "target\release\bundle\nsis\*_${ver}_*-setup.exe" -ErrorAction SilentlyContinue)
if (-not $installers) { throw "No installer for version $ver in target\release\bundle" }
# oui.txt goes next to the exe in the portable version too (the installer places it by itself)
$files = @(Get-Item 'target\release\nettoolbox.exe', 'target\release\oui.txt') + $installers
$sums = foreach ($f in $files) {
    Copy-Item $f.FullName $out -Force
    $h = Get-FileHash $f.FullName -Algorithm SHA256
    $sig = (Get-AuthenticodeSignature $f.FullName).Status
    [pscustomobject]@{ File = $f.Name; SHA256 = $h.Hash; Signature = $sig }
}
# Portable version: folder + zip to copy onto a USB stick (no installation, settings in .\data)
$pdir = Join-Path $out 'NetworkToolbox-portable'
if (Test-Path $pdir) { Remove-Item $pdir -Recurse -Force }
New-Item -ItemType Directory -Force -Path $pdir | Out-Null
Copy-Item 'target\release\nettoolbox.exe' (Join-Path $pdir 'NetworkToolbox.exe')
Copy-Item 'target\release\oui.txt' $pdir
@(
    'Network Toolbox - portable version',
    '',
    'The presence of this file next to NetworkToolbox.exe turns on portable mode:',
    'settings (language, theme, profiles) are saved in the "data" folder next to the exe',
    'instead of the user profile of the PC. Delete this file to use the normal location.',
    '',
    'Requires the Microsoft Edge WebView2 runtime (already included in Windows 11).',
    'Keep oui.txt next to the exe (vendor names in Local network and Wi-Fi).'
) | Set-Content (Join-Path $pdir 'portable.txt') -Encoding ascii
foreach ($doc in 'LICENSE', 'NOTICE') {
    if (Test-Path $doc) { Copy-Item $doc $pdir }
}
$pzip = Join-Path $out "NetworkToolbox-$ver-portable.zip"
if (Test-Path $pzip) { Remove-Item $pzip -Force }
Compress-Archive -Path (Join-Path $pdir '*') -DestinationPath $pzip
$ph = Get-FileHash $pzip -Algorithm SHA256
$sums += [pscustomobject]@{ File = (Split-Path $pzip -Leaf); SHA256 = $ph.Hash; Signature = 'n/a' }
$sums | Format-Table -AutoSize
$sums | ForEach-Object { "$($_.SHA256)  $($_.File)" } | Set-Content (Join-Path $out 'SHA256SUMS.txt') -Encoding ascii
Write-Host "Version $ver - files ready in $out (hashes in SHA256SUMS.txt, useful for the EDR exclusion)" -ForegroundColor Green
