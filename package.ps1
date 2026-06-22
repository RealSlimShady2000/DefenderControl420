# package.ps1 — builds the release exe and drops a portable, self-contained
# copy into <Desktop>\DefenderControl420, ready to copy to another Win10/11 PC.
# Run from the project root:  .\package.ps1
$ErrorActionPreference = 'Stop'

Push-Location $PSScriptRoot
try {
    cargo build --release
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed (exit $LASTEXITCODE)" }
} finally {
    Pop-Location
}

$exe  = Join-Path $PSScriptRoot 'target\release\defender-control.exe'
$ver  = (Get-Item $exe).VersionInfo.ProductVersion
$dest = Join-Path "$env:USERPROFILE\Desktop" 'DefenderControl420'

New-Item -ItemType Directory -Force -Path $dest | Out-Null

# The app runs elevated, so a running instance locks the .exe. Close it with an
# elevated taskkill (accept the UAC prompt), then wait for it to exit.
if (Get-Process -Name DefenderControl420 -ErrorAction SilentlyContinue) {
    Write-Host "Closing running DefenderControl420 (accept the UAC prompt)..."
    Start-Process taskkill -ArgumentList '/F', '/IM', 'DefenderControl420.exe' -Verb RunAs -WindowStyle Hidden
    for ($i = 0; $i -lt 30; $i++) {
        if (-not (Get-Process -Name DefenderControl420 -ErrorAction SilentlyContinue)) { break }
        Start-Sleep -Milliseconds 400
    }
}

$target = Join-Path $dest 'DefenderControl420.exe'
$copied = $false
for ($i = 0; $i -lt 12 -and -not $copied; $i++) {
    try { Copy-Item $exe $target -Force -ErrorAction Stop; $copied = $true }
    catch { Start-Sleep -Milliseconds 400 }
}
if (-not $copied) { throw "could not overwrite $target (is the app still open?)" }
Copy-Item (Join-Path $PSScriptRoot 'README.md') (Join-Path $dest 'README.md') -Force

Write-Host "Packaged Defender Control $ver  ->  $dest"
Get-ChildItem $dest | Select-Object Name, Length
