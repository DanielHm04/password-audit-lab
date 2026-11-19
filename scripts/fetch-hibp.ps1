<#
  fetch-hibp.ps1 -- download the Have I Been Pwned NTLM corpus (~40GB, ~1B hashes,
  ordered) for the `hibp` command. This is the top move for a domain password
  audit: compare NTDS NT hashes directly against known-breached passwords with
  ZERO cracking -- findings in seconds, even for strong passwords.

  Uses the official haveibeenpwned-downloader .NET tool. Needs the .NET SDK
  (https://dotnet.microsoft.com/download). Output lands where `hibp` expects it:
  loot\hibp\pwned-ntlm.txt

  Usage:  powershell -File scripts\fetch-hibp.ps1
#>
$ErrorActionPreference = "Stop"
$dest = "$PSScriptRoot\..\loot\hibp"
New-Item -ItemType Directory -Force $dest | Out-Null

if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
  Write-Host "The .NET SDK isn't installed. Get it from https://dotnet.microsoft.com/download," -ForegroundColor Yellow
  Write-Host "or download the NTLM list manually from https://haveibeenpwned.com/Passwords" -ForegroundColor Yellow
  Write-Host "and save it (UPPERHASH:count lines) to: $dest\pwned-ntlm.txt" -ForegroundColor Yellow
  exit 1
}
Write-Host "Installing/updating haveibeenpwned-downloader..." -ForegroundColor Cyan
dotnet tool install --global haveibeenpwned-downloader 2>$null
dotnet tool update  --global haveibeenpwned-downloader 2>$null

# The tool targets .NET 9; the machine's default runtime may be older. Point it at
# the dotnet we have and allow a major-version roll-forward so it runs regardless.
$dotnetRoot = Split-Path (Get-Command dotnet -ErrorAction SilentlyContinue).Source
if ($dotnetRoot) { $env:DOTNET_ROOT = $dotnetRoot }
$env:DOTNET_ROLL_FORWARD = "LatestMajor"
$tool = "$HOME\.dotnet\tools\haveibeenpwned-downloader.exe"

Push-Location $dest
try {
  # -n = NTLM hashes, single file, ordered by hash (what hibp.py streams); -o overwrite
  Write-Host "Downloading HIBP NTLM corpus (~40GB; resumable, be patient)..." -ForegroundColor Cyan
  & $tool pwned-ntlm -n -o
  if (Test-Path "$dest\pwned-ntlm.txt") {
    $gb = [math]::Round((Get-Item "$dest\pwned-ntlm.txt").Length/1GB,1)
    Write-Host "Done: $dest\pwned-ntlm.txt ($gb GB). Run: python core\cracklab.py hibp <ntds.txt> --scope <s>" -ForegroundColor Green
  }
} finally { Pop-Location }
