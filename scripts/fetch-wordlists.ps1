<#
  fetch-wordlists.ps1 -- pull the optional "medium" corpus (weakpass_4) on demand.

  CrackLab's ladder auto-detects wordlists\weakpass*.txt once it's here (no code
  change needed). rockyou + rules already covers ~90% of first-pass wins, so this
  is only worth it for tougher sets. weakpass_4 is ~85GB; you have the disk.

  weakpass rotates its direct download URL, so paste the current link from
  https://weakpass.com/wordlists (pick weakpass_4). The script handles .gz.

  Usage:
    powershell -File scripts\fetch-wordlists.ps1 -Url "https://download.weakpass.com/.../weakpass_4.txt.gz"
#>
param(
  [string]$Url,
  [string]$Dest = "$PSScriptRoot\..\wordlists\weakpass_4.txt"
)
$ErrorActionPreference = "Stop"
if (-not $Url) {
  Write-Host "No -Url given. Open https://weakpass.com/wordlists, copy the weakpass_4 direct link, then:" -ForegroundColor Yellow
  Write-Host "  powershell -File scripts\fetch-wordlists.ps1 -Url '<paste-link>'" -ForegroundColor Yellow
  exit 1
}
$dir = Split-Path $Dest
New-Item -ItemType Directory -Force $dir | Out-Null
$gz = ($Url -match '\.gz($|\?)')
$tmp = if ($gz) { "$Dest.gz" } else { $Dest }
Write-Host "Downloading -> $tmp (this is large; let it run)..." -ForegroundColor Cyan
Invoke-WebRequest -Uri $Url -OutFile $tmp -UseBasicParsing
if ($gz) {
  Write-Host "Decompressing .gz -> $Dest ..." -ForegroundColor Cyan
  $in  = [IO.File]::OpenRead($tmp)
  $out = [IO.File]::Create($Dest)
  $gzs = New-Object IO.Compression.GzipStream($in, [IO.Compression.CompressionMode]::Decompress)
  $gzs.CopyTo($out); $gzs.Dispose(); $out.Dispose(); $in.Dispose()
  Remove-Item $tmp
}
$mb = [math]::Round((Get-Item $Dest).Length/1MB,1)
Write-Host "Done: $Dest ($mb MB). The ladder will use it automatically as a 'weakpass+OneRule' rung." -ForegroundColor Green
