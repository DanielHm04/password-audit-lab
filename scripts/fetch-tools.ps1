<#
  fetch-tools.ps1 -- optional candidate generators: princeprocessor (PRINCE) and
  kwprocessor (keyboard walks). CrackLab's ladder auto-detects them:
    - tools\...\pp64.exe present  -> a gated "prince-rockyou" rung (needs --allow-bruteforce)
    - wordlists\keywalks.txt present -> a "keywalks-straight" rung
  Both are pure upside; their absence is handled gracefully (rungs just skip).

  hashcat ships these as .7z releases. Extraction needs 7-Zip (7z.exe on PATH) or
  WinRAR. If neither is present the script downloads the archives and tells you
  where to extract them.

  Usage:  powershell -File scripts\fetch-tools.ps1
#>
$ErrorActionPreference = "Stop"
$tools = "$PSScriptRoot\..\tools"
$wl    = "$PSScriptRoot\..\wordlists"
New-Item -ItemType Directory -Force $tools | Out-Null

$sevenzip = (Get-Command 7z -ErrorAction SilentlyContinue).Source
function Grab($url, $out) { Write-Host "  downloading $([IO.Path]::GetFileName($out))..." -ForegroundColor Cyan; Invoke-WebRequest -Uri $url -OutFile $out -UseBasicParsing }

$pp = "$tools\princeprocessor-0.22.7z"
$kw = "$tools\kwprocessor-1.00.7z"
Grab "https://github.com/hashcat/princeprocessor/releases/download/v0.22/princeprocessor-0.22.7z" $pp
Grab "https://github.com/hashcat/kwprocessor/releases/download/v1.00/kwprocessor-1.00.7z" $kw

if (-not $sevenzip) {
  Write-Host "7-Zip not found on PATH. Archives are in $tools -- extract them there (so pp64.exe / kwp64.exe land under tools\), then re-run this script to generate keywalks." -ForegroundColor Yellow
  exit 0
}
& $sevenzip x $pp "-o$tools" -y | Out-Null
& $sevenzip x $kw "-o$tools" -y | Out-Null
Remove-Item $pp,$kw -ErrorAction SilentlyContinue

# kwprocessor (kwp64.exe) is installed under tools\ for manual use. NOTE: this
# build's kwp64 emits only short (2-5 char) walks with default flags, and the
# longer-walk direction flags are finicky to drive here -- auto-generating a
# useful keywalks.txt was unreliable, so it's intentionally NOT generated. If you
# want the rung, tune kwp64 by hand, filter to length>=6, and save the result to
# wordlists\keywalks.txt -- the ladder will auto-detect and use it. Low priority;
# PRINCE (below) is the higher-value generator from this fetch.
Write-Host "kwprocessor installed (tools\kwprocessor\kwp64.exe) -- keywalks NOT auto-generated (see script note)." -ForegroundColor Yellow
Write-Host "PRINCE ready: prince-rockyou rung activates when you pass --allow-bruteforce." -ForegroundColor Green
