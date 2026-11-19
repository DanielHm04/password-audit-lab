# benchmark.ps1 - quick GPU benchmark across the hash modes you actually meet in CPTS.
# Run: powershell -ExecutionPolicy Bypass -File scripts\benchmark.ps1
$hcDir = Join-Path $PSScriptRoot "..\hashcat"
Push-Location $hcDir
$modes = [ordered]@{
  "0"="MD5"; "100"="SHA1"; "1000"="NTLM"; "1800"="sha512crypt (Linux shadow)";
  "3200"="bcrypt"; "5600"="NetNTLMv2 (Responder)"; "13100"="Kerberos TGS-REP (Kerberoast)";
  "18200"="Kerberos AS-REP (AS-REP roast)"; "22000"="WPA-PBKDF2"
}
Write-Host "`nRTX 3080 benchmark (CUDA only):`n" -ForegroundColor Cyan
foreach($m in $modes.Keys){
  $out = .\hashcat.exe -b -m $m --backend-ignore-opencl -d 1 --quiet 2>&1 | Select-String "Speed\.#01"
  $spd = ($out -replace '.*Speed\.#01\.+:\s*','') -replace '\s*\(.*',''
  "{0,-7} {1,-34} {2}" -f $m, $modes[$m], $spd
}
Pop-Location
