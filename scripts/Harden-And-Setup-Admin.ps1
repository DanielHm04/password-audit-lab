# Harden-And-Setup-Admin.ps1  -- RUN AS ADMINISTRATOR (optional hardening + QoL)
# From an elevated prompt:
#   powershell -ExecutionPolicy Bypass -File .\scripts\Harden-And-Setup-Admin.ps1
# To also install an SSH key and disable password auth, pass your Kali public key:
#   ... -PubKey 'ssh-ed25519 AAAA... you@kali' -DisablePassword
#
# What it does:
#  1) Scopes the SSH firewall rule from "Any" to just your VM subnets.
#  2) Sets the default SSH shell to PowerShell.
#  3) Ensures sshd is running + auto-start.
#  4) (if -PubKey) installs the key into administrators_authorized_keys with correct ACLs
#     -- the admin-account location; ~/.ssh/authorized_keys is IGNORED for admins.
#  5) (if -DisablePassword, requires -PubKey) turns off password auth.
param(
  [string]$PubKey,
  [switch]$DisablePassword
)

$AllowedSubnets = @(
  "RIG_SUBNET_NAT",   # VMware NAT (VMnet8)
  "RIG_SUBNET_HOSTONLY"    # VMware host-only (VMnet1)
  # "RIG_SUBNET_BRIDGED"   # <- uncomment if Kali is BRIDGED onto your LAN
)

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host "Not elevated. Re-run this in an Administrator PowerShell." -ForegroundColor Red; exit 1
}

Write-Host "[1/5] Scoping SSH firewall to VM subnets..." -ForegroundColor Cyan
foreach ($rule in @("OpenSSH-Server-In-TCP","OpenSSH SSH Server (sshd)","OpenSSH-Server")) {
  $r = Get-NetFirewallRule -Name $rule -ErrorAction SilentlyContinue
  if (-not $r) { $r = Get-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue }
  if ($r) { $r | Set-NetFirewallRule -RemoteAddress $AllowedSubnets; Write-Host "   scoped: $($r.DisplayName)" -ForegroundColor Green }
}

Write-Host "[2/5] Setting default SSH shell to PowerShell..." -ForegroundColor Cyan
$pwsh = (Get-Command powershell.exe).Source
New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value $pwsh -PropertyType String -Force | Out-Null
Write-Host "   DefaultShell = $pwsh" -ForegroundColor Green

Write-Host "[3/5] Ensuring sshd is running + automatic..." -ForegroundColor Cyan
Set-Service sshd -StartupType Automatic
Start-Service sshd -ErrorAction SilentlyContinue
Get-Service sshd | Select-Object Name,Status,StartType | Format-Table -AutoSize

if ($PubKey) {
  Write-Host "[4/5] Installing admin SSH key..." -ForegroundColor Cyan
  $f = "$env:ProgramData\ssh\administrators_authorized_keys"
  if (Test-Path $f) { Add-Content $f $PubKey -Encoding ascii } else { Set-Content $f $PubKey -Encoding ascii }
  icacls $f /inheritance:r /grant "Administrators:F" /grant "SYSTEM:F" | Out-Null
  Write-Host "   key added to $f (ACL: Administrators+SYSTEM only)" -ForegroundColor Green
} else {
  Write-Host "[4/5] No -PubKey given -- skipping key install (still on password auth)." -ForegroundColor DarkYellow
}

if ($DisablePassword) {
  if (-not $PubKey -and -not (Test-Path "$env:ProgramData\ssh\administrators_authorized_keys")) {
    Write-Host "[5/5] Refusing to disable password auth with no key installed (you'd lock yourself out)." -ForegroundColor Red
  } else {
    Write-Host "[5/5] Disabling password auth..." -ForegroundColor Cyan
    $cfg = "$env:ProgramData\ssh\sshd_config"
    $c = Get-Content $cfg
    if ($c -match '^\s*#?\s*PasswordAuthentication') {
      $c = $c -replace '^\s*#?\s*PasswordAuthentication.*', 'PasswordAuthentication no'
    } else { $c += 'PasswordAuthentication no' }
    Set-Content $cfg $c -Encoding ascii
    Restart-Service sshd
    Write-Host "   PasswordAuthentication no  (key-only now)" -ForegroundColor Green
  }
} else {
  Write-Host "[5/5] Leaving password auth on (pass -DisablePassword once your key works)." -ForegroundColor DarkYellow
}

Write-Host "`nDone. From Kali:  ssh user@RIG_IP" -ForegroundColor Yellow
Write-Host "Password (if still on) = your MICROSOFT ACCOUNT password, not your PIN." -ForegroundColor Yellow
