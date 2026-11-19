@echo off
REM crack.cmd - opinionated straight dictionary attack against rockyou.
REM   crack <mode> <hashfile> [rulefile-in-rules-folder]
REM Examples:
REM   crack 1000 hashes\ntlm.txt
REM   crack 1000 hashes\ntlm.txt OneRuleToRuleThemAll.rule
REM   crack 13100 hashes\kerb.txt best64.rule   (rules live in hashcat\rules or CrackLab\rules)
setlocal
if "%~2"=="" ( echo Usage: crack ^<mode^> ^<hashfile^> [rulefile] & echo Common modes: 1000 NTLM ^| 5600 NetNTLMv2 ^| 13100 TGS ^| 18200 AS-REP ^| 22000 WPA ^| 1800 sha512crypt ^| 3200 bcrypt & exit /b 1 )
set "ROOT=%~dp0"
set "MODE=%~1"
set "HASHFILE=%~f2"
set "RULE=%~3"
pushd "%ROOT%hashcat"
if "%RULE%"=="" (
  "%ROOT%hashcat\hashcat.exe" -m %MODE% -a 0 -O -w 3 --backend-ignore-opencl -d 1 --potfile-path "%ROOT%loot\cracked.pot" "%HASHFILE%" "%ROOT%wordlists\rockyou.txt"
) else (
  REM look for the rule in CrackLab\rules first, else hashcat\rules
  if exist "%ROOT%rules\%RULE%" ( set "RPATH=%ROOT%rules\%RULE%" ) else ( set "RPATH=%ROOT%hashcat\rules\%RULE%" )
  "%ROOT%hashcat\hashcat.exe" -m %MODE% -a 0 -O -w 3 --backend-ignore-opencl -d 1 --potfile-path "%ROOT%loot\cracked.pot" -r "%RPATH%" "%HASHFILE%" "%ROOT%wordlists\rockyou.txt"
)
echo.
echo === Cracked so far (loot\cracked.pot) ===
type "%ROOT%loot\cracked.pot" 2>nul
popd
endlocal
