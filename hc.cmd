@echo off
REM hc.cmd - hashcat passthrough that fixes the working-directory gotcha and
REM locks to the RTX 3080 CUDA backend. Use exactly like hashcat, e.g.:
REM   hc -m 1000 -a 0 hashes\ntlm.txt wordlists\rockyou.txt -r rules\OneRuleToRuleThemAll.rule
REM All paths are resolved from where you called it, then it runs from hashcat\.
setlocal
set "ROOT=%~dp0"
pushd "%ROOT%hashcat"
"%ROOT%hashcat\hashcat.exe" --backend-ignore-opencl -d 1 --potfile-path "%ROOT%loot\cracked.pot" %*
popd
endlocal
