@echo off
REM show.cmd - print cracked hash:plaintext pairs for a given mode + hashfile
REM   show <mode> <hashfile>
setlocal
if "%~2"=="" ( echo Usage: show ^<mode^> ^<hashfile^>  & exit /b 1 )
set "ROOT=%~dp0"
set "HASHFILE=%~f2"
pushd "%ROOT%hashcat"
"%ROOT%hashcat\hashcat.exe" -m %~1 "%HASHFILE%" --show --potfile-path "%ROOT%loot\cracked.pot"
popd
endlocal
