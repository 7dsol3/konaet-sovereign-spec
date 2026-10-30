@echo off
setlocal
cd /d "%~dp0"
"%~dp0bin\node.exe" "%~dp0tools\verify-package.mjs"
pause
