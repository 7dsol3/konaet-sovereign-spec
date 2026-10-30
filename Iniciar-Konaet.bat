@echo off
setlocal
title Konaet Console
cd /d "%~dp0"
if not exist "%~dp0bin\node.exe" (
  echo Baixe o asset Konaet-Console-Windows-x64.zip e extraia tudo antes de iniciar.
  echo Pelo codigo-fonte, use npm ci --ignore-scripts e npm start.
  pause
  exit /b 1
)
"%~dp0bin\node.exe" "%~dp0tools\console.mjs"
if errorlevel 1 pause
