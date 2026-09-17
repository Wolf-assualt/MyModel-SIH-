@echo off
title TRUST-CV // Unified Defense Platform Launcher
color 0A
cls

echo ===============================================================================
echo                TRUST-CV (SIH26228) - SYSTEM INITIALIZATION                     
echo        Continuous Integrity, Cryptographic Lineage ^& Provenance Sentinel       
echo ===============================================================================
echo.

cd /d "%~dp0"

:: 1. Start FastAPI Backend in new window if not already active
echo [*] Checking Backend status on port 8000...
powershell -Command "if (Test-NetConnection -ComputerName 127.0.0.1 -Port 8000 -InformationLevel Quiet) { exit 0 } else { exit 1 }" >nul 2>&1
if %errorlevel% equ 0 (
    echo [OK] Backend is already running on http://127.0.0.1:8000
) else (
    echo [*] Starting Backend in new terminal...
    start "TRUST-CV Backend" cmd /k "cd /d "%~dp0Block-Sentinal" && run_trust_cv.bat"
)

:: Wait for Backend to initialize and become available on port 8000
echo [*] Waiting for Backend to complete startup and become available...
:wait_backend
powershell -Command "if (Test-NetConnection -ComputerName 127.0.0.1 -Port 8000 -InformationLevel Quiet) { exit 0 } else { exit 1 }" >nul 2>&1
if %errorlevel% neq 0 (
    timeout /t 2 /nobreak >nul
    goto wait_backend
)
echo [OK] Backend is online!


:: 2. Start React Frontend in new window if not already active
echo [*] Checking Frontend status on port 5173...
powershell -Command "if (Test-NetConnection -ComputerName 127.0.0.1 -Port 5173 -InformationLevel Quiet) { exit 0 } else { exit 1 }" >nul 2>&1
if %errorlevel% equ 0 (
    echo [OK] Frontend is already running on http://localhost:5173
) else (
    echo [*] Starting Frontend dev server...
    start "TRUST-CV Frontend" cmd /k "cd /d "%~dp0frontend" && npm run dev"
)

:: 3. Open Browser
echo.
echo ===============================================================================
echo  Applications Active:
echo   - Tactical UI:   http://localhost:5173
echo   - Backend Docs:  http://localhost:8000/docs
echo   - Backend API:   http://localhost:8000
echo ===============================================================================
echo.
timeout /t 2 /nobreak >nul
start http://localhost:5173
