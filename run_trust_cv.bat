@echo off
title TRUST-CV // Tactical Defense AI Operations Center
color 0A
cls

echo ===============================================================================
echo                TRUST-CV (SIH26228) - SYSTEM INITIALIZATION                     
echo        Continuous Integrity, Cryptographic Lineage ^& Provenance Sentinel       
echo ===============================================================================
echo.

:: 1. Navigate to script directory
cd /d "%~dp0"
set "PYTHONPATH=backend"

:: 2. Verify Python Runtime
python --version >nul 2>&1
if %errorlevel% neq 0 (
    color 0C
    echo [ERROR] Python 3.10+ runtime not found in PATH.
    echo Please install Python and ensure it is added to your environment variables.
    pause
    exit /b 1
)

echo [*] Python Runtime Detected:
python --version
echo.

:: 3. Create required directory tree if missing
echo [*] Checking required storage directories...
if not exist "data\manifests" mkdir "data\manifests"
if not exist "data\models" mkdir "data\models"
if not exist "data\inference_dna" mkdir "data\inference_dna"
if not exist "data\fingerprints" mkdir "data\fingerprints"
if not exist "data\drift" mkdir "data\drift"
if not exist "data\graph" mkdir "data\graph"
if not exist "data\reports\assurance" mkdir "data\reports\assurance"
if not exist "data\quarantine\attacks" mkdir "data\quarantine\attacks"
if not exist "data\fusion\assessments" mkdir "data\fusion\assessments"
echo [OK] Storage tree verified.
echo.

:: 4. Verify/Install core runtime dependencies
echo [*] Checking package dependencies...
python -c "import fastapi, uvicorn, pydantic, sqlalchemy, cryptography, PIL, numpy, httpx" >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Missing core dependencies detected. Installing lightweight requirements...
    pip install -r requirements.txt
    if %errorlevel% neq 0 (
        color 0C
        echo [ERROR] Failed to install dependencies.
        pause
        exit /b 1
    )
)
echo [OK] All dependencies active.
echo.

:: 5. Run Fast System Diagnostics (Optional quick health check)
echo [*] Executing core subsystem validation...
python -m pytest backend/tests/test_health.py backend/tests/test_crypto.py -q
if %errorlevel% neq 0 (
    color 0E
    echo [WARNING] Some diagnostics flagged issues. Check pytest output above.
    echo Press any key to continue launching anyway, or CTRL+C to abort.
    pause >nul
) else (
    echo [OK] Trust foundation and cryptographic subroutines verified.
)
echo.

:: 6. Launch Browser and FastAPI Server
echo ===============================================================================
echo  Launching TRUST-CV Defense Dashboard:
echo  API Documentation:  http://localhost:8000/docs
echo  System Dashboard:   http://localhost:8000
echo  System Status:      http://localhost:8000/api/v1/system/status
echo ===============================================================================
echo.

:: Open browser automatically after 2 seconds in background
start "" cmd /c "timeout /t 2 /nobreak >nul & start http://localhost:8000"

:: Start Uvicorn Server with live reload
python -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000 --reload

pause
