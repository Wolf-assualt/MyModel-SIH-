@echo off
setlocal EnableExtensions EnableDelayedExpansion

title TRUST-CV ^| SIH26228 ^| Zero-Trust CV Integrity Assurance
color 0A
cls

echo.
echo ================================================================================
echo    TRUST-CV  //  SIH26228
echo    Zero-Trust Computer Vision Integrity Assurance ^& Evidence Graph
echo    Phases 1-10 : Data / Model / Inference / Drift / Fusion / Graph / Ledger
echo ================================================================================
echo.

:: ============================================================================
:: Resolve paths relative to this .bat file
:: ============================================================================

set "ROOT=%~dp0"
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"

set "BACKEND_DIR=%ROOT%\Block-Sentinal\backend"
set "BLOCK_DIR=%ROOT%\Block-Sentinal"
set "FRONTEND_DIR=%ROOT%\frontend"

:: ============================================================================
:: Parse mode
::
:: run_trust_cv.bat
::     Development mode: backend + Vite frontend
::
:: run_trust_cv.bat demo
::     Production frontend served by backend
::
:: run_trust_cv.bat test
::     Run backend + frontend tests
::
:: run_trust_cv.bat build
::     Build frontend production bundle
:: ============================================================================

set "MODE=dev"

if /I "%~1"=="demo"  set "MODE=demo"
if /I "%~1"=="test"  set "MODE=test"
if /I "%~1"=="build" set "MODE=build"

echo  Mode: %MODE%
echo.

:: ============================================================================
:: 1. Python check
:: ============================================================================

echo [1/7] Checking Python runtime...

python --version >nul 2>&1

if errorlevel 1 (
    color 0C
    echo [ERROR] Python was not found in PATH.
    echo         Install Python 3.10+ and restart the terminal.
    pause
    exit /b 1
)

for /f "tokens=*" %%v in ('python --version 2^>^&1') do set "PY_VER=%%v"

echo       %PY_VER%

:: ============================================================================
:: 2. Backend dependency check
:: ============================================================================

echo [2/7] Checking backend dependencies...

python -c "import fastapi, uvicorn, pydantic, sqlalchemy, cryptography, PIL, numpy, onnx, onnxruntime" >nul 2>&1

if errorlevel 1 (
    echo       Missing packages detected.
    echo       Installing backend requirements...

    python -m pip install -r "%BLOCK_DIR%\backend\requirements.txt"

    if errorlevel 1 (
        color 0C
        echo [ERROR] Backend dependency installation failed.
        pause
        exit /b 1
    )

    echo       Dependencies installed.
) else (
    echo       All backend dependencies present.
)

:: ============================================================================
:: 3. Node / npm check
:: ============================================================================

if /I "%MODE%"=="demo" goto SKIP_NODE_CHECK

echo [3/7] Checking Node.js runtime...

node --version >nul 2>&1

if errorlevel 1 (
    color 0E
    echo [WARNING] Node.js was not found.
    echo           Frontend development server cannot start.
    echo           Falling back to backend-only mode.
    set "MODE=backend_only"
    goto SKIP_NODE_CHECK
)

for /f "tokens=*" %%v in ('node --version 2^>^&1') do set "NODE_VER=%%v"

echo       Node.js %NODE_VER%

if not exist "%FRONTEND_DIR%\node_modules\vite" (
    echo       Frontend node_modules not found.
    echo       Running npm install...

    pushd "%FRONTEND_DIR%"
    call npm install
    set "NPM_RESULT=!errorlevel!"
    popd

    if not "!NPM_RESULT!"=="0" (
        color 0E
        echo [WARNING] npm install failed.
        echo           Falling back to backend-only mode.
        set "MODE=backend_only"
        goto SKIP_NODE_CHECK
    )

    echo       Frontend dependencies installed.
)

:SKIP_NODE_CHECK

:: ============================================================================
:: 4. Required storage directories
:: ============================================================================

echo [4/7] Verifying storage directories...

for %%D in (
    "%BLOCK_DIR%\data\manifests"
    "%BLOCK_DIR%\data\models\manifests"
    "%BLOCK_DIR%\data\models\baselines"
    "%BLOCK_DIR%\data\models\uploads"
    "%BLOCK_DIR%\data\inference_dna"
    "%BLOCK_DIR%\data\fingerprints"
    "%BLOCK_DIR%\data\drift\baselines"
    "%BLOCK_DIR%\data\drift\reports"
    "%BLOCK_DIR%\data\fusion\assessments"
    "%BLOCK_DIR%\data\fusion\evidence"
    "%BLOCK_DIR%\data\graph"
    "%BLOCK_DIR%\data\ledger"
    "%BLOCK_DIR%\data\reports"
    "%BLOCK_DIR%\data\audit"
    "%BLOCK_DIR%\data\uploads"
    "%BLOCK_DIR%\data\quarantine\attacks"
    "%BLOCK_DIR%\data\quarantine\models"
    "%BLOCK_DIR%\data\redteam\sandbox"
    "%BLOCK_DIR%\data\redteam\results"
) do (
    if not exist "%%~D" mkdir "%%~D" >nul 2>&1
)

echo       Storage tree ready.

:: ============================================================================
:: 5. Core subsystem smoke test
:: ============================================================================

echo [5/7] Running core subsystem smoke test...

pushd "%BLOCK_DIR%"

python -m pytest backend\tests\test_config.py backend\tests\test_crypto.py backend\tests\test_database.py -q --tb=short

set "SMOKE_RESULT=!errorlevel!"

popd

if not "%SMOKE_RESULT%"=="0" (
    color 0E
    echo.
    echo [WARNING] Smoke test reported failures.
    echo         Review the test output above.
    echo.
    choice /C YN /M "Continue launching TRUST-CV"
    if errorlevel 2 exit /b 1
) else (
    echo       Core cryptographic and config subsystems verified.
)

:: ============================================================================
:: Special modes
:: ============================================================================

if /I "%MODE%"=="test" goto RUN_TESTS
if /I "%MODE%"=="build" goto RUN_BUILD

:: ============================================================================
:: 6. Launch TRUST-CV
:: ============================================================================

echo [6/7] Launching TRUST-CV services...
echo.

set "PYTHONPATH=%BACKEND_DIR%"

:: ============================================================================
:: DEMO MODE
:: ============================================================================

if /I "%MODE%"=="demo" goto LAUNCH_DEMO

:: ============================================================================
:: BACKEND ONLY MODE
:: ============================================================================

if /I "%MODE%"=="backend_only" goto LAUNCH_BACKEND_ONLY

:: ============================================================================
:: DEVELOPMENT MODE
:: ============================================================================

echo [*] Development mode selected.
echo.

:: --------------------------------------------------------------------------
:: Check backend port
:: --------------------------------------------------------------------------

powershell -NoProfile -Command "if (Test-NetConnection -ComputerName 127.0.0.1 -Port 8000 -InformationLevel Quiet -WarningAction SilentlyContinue) { exit 0 } else { exit 1 }" >nul 2>&1

if errorlevel 1 (
    echo [*] Starting backend development server...

    start "TRUST-CV Backend - port 8000" cmd /k "cd /d ""%BLOCK_DIR%"" && set ""PYTHONPATH=%BACKEND_DIR%"" && python -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000 --reload"
) else (
    echo [OK] Backend already running on port 8000.
)

:: --------------------------------------------------------------------------
:: Wait for backend
:: --------------------------------------------------------------------------

echo [*] Waiting for backend to become ready...

:WAIT_BACKEND

powershell -NoProfile -Command "if (Test-NetConnection -ComputerName 127.0.0.1 -Port 8000 -InformationLevel Quiet -WarningAction SilentlyContinue) { exit 0 } else { exit 1 }" >nul 2>&1

if errorlevel 1 (
    timeout /t 2 /nobreak >nul
    goto WAIT_BACKEND
)

echo [OK] Backend is online.

:: --------------------------------------------------------------------------
:: Check frontend port
:: --------------------------------------------------------------------------

powershell -NoProfile -Command "if (Test-NetConnection -ComputerName 127.0.0.1 -Port 5173 -InformationLevel Quiet -WarningAction SilentlyContinue) { exit 0 } else { exit 1 }" >nul 2>&1

if errorlevel 1 (
    echo [*] Starting frontend development server...

    start "TRUST-CV Frontend - port 5173" cmd /k "cd /d ""%FRONTEND_DIR%"" && npm run dev"
) else (
    echo [OK] Frontend already running on port 5173.
)

:: --------------------------------------------------------------------------
:: Wait for frontend
:: --------------------------------------------------------------------------

echo [*] Waiting for frontend to become ready...

:WAIT_FRONTEND

powershell -NoProfile -Command "if (Test-NetConnection -ComputerName 127.0.0.1 -Port 5173 -InformationLevel Quiet -WarningAction SilentlyContinue) { exit 0 } else { exit 1 }" >nul 2>&1

if errorlevel 1 (
    timeout /t 2 /nobreak >nul
    goto WAIT_FRONTEND
)

echo [OK] Frontend is online.

goto SYSTEM_READY

:: ============================================================================
:: DEMO LAUNCH
:: ============================================================================

:LAUNCH_DEMO

echo [*] Demo mode selected.
echo.

if not exist "%FRONTEND_DIR%\dist\index.html" (
    echo [!] Production frontend build not found.
    echo [*] Building frontend...

    pushd "%FRONTEND_DIR%"

    call npm run build

    set "BUILD_RESULT=!errorlevel!"

    popd

    if not "!BUILD_RESULT!"=="0" (
        color 0E
        echo [WARNING] Frontend build failed.
        echo           Backend API will still be available at:
        echo           http://localhost:8000/docs
    )
)

if not exist "%BACKEND_DIR%\app\static" mkdir "%BACKEND_DIR%\app\static"
if not exist "%BACKEND_DIR%\app\templates" mkdir "%BACKEND_DIR%\app\templates"

if exist "%FRONTEND_DIR%\dist\index.html" (
    echo [*] Syncing frontend production bundle...

    xcopy "%FRONTEND_DIR%\dist\*" "%BACKEND_DIR%\app\static\" /E /I /Y /Q >nul 2>&1

    copy /Y "%FRONTEND_DIR%\dist\index.html" "%BACKEND_DIR%\app\templates\index.html" >nul 2>&1
)

echo.
echo ================================================================================
echo  TRUST-CV LIVE
echo.
echo    Tactical Analyst UI : http://localhost:8000
echo    Backend API Docs    : http://localhost:8000/docs
echo    Backend Health      : http://localhost:8000/api/v1/system/health
echo ================================================================================
echo.

timeout /t 2 /nobreak >nul

start "" "http://localhost:8000"

pushd "%BLOCK_DIR%"

python -m uvicorn app.main:app --app-dir backend --host 0.0.0.0 --port 8000

set "BACKEND_RESULT=!errorlevel!"

popd

exit /b %BACKEND_RESULT%

:: ============================================================================
:: BACKEND ONLY
:: ============================================================================

:LAUNCH_BACKEND_ONLY

echo [*] Backend-only mode.
echo.

echo ================================================================================
echo  Backend API: http://localhost:8000/docs
echo ================================================================================
echo.

pushd "%BLOCK_DIR%"

python -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000 --reload

set "BACKEND_RESULT=!errorlevel!"

popd

exit /b %BACKEND_RESULT%

:: ============================================================================
:: SYSTEM READY
:: ============================================================================

:SYSTEM_READY

echo.
echo [7/7] System ready.
echo.

echo ================================================================================
echo  TRUST-CV LIVE
echo.
echo    Tactical Analyst UI : http://localhost:5173
echo    Backend API Docs    : http://localhost:8000/docs
echo    Backend Health      : http://localhost:8000/api/v1/system/health
echo    Ledger Verify       : http://localhost:8000/api/v1/ledger/verify
echo    Evidence Graph      : http://localhost:8000/api/v1/graph/export
echo ================================================================================
echo.

timeout /t 2 /nobreak >nul

start "" "http://localhost:5173"

echo.
echo TRUST-CV is running.
echo Close the backend/frontend terminal windows when finished.
echo.

goto END

:: ============================================================================
:: TEST MODE
:: ============================================================================

:RUN_TESTS

echo.
echo ================================================================================
echo  TRUST-CV FULL TEST MODE
echo ================================================================================
echo.

echo [TEST] Running full backend test suite...
echo.

pushd "%BLOCK_DIR%"

python -m pytest backend\tests\ -v --tb=short

set "BACKEND_RESULT=!errorlevel!"

popd

echo.
echo [TEST] Backend exit code: %BACKEND_RESULT%
echo.

echo [TEST] Running frontend tests...
echo.

pushd "%FRONTEND_DIR%"

call npm test

set "FRONTEND_RESULT=!errorlevel!"

popd

echo.
echo ================================================================================
echo  TEST RESULTS
echo.
if "%BACKEND_RESULT%"=="0" (
    echo  Backend  : PASS
) else (
    echo  Backend  : FAIL ^(exit %BACKEND_RESULT%^)
)

if "%FRONTEND_RESULT%"=="0" (
    echo  Frontend : PASS
) else (
    echo  Frontend : FAIL ^(exit %FRONTEND_RESULT%^)
)

echo ================================================================================
echo.

pause

if not "%BACKEND_RESULT%"=="0" exit /b %BACKEND_RESULT%
if not "%FRONTEND_RESULT%"=="0" exit /b %FRONTEND_RESULT%

exit /b 0

:: ============================================================================
:: BUILD MODE
:: ============================================================================

:RUN_BUILD

echo.
echo ================================================================================
echo  TRUST-CV FRONTEND BUILD
echo ================================================================================
echo.

echo [BUILD] Building frontend production bundle...
echo.

pushd "%FRONTEND_DIR%"

call npm run build

set "BUILD_RESULT=!errorlevel!"

popd

if not "%BUILD_RESULT%"=="0" (
    color 0C
    echo.
    echo [ERROR] Frontend build failed.
    echo.
    pause
    exit /b 1
)

echo.
echo [BUILD] Frontend build successful.
echo.

if not exist "%BACKEND_DIR%\app\static" mkdir "%BACKEND_DIR%\app\static"
if not exist "%BACKEND_DIR%\app\templates" mkdir "%BACKEND_DIR%\app\templates"

echo [BUILD] Copying frontend bundle into backend...

xcopy "%FRONTEND_DIR%\dist\*" "%BACKEND_DIR%\app\static\" /E /I /Y /Q >nul 2>&1

copy /Y "%FRONTEND_DIR%\dist\index.html" "%BACKEND_DIR%\app\templates\index.html" >nul 2>&1

echo.
echo ================================================================================
echo  BUILD COMPLETE
echo.
echo    Frontend bundle : frontend\dist\
echo    Backend static  : Block-Sentinal\backend\app\static\
echo    Template        : Block-Sentinal\backend\app\templates\index.html
echo.
echo    To launch production mode:
echo       run_trust_cv.bat demo
echo ================================================================================
echo.

pause
exit /b 0

:: ============================================================================
:: END
:: ============================================================================

:END

endlocal
exit /b 0