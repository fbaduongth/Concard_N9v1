@echo off
cd /d "%~dp0"
title ConCard AP Monitor v1.1 - Prometheus API Server
cls
echo ====================================================================
echo   KHOI CHAY HE THONG CONCARD AP MONITOR v1.1
echo ====================================================================
echo.

set "NODE_EXE=%~dp0runtime\node.exe"

if not exist "%NODE_EXE%" (
    where node >nul 2>&1
    if not errorlevel 1 (
        echo [INFO] Su dung Node.js he thong...
        set "NODE_EXE=node"
    ) else (
        echo [LOI] Khong tim thay Node.js Portable tai: %NODE_EXE%
        pause
        exit /b 1
    )
)

echo [INFO] Thu muc lam viec: %CD%
echo [INFO] File cau hinh:    %CD%\config.json
echo [INFO] Kiem tra va giai phong cong 9100 neu co tien trinh cu...

for /f "tokens=5" %%p in ('netstat -ano ^| findstr /r /c:":9100 .*LISTENING"') do (
    echo [INFO] Dong tien trinh cu PID %%p tren cong 9100...
    taskkill /F /PID %%p >nul 2>&1
)

echo [INFO] Runtime Node.js:  %NODE_EXE%
echo [INFO] Dang khoi chay Collector...
echo.
"%NODE_EXE%" standalone_ap_collector.js

pause
