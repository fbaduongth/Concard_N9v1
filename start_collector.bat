@echo off
cd /d "%~dp0"
title ConCard AP Monitor v1.1 - Prometheus API Server
cls
echo ====================================================================
echo   KHOI CHAY HE THONG CONCARD AP MONITOR v1.1
echo ====================================================================
echo.

set "NODE_EXE=%~dp0runtime\node.exe"
set "NODE_ZIP=%~dp0runtime\node_portable.zip"

if not exist "%NODE_EXE%" (
    if exist "%NODE_ZIP%" (
        echo [INFO] Khoi chay lan dau: Dang giai nen Node.js Portable di kem ^(Offline^)...
        tar -xf "%NODE_ZIP%" -C "%~dp0runtime" >nul 2>&1
        if not exist "%NODE_EXE%" (
            powershell -NoProfile -ExecutionPolicy Bypass -Command "Expand-Archive -LiteralPath '%NODE_ZIP%' -DestinationPath '%~dp0runtime' -Force" >nul 2>&1
        )
        if exist "%NODE_EXE%" (
            echo [OK] Da san sang Node.js Portable tai: %NODE_EXE%
        )
    )
)

if not exist "%NODE_EXE%" (
    where node >nul 2>&1
    if not errorlevel 1 (
        echo [INFO] Su dung Node.js cai san tren he thong...
        set "NODE_EXE=node"
    ) else (
        echo [INFO] Dang tai Node.js Portable LTS tu nodejs.org ^(chi 1 lan dau^)...
        if not exist "%~dp0runtime" mkdir "%~dp0runtime"
        powershell -NoProfile -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri 'https://nodejs.org/dist/v22.14.0/win-x64/node.exe' -OutFile '%~dp0runtime\node.exe' -UseBasicParsing"
        if not exist "%NODE_EXE%" (
            echo [LOI] Khong tim thay Node.js Portable va khong the tai tu dong.
            pause
            exit /b 1
        )
        echo [OK] Da tai thanh cong Node.js Portable tai: %NODE_EXE%
    )
)

echo [INFO] Thu muc lam viec: %CD%
echo [INFO] File cau hinh:    %CD%\config.json
echo [INFO] Kiem tra va giai phong cong 9100 neu co tien trinh cu...

for /f "tokens=5" %%p in ('netstat -ano ^| findstr /r /c:":9100 .*LISTENING"') do (
    echo [INFO] Dong tien trinh cu PID %%p tren cong 9100...
    taskkill /F /PID %%p >nul 2>&1
)

if /i not "%~1"=="--no-browser" (
    start "" /b cmd /c "ping 127.0.0.1 -n 3 >nul & start http://localhost:9100/"
)

echo [INFO] Runtime Node.js:  %NODE_EXE%
echo [INFO] Dang khoi chay Collector ^(trinh duyet se tu dong mo http://localhost:9100/^)...
echo.
"%NODE_EXE%" standalone_ap_collector.js

pause
