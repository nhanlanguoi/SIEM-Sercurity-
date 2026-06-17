@echo off
setlocal EnableExtensions

REM Start SIEM Stack on Windows with Docker.
REM Docker runs Elasticsearch, Kibana, Redis, Filebeat.
REM Windows host runs Node.js SIEM Engine.

set "SIEM_DIR=%~dp0"
cd /d "%SIEM_DIR%"

echo.
echo =====================================================
echo   SIEM Stack Startup for Windows Docker
echo   Folder: %SIEM_DIR%
echo =====================================================
echo.

where docker >nul 2>nul
if errorlevel 1 (
  echo [ERROR] Khong tim thay Docker. Hay cai Docker Desktop truoc.
  exit /b 1
)

docker compose version >nul 2>nul
if errorlevel 1 (
  echo [ERROR] Docker Compose chua san sang. Hay cap nhat Docker Desktop.
  exit /b 1
)

where node >nul 2>nul
if errorlevel 1 (
  echo [ERROR] Khong tim thay Node.js trong PATH. Hay cai Node.js LTS.
  exit /b 1
)

if not exist "node_modules" (
  echo [WARN] Chua co node_modules. Dang chay npm install...
  call npm install
  if errorlevel 1 exit /b 1
)

echo [1/5] Tao file log neu chua co...
if not exist "security.log" type nul > "security.log"
if not exist "alerts.log" type nul > "alerts.log"

echo.
echo [2/5] Khoi dong Elasticsearch, Kibana, Redis, Filebeat bang Docker Compose...
docker compose up -d
if errorlevel 1 (
  echo [ERROR] docker compose up that bai.
  exit /b 1
)

echo.
echo [3/5] Cho Elasticsearch san sang...
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$ready=$false; for($i=0; $i -lt 60; $i++){ try { $r=Invoke-RestMethod -Uri 'http://localhost:9200/_cluster/health' -TimeoutSec 2; if($r.status -eq 'green' -or $r.status -eq 'yellow'){ Write-Host ('  Elasticsearch ready: ' + $r.status); $ready=$true; break } } catch { Start-Sleep -Seconds 2 } }; if(-not $ready){ exit 1 }"
if errorlevel 1 (
  echo [ERROR] Elasticsearch chua san sang sau 120 giay.
  echo         Xem log: docker compose logs elasticsearch
  exit /b 1
)

echo.
echo [4/5] Cai replica=0 cho single-node cluster...
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$body = @{ index_patterns = @('*'); settings = @{ number_of_replicas = 0 } } | ConvertTo-Json -Depth 5; Invoke-RestMethod -Method Put -Uri 'http://localhost:9200/_template/default_settings' -ContentType 'application/json' -Body $body | Out-Null"

echo.
echo [5/5] Khoi dong SIEM Engine Node.js tren Windows host...
start "SIEM Engine" /D "%SIEM_DIR%" cmd /k "node app.js"

echo.
echo =====================================================
echo   Da khoi dong stack.
echo.
echo   Elasticsearch: http://localhost:9200
echo   Kibana:        http://localhost:5601
echo   Redis:         localhost:6379
echo.
echo   Xem Docker logs:
echo     docker compose logs -f
echo.
echo   Test demo:
echo     node attacker.js
echo =====================================================
echo.

endlocal
