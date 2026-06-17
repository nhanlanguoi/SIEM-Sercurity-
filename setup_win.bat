@echo off
setlocal EnableExtensions

REM Setup SIEM Stack for Windows with Docker.
REM Elasticsearch, Kibana, Redis, and Filebeat run in containers.
REM Node.js SIEM Engine runs on Windows host.

set "SIEM_DIR=%~dp0"
cd /d "%SIEM_DIR%"

echo.
echo =====================================================
echo   SIEM Windows Docker Setup
echo   Folder: %SIEM_DIR%
echo =====================================================
echo.

where docker >nul 2>nul
if errorlevel 1 (
  echo [ERROR] Khong tim thay Docker.
  echo         Hay cai Docker Desktop va bat WSL2 backend truoc.
  exit /b 1
)

docker compose version >nul 2>nul
if errorlevel 1 (
  echo [ERROR] Docker Compose chua san sang.
  echo         Hay cap nhat Docker Desktop len ban moi.
  exit /b 1
)

where node >nul 2>nul
if errorlevel 1 (
  echo [ERROR] Khong tim thay Node.js trong PATH.
  echo         Hay cai Node.js LTS: https://nodejs.org/
  exit /b 1
)

echo [1/4] Cai Node dependencies...
call npm install
if errorlevel 1 (
  echo [ERROR] npm install that bai.
  exit /b 1
)

echo.
echo [2/4] Tao file log neu chua co...
if not exist "security.log" type nul > "security.log"
if not exist "alerts.log" type nul > "alerts.log"

echo.
echo [3/4] Keo Docker images cho Elasticsearch, Kibana, Redis, Filebeat...
docker compose pull
if errorlevel 1 (
  echo [ERROR] docker compose pull that bai.
  exit /b 1
)

echo.
echo [4/4] Kiem tra config Docker Compose...
docker compose config >nul
if errorlevel 1 (
  echo [ERROR] docker-compose.yml khong hop le.
  exit /b 1
)

echo.
echo =====================================================
echo   Setup xong.
echo.
echo   Chay tat ca:
echo     start_all_win.bat
echo.
echo   Dich vu Docker:
echo     Elasticsearch  http://localhost:9200
echo     Kibana         http://localhost:5601
echo     Redis          localhost:6379
echo =====================================================
echo.

endlocal
