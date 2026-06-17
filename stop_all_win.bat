@echo off
setlocal EnableExtensions

REM Stop SIEM Docker services on Windows.

set "SIEM_DIR=%~dp0"
cd /d "%SIEM_DIR%"

echo.
echo Stopping SIEM Docker services...
docker compose down

echo.
echo Docker services stopped.
echo Close the "SIEM Engine" terminal window if it is still running.
echo.

endlocal
