@echo off
SETLOCAL

REM Define paths
SET EXT_DIR=%~dp0
SET NATIVE_APP_DIR=%EXT_DIR%native-messaging-app\
SET BAT_PATH=%NATIVE_APP_DIR%run_native_app.bat
SET JSON_PATH=%NATIVE_APP_DIR%native_app_manifest.json

SET BAT_PATH_UNIX=%BAT_PATH:\=/%

REM Update JSON with the correct path
powershell -Command "(Get-Content %JSON_PATH%) -replace 'path_to_script_based_on_os', '%BAT_PATH_UNIX%' | Set-Content %JSON_PATH%"

REM Add registry key for the native messaging host
REG ADD "HKCU\Software\Google\Chrome\NativeMessagingHosts\unibonn.netsec.fpki.extension" /ve /t REG_SZ /d "%JSON_PATH%" /f

echo "Installation complete."

ENDLOCAL