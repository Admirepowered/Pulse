@echo off
setlocal
set "PATH=D:\msys64\mingw64\bin;%PATH%"
cd /d "%~dp0"
.\bin\vless_proxy.exe run %*
