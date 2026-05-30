@echo off
if "%~1"=="query" (
  if "%~2"=="HKCU\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice" (
    echo ProgId    REG_SZ    MSEdgeHTTP
    exit /B 0
  )
  if "%~2"=="HKCU\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice" (
    echo ProgId    REG_SZ    MSEdgeHTM
    exit /B 0
  )
  if "%~2"=="HKCU\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\myapp\UserChoice" (
    echo ProgId    REG_SZ    com.example.callback
    exit /B 0
  )
  if "%~2"=="HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.html\UserChoice" (
    echo ProgId    REG_SZ    MSEdgeHTML
    exit /B 0
  )
  if "%~2"=="HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.htm\UserChoice" (
    echo ProgId    REG_SZ    MSEdgeHTML
    exit /B 0
  )
  if "%~2"=="HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.xhtml\UserChoice" (
    echo ProgId    REG_SZ    MSEdgeXHTML
    exit /B 0
  )
  if "%~2"=="HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.xht\UserChoice" (
    echo ProgId    REG_SZ    MSEdgeXHTML
    exit /B 0
  )
)
echo Mock reg query unsupported: %*
exit /B 1
