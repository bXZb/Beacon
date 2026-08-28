@echo off

:: Batch file to build the following four projects for win32 and x64
::    beacon
::    dnsb
::    extc2
::    pivot

:: Make sure we are using the correct environment.
:: The msbuild tool will pick the correct toolset based on the platform type (win32 or x64)
if not "%VisualStudioVersion%" == "11.0" (
   echo The package.bat file can only run within the VS2012 x64 Cross Tools Command Prompt window
   exit /B 1
)

:: Workaround for an issue with build tools that are case-insensitive but the
:: underlying mounted filesystem is case-sensitive.  Just make sure there is
:: a lowercase "release" directories.
:: Basically these directories will contain the *.pdb file
rd /s /q release
rd /s /q x64\release
set reqdirs=release x64 x64\release
for %%d in (%reqdirs%) do (
   if not exist "%%d" md "%%d"
)

echo -----------------------------------------------------------------------
echo Building Standard (5K Ref loader) Beacons...
echo -----------------------------------------------------------------------
set CSRefLoadSize=
set CSRefLoadSize=/p:RefLoadSize=5
set UDRLExtension=
set CSOptimized=MinSpace

set projects=beacon dnsb extc2 pivot
set platforms=win32 x64

set ERRORLEVEL=
call :BuildEm
set CALL_STATUS=%ERRORLEVEL%
if not %CALL_STATUS%==0 echo ---------- Call Failed (%CALL_STATUS%) ----------
if not %CALL_STATUS%==0 exit /B 1
if %CALL_STATUS%==0 echo ---------- Call Successful (%CALL_STATUS%) ----------
      
echo -----------------------------------------------------------------------
echo Building Beacons with Larger Ref Loader Size (UDRL)...
echo -----------------------------------------------------------------------

:: ----------
:: Build 50k?
:: ----------
:: set CSRefLoadSize=/p:RefLoadSize=50
:: set UDRLExtension=.rl50k

:: ----------
:: Build 100k?
:: ----------
set CSRefLoadSize=/p:RefLoadSize=100
set UDRLExtension=.rl100k

:: ----------
:: Build 1000k?
:: ----------
:: set CSRefLoadSize=/p:RefLoadSize=1000
:: set UDRLExtension=.rl1000k

set projects=beacon dnsb extc2 pivot

set platforms=win32
set CSOptimized=MinSpace

set ERRORLEVEL=
call :BuildEm
set CALL_STATUS=%ERRORLEVEL%
if not %CALL_STATUS%==0 echo ---------- Call Failed (%CALL_STATUS%) ----------
if not %CALL_STATUS%==0 exit /B 1
if %CALL_STATUS%==0 echo ---------- Call Successful (%CALL_STATUS%) ----------

set platforms=x64
:: Disable optimization for x64 with large ref loader space
:: (Otherwise compiles can run for a very long time...)
set CSOptimized=Disabled

set ERRORLEVEL=
call :BuildEm
set CALL_STATUS=%ERRORLEVEL%
if not %CALL_STATUS%==0 echo ---------- Call Failed (%CALL_STATUS%) ----------
if not %CALL_STATUS%==0 exit /B 1
if %CALL_STATUS%==0 echo ---------- Call Successful (%CALL_STATUS%) ----------

exit /B 0

:: ------------------------------------------------------------------------------------------
:: Loop through the projects and build each platform type
:: Example command
::    set CSOptimized=MinSpace
::    set UDRLExtension=
::    msbuild beacon.vcxproj /t:Build /p:Configuration=Release /p:Platform=win32 /p:RefLoadSize=5
:: Note: msbuild does not stop on any error does not appear to be supported with this version
:: ------------------------------------------------------------------------------------------
:BuildEm

echo =======================================================================
echo BuildEm Projects: (%projects%) Platforms: (%platforms%)
echo =======================================================================

SETLOCAL EnableDelayedExpansion

for %%p in (%projects%) do (
   for %%t in (%platforms%) do (
      echo =======================================================================
      echo Building Project: %%p Platform: %%t UDRLExtension: %UDRLExtension% CSRefLoadSize: %CSRefLoadSize% CSOptimized: %CSOptimized%
      echo =======================================================================
      set BUILD_STATUS=
      set ERRORLEVEL=
      msbuild %%p.vcxproj /t:Build /p:Configuration=Release /p:Platform=%%t %CSRefLoadSize%
      set BUILD_STATUS=!ERRORLEVEL!
      echo Build Status: !BUILD_STATUS!
      if not !BUILD_STATUS!==0 echo ---------- msbuild Failed ----------
      if not !BUILD_STATUS!==0 exit /B 1
      if !BUILD_STATUS!==0 echo ---------- msbuild Successful ----------
   )
)
exit /B 0