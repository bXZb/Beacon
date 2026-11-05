<#
.SYNOPSIS
  Run host-side unit tests. Does not compile; CMake owns the build.

  cmake -S . -B build -A x64
  cmake --build build --config Release --target beacon_tests
  .\tests\run_tests.ps1

  Against rebuilt libs:
  cmake -S . -B build -A x64 -DBEACON_LIB_DIR=thirdparty/out -DBEACON_TEST_EXTRA_DEFS=BEACON_TEST_ENABLE_KEYGEN
  cmake --build build --config Release --target beacon_tests
  .\tests\run_tests.ps1
#>
param(
    [string]$BuildDir = 'build',
    [string]$Config = 'Release',
    [string]$LibDir = '',
    [string[]]$ExtraDefines = @()
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

if ($LibDir -or $ExtraDefines) {
    throw "run_tests.ps1 no longer compiles. Reconfigure with cmake -DBEACON_LIB_DIR= and -DBEACON_TEST_EXTRA_DEFS=, then cmake --build --target beacon_tests."
}

$exe = Join-Path $root (Join-Path $BuildDir "out\tests.exe")
if (-not (Test-Path -LiteralPath $exe)) {
    throw "tests.exe not found at $exe. Run: cmake --build $BuildDir --config $Config --target beacon_tests"
}

Write-Host "==> running $exe" -ForegroundColor Cyan
& $exe 2>&1 | Tee-Object -Variable testOutput
$code = $LASTEXITCODE
if ($code -ne 0) {
    Write-Host "tests exited with $code; captured output follows:" -ForegroundColor Red
    $testOutput | ForEach-Object { Write-Host $_ }
}
exit $code
