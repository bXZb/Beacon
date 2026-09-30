# Build LinuxBeaconBridge against CS 4.5 jars (AGENTS.md classpath style).
$ErrorActionPreference = "Stop"
# tools/bridge -> tools -> LinuxBeacon -> protections-artifacts
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path
$JarDir = Join-Path $Root "4.5\lib"
$Out = Join-Path $PSScriptRoot "out"
$Src = Join-Path $PSScriptRoot "LinuxBeaconBridge.java"
New-Item -ItemType Directory -Force -Path $Out | Out-Null
if (-not (Test-Path (Join-Path $JarDir "cobaltstrike.jar"))) {
    Write-Error "missing $JarDir\cobaltstrike.jar"
}
Write-Host "[javac] $Src"
& javac -encoding UTF-8 -cp "$JarDir\*" -d $Out $Src
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host "[+] classes in $Out"
Write-Host "Run example:"
Write-Host "  java -cp `"$Out;$JarDir\*`" LinuxBeaconBridge --help"
