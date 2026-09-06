<#
.SYNOPSIS
  构建 beacon 四变体（beacon/dnsb/extc2/pivot）的 x64 或 Win32 Release DLL。

.DESCRIPTION
  参数化构建入口。工具集/SDK 默认取 common.props 中的 v142 / 10.0.19041.0
  （版本约束的理由见 common.props 注释与 docs/BUILD.md §工具链），
  均可用 -Toolset / -SDK 覆盖。

  产物：x64\Release\<name>.x64.dll 或 Win32\Release\<name>.dll + 同名 .map。

.EXAMPLE
  .\build.ps1                          # 构建全部四个变体
  .\build.ps1 -Project beacon          # 只构建 beacon
  .\build.ps1 -Project dnsb -Toolset v143 -SDK 10.0.22621.0
#>
[CmdletBinding()]
param(
    # beacon|dnsb|extc2|pivot|all
    [ValidateSet('beacon','dnsb','extc2','pivot','all')]
    [string]$Project = 'all',

    # 覆盖 common.props 中的 BeaconToolset / BeaconSDK
    [string]$Toolset,
    [string]$SDK,

    # 额外传给 MSBuild 的属性（如 /p:CSOptimized=MinSpace）
    [string[]]$ExtraProperties = @(),

    # wininet (default, beacon.x64.dll / beacon.dll) | winhttp (winhttpb.*.dll)
    [ValidateSet('wininet','winhttp')]
    [string]$HttpLibrary = 'wininet',

    # x64 (default) | Win32 (CS 4.9 sleeve/beacon.dll, 明文上限 247808)
    [ValidateSet('x64','Win32')]
    [string]$Platform = 'x64'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path

# ---- 定位 MSBuild（vswhere 优先，退回常见安装路径） ----
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$msbuild = $null
if (Test-Path $vswhere) {
    $vsPath = & $vswhere -latest -products * -requires Microsoft.Component.MSBuild `
              -property installationPath
    if ($vsPath) { $msbuild = Join-Path $vsPath 'MSBuild\Current\Bin\MSBuild.exe' }
}
if (-not $msbuild -or -not (Test-Path $msbuild)) {
    foreach ($cand in @("${env:ProgramFiles}\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe",
                        "${env:ProgramFiles}\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe",
                        "${env:ProgramFiles}\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\MSBuild.exe")) {
        if (Test-Path $cand) { $msbuild = $cand; break }
    }
}
if (-not $msbuild) { throw 'MSBuild not found - is Visual Studio 2019/2022 (with MSBuild) installed?' }

# ---- 组装属性 ----
$props = @('/p:Configuration=Release', "/p:Platform=$Platform", '/p:CSOptimized=MinSpace')
if ($Toolset) { $props += "/p:BeaconToolset=$Toolset" }
if ($SDK)     { $props += "/p:BeaconSDK=$SDK" }
if ($HttpLibrary -eq 'winhttp') { $props += '/p:BeaconHttpLibrary=winhttp' }
foreach ($p in $ExtraProperties) {
    $props += if ($p.StartsWith('/p:')) { $p } else { "/p:$p" }
}

$projects = if ($Project -eq 'all') { @('beacon','dnsb','extc2','pivot') } else { @($Project) }

# 套筒明文上限：x64 wininet 走 stageless 容器 271852；x64 winhttp TS 槽 309248；
# x86 wininet sleeve/beacon.dll 编码 247840 → 明文 247808；x86 winhttp 249888-32=249856
$ceil = if ($Platform -eq 'Win32') {
    if ($HttpLibrary -eq 'winhttp') { 249856 } else { 247808 }
} elseif ($HttpLibrary -eq 'winhttp') { 309248 } else { 271852 }
$platDir = if ($Platform -eq 'Win32') { 'Win32' } else { 'x64' }

$results = @()
foreach ($name in $projects) {
    $vcxproj = Join-Path $root "$name.vcxproj"
    if (-not (Test-Path $vcxproj)) { throw "vcxproj not found: $vcxproj" }

    Write-Host "==> Building $name ($Platform Release, MinSpace, http=$HttpLibrary)" -ForegroundColor Cyan
    & $msbuild $vcxproj /t:Rebuild /nologo /v:m /m:1 @props
    if ($LASTEXITCODE -ne 0) { throw "MSBuild failed for $name (exit $LASTEXITCODE)" }

    if ($Platform -eq 'Win32') {
        $dllName = if ($HttpLibrary -eq 'winhttp' -and $name -eq 'beacon') { 'winhttpb.dll' } else { "$name.dll" }
    } else {
        $dllName = if ($HttpLibrary -eq 'winhttp' -and $name -eq 'beacon') { 'winhttpb.x64.dll' } else { "$name.x64.dll" }
    }
    $dll = Join-Path $root "$platDir\Release\$dllName"
    if (-not (Test-Path $dll)) { throw "Build reported success but DLL not found: $dll" }
    $bytes = (Get-Item $dll).Length
    $results += [pscustomobject]@{
        Project   = $name
        Dll       = $dll
        Bytes     = $bytes
        Stageless = if ($bytes -le $ceil) { "OK (+$($ceil - $bytes))" } else { "OVER (-$($bytes - $ceil))" }
        Map       = (Test-Path ([IO.Path]::ChangeExtension($dll, '.map')))
    }
}

Write-Host ''
$results | Format-Table Project, Bytes, Stageless, Map -AutoSize
$worst = ($results | Measure-Object -Property Bytes -Maximum).Maximum
if ($worst -gt $ceil) {
    Write-Host "==> WARNING: largest DLL exceeds stageless ceiling $ceil (needs more shrinking)" -ForegroundColor Yellow
} else {
    Write-Host '==> All builds OK, all within stageless ceiling' -ForegroundColor Green
}
