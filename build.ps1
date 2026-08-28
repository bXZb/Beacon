<#
.SYNOPSIS
  构建 beacon 四变体（beacon/dnsb/extc2/pivot）的 x64 Release DLL。

.DESCRIPTION
  参数化构建入口。工具集/SDK 默认取 common.props 中的 v142 / 10.0.19041.0
  （版本约束的理由见 common.props 注释与 docs/BUILD.md §工具链），
  均可用 -Toolset / -SDK 覆盖。

  产物：x64\Release\<name>.x64.dll + 同名 .map（体积归因分析用）。

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
    [string[]]$ExtraProperties = @()
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
$props = @('/p:Configuration=Release', '/p:Platform=x64')
if ($Toolset) { $props += "/p:BeaconToolset=$Toolset" }
if ($SDK)     { $props += "/p:BeaconSDK=$SDK" }
foreach ($p in $ExtraProperties) {
    $props += if ($p.StartsWith('/p:')) { $p } else { "/p:$p" }
}

$projects = if ($Project -eq 'all') { @('beacon','dnsb','extc2','pivot') } else { @($Project) }

$results = @()
foreach ($name in $projects) {
    $vcxproj = Join-Path $root "$name.vcxproj"
    if (-not (Test-Path $vcxproj)) { throw "vcxproj not found: $vcxproj" }

    Write-Host "==> Building $name (x64 Release)" -ForegroundColor Cyan
    & $msbuild $vcxproj /t:Rebuild /nologo /v:m /m:1 @props
    if ($LASTEXITCODE -ne 0) { throw "MSBuild failed for $name (exit $LASTEXITCODE)" }

    $dll = Join-Path $root "x64\Release\$name.x64.dll"
    if (-not (Test-Path $dll)) { throw "Build reported success but DLL not found: $dll" }
    $results += [pscustomobject]@{
        Project = $name
        Dll     = $dll
        Bytes   = (Get-Item $dll).Length
        Map     = (Test-Path (Join-Path $root "x64\Release\$name.x64.map"))
    }
}

Write-Host ''
$results | Format-Table Project, Bytes, Map -AutoSize
Write-Host '==> All builds OK' -ForegroundColor Green
