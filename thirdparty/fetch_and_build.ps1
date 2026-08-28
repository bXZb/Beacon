<#
.SYNOPSIS
  拉取 LibTomCrypt 1.17 / LibTomMath 1.3.0 源码并构建精简版 lib（P4.16）。

.DESCRIPTION
  需要有网环境 + git + MSVC（Developer Command Prompt 或 msvc-dev-cmd）。
  步骤细节与验收标准见同目录 README.md。构建成功后手动核对验收项，
  再替换 lib/ 下的 vendored 库。
#>
[CmdletBinding()]
param(
    [string]$LtcVersion = 'v1.17',
    [string]$LtmVersion = 'v1.3.0',
    [string]$WorkDir = "$PSScriptRoot\_src"
)

$ErrorActionPreference = 'Stop'

Write-Host '==> check toolchain' -ForegroundColor Cyan
foreach ($tool in @('git', 'nmake')) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        throw "missing tool: $tool (run from VS Developer Command Prompt?)"
    }
}

New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
Push-Location $WorkDir
try {
    # ---- libtommath ----
    if (-not (Test-Path 'libtommath')) {
        Write-Host "==> clone libtommath $LtmVersion"
        & git clone --depth 1 --branch $LtmVersion https://github.com/libtom/libtommath
    }
    # ---- libtomcrypt ----
    if (-not (Test-Path 'libtomcrypt')) {
        Write-Host "==> clone libtomcrypt $LtcVersion"
        & git clone --depth 1 --branch $LtcVersion https://github.com/libtom/libtomcrypt
    }

    # ---- 应用精简配置 ----
    Write-Host '==> apply trimmed tomcrypt_custom.h'
    $customSrc = "$PSScriptRoot\tomcrypt_custom_min.h"
    $customDst = "$WorkDir\libtomcrypt\src\headers\tomcrypt_custom.h"
    if (-not (Test-Path $customDst)) { throw "unexpected libtomcrypt layout: $customDst missing" }
    Copy-Item $customSrc $customDst -Force
    Write-Warning '源码补丁（ltm_desc 死指针置 NULL / toom cutoff 抬高）需按 README 第 3 步手工应用'

    # ---- 构建 ----
    Push-Location "$WorkDir\libtommath"
    & nmake -f makefile.msvc
    if ($LASTEXITCODE -ne 0) { throw "libtommath build failed" }
    Pop-Location

    Push-Location "$WorkDir\libtomcrypt"
    & nmake -f makefile.msvc
    if ($LASTEXITCODE -ne 0) { throw "libtomcrypt build failed" }
    Pop-Location

    Write-Host '==> done. artifacts:' -ForegroundColor Green
    Get-ChildItem -Recurse -Include *.lib | Format-Table FullName, Length -AutoSize
    Write-Host '下一步：按 README 第 5 步跑验收（tests + MAP 检查）后替换 lib/。'
}
finally {
    Pop-Location
}
