<#
.SYNOPSIS
  拉取 LibTomCrypt 1.18.2 / LibTomMath 1.3.0 源码并构建精简版 lib（P4.16）。

.DESCRIPTION
  在 CI（windows-2022 + MSVC）或本机 Developer Command Prompt 中运行。
  - LTC 套 thirdparty/tomcrypt_custom_min_1182.h（仅 AES/CBC/ECB/SHA256/HMAC/
    BASE64/MRSA/DER，PRNG 全禁用——运行时由 src/crypto.cpp 注册 processprng）
  - LTM 原样构建（1.3.0）
  - 产物输出到 thirdparty/out/{tomcrypt.x64.lib, tommath.x64.lib}
  验收：用重编库编译并运行 tests/（含 keygen 探针），见 trimlib.yml。

  所有版本引用以 lib/VERSIONS.md 的实证结论为准：vendored lib 是 1.18.2。
#>
[CmdletBinding()]
param(
    [string]$LtcVersion = 'v1.18.2',
    [string]$LtmVersion = 'v1.3.0',
    [string]$WorkDir    = "$PSScriptRoot\_src",
    [string]$OutDir     = "$PSScriptRoot\out",
    # 本机走代理时填 http://127.0.0.1:10808；CI 留空
    [string]$Proxy      = ''
)

$ErrorActionPreference = 'Stop'

function Invoke-Download([string]$url, [string]$dest) {
    if ($Proxy) {
        Invoke-WebRequest -Uri $url -OutFile $dest -Proxy $Proxy -UseBasicParsing
    } else {
        Invoke-WebRequest -Uri $url -OutFile $dest -UseBasicParsing
    }
}

# ---- 工具链检查 ----
foreach ($tool in @('tar', 'cl', 'lib')) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        throw "missing tool: $tool (须在 VS Developer Command Prompt / msvc-dev-cmd 环境中运行)"
    }
}

New-Item -ItemType Directory -Force -Path $WorkDir, $OutDir | Out-Null

# ---- 下载 + 解压 ----
$ltcTgz = Join-Path $WorkDir 'ltc.tar.gz'
$ltmTgz = Join-Path $WorkDir 'ltm.tar.gz'
if (-not (Test-Path $ltcTgz)) { Invoke-Download "https://codeload.github.com/libtom/libtomcrypt/tar.gz/refs/tags/$LtcVersion" $ltcTgz }
if (-not (Test-Path $ltmTgz)) { Invoke-Download "https://codeload.github.com/libtom/libtommath/tar.gz/refs/tags/$LtmVersion" $ltmTgz }

$ltcDir = Join-Path $WorkDir 'libtomcrypt'
$ltmDir = Join-Path $WorkDir 'libtommath'
if (-not (Test-Path $ltcDir)) {
    tar -xzf $ltcTgz -C $WorkDir
    Get-ChildItem $WorkDir -Directory -Filter 'libtomcrypt-*' | Select-Object -First 1 | Rename-Item -NewName 'libtomcrypt'
}
if (-not (Test-Path $ltmDir)) {
    tar -xzf $ltmTgz -C $WorkDir
    Get-ChildItem $WorkDir -Directory -Filter 'libtommath-*' | Select-Object -First 1 | Rename-Item -NewName 'libtommath'
}

# ---- 应用精简配置（对齐 vendored lib 的 1.18.2） ----
$customSrc = Join-Path $PSScriptRoot 'tomcrypt_custom_min_1182.h'
$customDst = Join-Path $ltcDir 'src\headers\tomcrypt_custom.h'
if (-not (Test-Path $customDst)) { throw "unexpected layout: $customDst missing" }
Copy-Item $customSrc $customDst -Force
Write-Host '==> trimmed tomcrypt_custom.h applied' -ForegroundColor Cyan

# ---- 编译 LTM 1.3.0（原样） ----
Write-Host '==> building libtommath' -ForegroundColor Cyan
Push-Location $ltmDir
try {
    $ltmSrcs = Get-ChildItem -Filter '*.c' | ForEach-Object { $_.Name }
    # /O1：体积导向（MinSpace）；v143 下 /O2 曾触发 ICE（C1001），见 docs/BUILD.md
    & cl /nologo /c /MT /O1 /W3 /D_CRT_SECURE_NO_WARNINGS $ltmSrcs
    if ($LASTEXITCODE -ne 0) { throw 'libtommath compile failed' }
    & lib /nologo /OUT:"$OutDir\tommath.x64.lib" *.obj
    if ($LASTEXITCODE -ne 0) { throw 'libtommath lib failed' }
}
finally { Pop-Location }

# ---- 编译 LTC 1.18.2（精简配置） ----
Write-Host '==> building libtomcrypt (trimmed)' -ForegroundColor Cyan
Push-Location $ltcDir
try {
    # 按子目录分组编译，避免不同目录同名 .c 的 .obj 互相覆盖
    # （如 src/prng/chacha20 与 src/stream/chacha20 的 chacha20.c）
    $objAll = @()
    $i = 0
    Get-ChildItem -Recurse -Filter '*.c' -Path 'src' |
        Group-Object { $_.DirectoryName } |
        ForEach-Object {
            $i++
            $objDir = Join-Path $ltcDir "obj\$i"
            New-Item -ItemType Directory -Force -Path $objDir | Out-Null
            $srcs = $_.Group | ForEach-Object { $_.FullName }
            # /DLTC_SOURCE：math 描述符便捷宏；LTM_DESC/USE_LTM：对齐 vendored lib
            # /I libtommath：ltm_desc.c 需要 tommath.h
            # /O1：体积导向；v143 /O2 有 ICE 前科（C1001，base64_decode.c 实证），
            #      失败的组自动降级 /Od 重试
            $common = @('/nologo', '/c', '/MT', '/W3', '/D_CRT_SECURE_NO_WARNINGS',
                        '/DLTC_SOURCE', '/DLTM_DESC', '/DUSE_LTM',
                        "/Isrc\headers", "/I$ltmDir", "/Fo:$objDir\")
            & cl @common '/O1' $srcs
            if ($LASTEXITCODE -ne 0) {
                Write-Warning "group $($_.Name) failed at /O1, retrying at /Od"
                & cl @common '/Od' $srcs
                if ($LASTEXITCODE -ne 0) { throw "libtomcrypt compile failed in $($_.Name)" }
            }
            $objAll += Get-ChildItem $objDir -Filter '*.obj' | ForEach-Object { $_.FullName }
        }
    & lib /nologo /OUT:"$OutDir\tomcrypt.x64.lib" $objAll
    if ($LASTEXITCODE -ne 0) { throw 'libtomcrypt lib failed' }
}
finally { Pop-Location }

Write-Host '==> done. artifacts:' -ForegroundColor Green
Get-ChildItem $OutDir -Filter '*.lib' | Format-Table Name, Length -AutoSize
