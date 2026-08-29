<#
.SYNOPSIS
  编译并运行宿主机侧测试（无需注入/反射加载，普通 console exe）。
  被 CI（.github/workflows/build.yml）与本机开发者使用；需要 MSVC 环境
  （在 Developer Command Prompt 下运行，或先由 CI 的 msvc-dev-cmd 建立）。
#>
param(
    # 链接的库目录：默认 vendored 库；重编库验收传 thirdparty\out
    [string]$LibDir = 'lib',
    # 追加的预处理定义（如 BEACON_TEST_ENABLE_KEYGEN，重编库验收时打开）
    [string[]]$ExtraDefines = @()
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

$sources = @(
    'tests/test_main.cpp',
    'tests/test_parse.cpp',
    'tests/test_bformat.cpp',
    'tests/test_settings.cpp',
    'tests/test_crypto.cpp',
    'tests/test_miniprintf.cpp',
    'tests/test_keygen.cpp',
    'src/parse.cpp',
    'src/bformat.cpp',
    'src/settings.cpp',
    'src/track_memory.cpp',
    'src/security.cpp',
    'src/crypto.cpp',
    'src/miniprintf.cpp'
)

Push-Location $root
try {
    $outDir = Join-Path $root 'tests\_build'
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null

    $defines = @('/D_CRT_SECURE_NO_WARNINGS', '/DWIN32_LEAN_AND_MEAN', '/DLTM_DESC', '/DUSE_LTM') +
               ($ExtraDefines | ForEach-Object { "/D$_" })

    & cl /nologo /W3 /EHsc /MT @defines `
        /Isrc /Itomcrypt-headers `
        $sources `
        /Fe:"$outDir\tests.exe" /Fo:"$outDir\" `
        /link /LIBPATH:$LibDir ws2_32.lib advapi32.lib tomcrypt.x64.lib tommath.x64.lib
    if ($LASTEXITCODE -ne 0) { throw "test build failed (exit $LASTEXITCODE)" }

    Write-Host '==> running tests' -ForegroundColor Cyan
    # 输出经管道捕获后回显：进程异常退出时也不丢测试现场
    & "$outDir\tests.exe" 2>&1 | Tee-Object -Variable testOutput
    $code = $LASTEXITCODE
    if ($code -ne 0) {
        Write-Host "tests exited with $code; captured output follows:" -ForegroundColor Red
        $testOutput | ForEach-Object { Write-Host $_ }
    }
    exit $code
}
finally {
    Pop-Location
}
