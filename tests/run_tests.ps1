<#
.SYNOPSIS
  编译并运行宿主机侧测试（无需注入/反射加载，普通 console exe）。
  被 CI（.github/workflows/build.yml）与本机开发者使用；需要 MSVC 环境
  （在 Developer Command Prompt 下运行，或先由 CI 的 msvc-dev-cmd 建立）。
#>
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

$sources = @(
    'tests/test_main.cpp',
    'tests/test_parse.cpp',
    'tests/test_bformat.cpp',
    'tests/test_settings.cpp',
    'tests/test_crypto.cpp',
    'src/parse.cpp',
    'src/bformat.cpp',
    'src/settings.cpp',
    'src/track_memory.cpp',
    'src/security.cpp',
    'src/crypto.cpp'
)

Push-Location $root
try {
    $outDir = Join-Path $root 'tests\_build'
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null

    & cl /nologo /W3 /EHsc /MT /D_CRT_SECURE_NO_WARNINGS /DLTM_DESC /DUSE_LTM `
        /Isrc /Itomcrypt-headers `
        $sources `
        /Fe:"$outDir\tests.exe" /Fo:"$outDir\" `
        /link /LIBPATH:lib ws2_32.lib advapi32.lib tomcrypt.x64.lib tommath.x64.lib
    if ($LASTEXITCODE -ne 0) { throw "test build failed (exit $LASTEXITCODE)" }

    Write-Host '==> running tests' -ForegroundColor Cyan
    & "$outDir\tests.exe"
    exit $LASTEXITCODE
}
finally {
    Pop-Location
}
