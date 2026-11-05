# 构建指南

权威构建是仓库根目录的 CMake 工程。GitHub Actions
（`.github/workflows/cmake.yml`）在 `windows-2022` 上执行：

```powershell
cmake -S . -B build -A x64
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

CMake 直接编译 `src/`、`udrl/`、`tests/`。不要用 `cl` 手写编译。

## LLVM 线（可选）

同一份根 `CMakeLists.txt`，换 toolchain。先编 pass 插件（host 原生编译器），再交叉编产品：

```bash
bash tools/llvm/setup-host.sh
source ~/.llvm-cross/toolpath.env
cmake -S tools/llvm/pass -B build-pass -DLLVM_DIR="$HOME/.llvm-cross/llvm/lib/cmake/llvm" -DCMAKE_BUILD_TYPE=Release
cmake --build build-pass

cmake -S . -B build-llvm -G Ninja --toolchain cmake/toolchain-clang-cl-xwin.cmake \
  -DCLANG_CL="$LLVM_CLANG" -DLLD_LINK="$LLVM_LLD" -DXWIN_DIR="$XWIN_SPLAT" \
  -DCMAKE_BUILD_TYPE=Release \
  -DBEACON_OBF_PLUGIN="$PWD/build-pass/obfpasses.so"
cmake --build build-llvm
```

产物仍在 `build-llvm/out/`，文件名与 MSVC 线相同。layout 第二遍由
`tools/llvm/apply_layout.py` 在每个 DLL 的 POST_BUILD 里跑。CI：
`.github/workflows/llvm-build.yml`。

产物在 `build/out/`：

| 文件 | 说明 |
|---|---|
| `beacon.x64.dll` | HTTP WinINET |
| `winhttpb.x64.dll` | HTTP WinHTTP |
| `dnsb.x64.dll` | DNS |
| `extc2.x64.dll` | External C2 |
| `pivot.x64.dll` | SMB/TCP pivot |
| `tests.exe` | 宿主机单元测试 |
| `load_smoke.exe` | DLL LoadLibrary 冒烟 |
| `ReflectiveLoader.x64.obj` | UDRL COFF |
| `ReflectiveLoader.rwx.x64.obj` | UDRL COFF（`BW_DIAG_RWX`） |
| `host_template_x64.exe` | 无 CRT 启动的宿主 EXE 模板 |

## 测试

编译归 CMake，运行归 CTest 或 `tests/run_tests.ps1`（后者只执行已编好的
`build/out/tests.exe`，不再调编译器）。

```powershell
ctest --test-dir build -C Release --output-on-failure -R host_unit
.\tests\run_tests.ps1
```

`tests/test_crypto.cpp` 是 C2 加密线缆协议的可执行规格（见
`docs/WIRE-PROTOCOL.md`）。替换 `lib/` 下的 TomCrypt 后必须全绿。

对精简重编库做验收：

```powershell
cmake -S . -B build -A x64 -DBEACON_LIB_DIR=thirdparty/out -DBEACON_TEST_EXTRA_DEFS=BEACON_TEST_ENABLE_KEYGEN
cmake --build build --config Release --target beacon_tests
ctest --test-dir build -C Release --output-on-failure -R host_unit
```

CI：`cmake.yml` 每次推送跑产品构建和 `host_unit`。`trimlib.yml` 手动触发，
用上面的 CMake 开关链 `thirdparty/out` 里的重编库。

## 工具链

| 项 | 值 |
|---|---|
| 生成器 | Visual Studio（`cmake -A x64`） |
| 编译器 | MSVC，windows-2022 默认工具集（v143） |
| CRT | `/MT`（`CMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded`） |
| 语言 | C++17，RTTI 关（`/GR-`），LTCG 关 |
| 依赖 | `lib/tomcrypt.x64.lib`、`lib/tommath.x64.lib`（见 `lib/VERSIONS.md`） |

x86 库不入库。需要 Win32 套筒时用 `thirdparty/build_trimmed.ps1 -Arch x86` 现编。

## 工程布局

- `CMakeLists.txt` / `cmake/sources.cmake` —— 产品定义（源文件、宏、链接）。
- `lib\` —— vendored 预编译 TomCrypt/TomMath。头在 `tomcrypt-headers\`，必须与 lib 成对替换。
- `thirdparty\` —— 精简重编 LTC/LTM 的配方。
- `.github/workflows/cmake.yml` —— 产品 CI。

## 体积硬约束（stageless 部署相关）

CS 的 stageless 容器 `artifact64big.exe` 把 beacon DLL 写进自身 `.data` 节：
RawSize `0x42600` = 271872 B，扣 20 B 头 → **payload 上限 271852 B**，
超限会覆盖导入表导致 stageless exe 起 `0xC000007B`。
构建产物若需进入该容器，构建后必须核对体积。容器侧打包属于部署流程，
不在本仓库 CMake 范围。

若体积超标，优先走 `thirdparty/` 的库源码级精简。
