# 构建指南

## 快速开始

```powershell
.\build.ps1                 # 构建全部四个变体（beacon/dnsb/extc2/pivot）的 x64 Release
.\build.ps1 -Project dnsb   # 单独构建某个变体
.\build.ps1 -Project beacon -HttpLibrary winhttp  # CS 4.9 WinHTTP 套筒 winhttpb.x64.dll
.\build.ps1 -Project beacon -Platform Win32       # x86 套筒 beacon.dll（需 lib/tomcrypt.x86.lib）
.\tests\run_tests.ps1       # 编译并运行宿主机侧测试（需 MSVC 环境）
```

产物：`x64\Release\<name>.x64.dll` 或 `Win32\Release\<name>.dll` + 同名 `.map`。
`-HttpLibrary winhttp` 时 x64 产物为 `winhttpb.x64.dll`（TS 槽明文上限 309248 B）；
x86 wininet 槽 `sleeve/beacon.dll` 明文上限 **247808**（编码 247840-32）。
x86 库：CI `dll-x86` 作业用 `thirdparty/build_trimmed.ps1 -Arch x86` 现编，不提交 `lib/*.x86.lib`。

## 工具链（CI 实证 2026-08-29 修订）

| 项 | 默认 | 说明 |
|---|---|---|
| 工具集 | v142（common.props 默认） | **CI 已用 v143 全绿**（4 变体 + 测试），v143 可编本项目是实证事实。原作者记录的"v143 ICE / v141 崩溃"降级为其环境经验值；若在别的环境复现编译问题，再按经验值切回 v142 |
| SDK | 10.0.19041.0 | CI（windows-2022 镜像含 19041）已验证；26100 仅跑过测试目标 |
| 编译器架构 | 64 位 cl（HostX64） | common.props 已锁 `PreferredToolArchitecture=x64`；32 位 cl 编大模板会 C1060 |
| LTCG | 关 | 保持关闭 |

以上默认值集中在 `common.props`，命令行可用 `/p:BeaconToolset=` `/p:BeaconSDK=` 覆盖；
CI（`build.yml`）显式以 `-Toolset v143` 运行——让"工具链漂移"在 CI 上尽早暴露。

## 工程布局

- `common.props` —— 四变体共享的构建属性（工具集/SDK/库路径/Release 策略/MAP 生成）。
  各 vcxproj 仅保留差异项（预处理宏、目标名）。**不要**把共享设置改回各工程内部。
- `lib\` —— vendored 预编译依赖（`tomcrypt.x64.lib`/`tommath.x64.lib`），
  版本与验收要求见 `lib\VERSIONS.md`。头文件是 LTC 1.17，与 lib 配对，
  不可单独替换其一。
- `thirdparty\` —— 精简重编 LTC/LTM 的配方与脚本（有网环境执行）。
- `.github\workflows\build.yml` —— CI：4 变体构建 + 体积上报 + 测试。

## 体积硬约束（stageless 部署相关）

CS 的 stageless 容器 `artifact64big.exe` 把 beacon DLL 写进自身 `.data` 节：
RawSize `0x42600` = 271872 B，扣 20 B 头 → **payload 上限 271852 B**，
超限会覆盖导入表导致 stageless exe 起 `0xC000007B`。
构建产物若需进入该容器，构建后必须核对体积（`build.ps1` 不做此项，
容器侧打包属于部署流程，不在本仓库范围）。

若体积超标，优先走 `thirdparty/` 的库源码级精简，而不是链接期符号桩
（历史方案，脆弱且依赖 lib 二进制细节，新库构建后即无必要）。

## 测试

- `tests\` 下为宿主机侧 console 程序，不涉及注入/网络，MSVC 环境即可编译运行；
- `tests\test_crypto.cpp` 同时是 C2 线缆协议加密层的可执行规格
  （见 `docs\WIRE-PROTOCOL.md`），替换任何依赖库后必须全绿；
- CI 每次推送自动运行。

推送、下载 artifact、CrackSleeve 套筒、patch TeamServer、Headless 矩阵活测：见 `docs/LIVE-OPS.md`。功能完成度见 `docs/MATRIX.md`。
