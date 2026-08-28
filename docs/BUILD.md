# 构建指南

## 快速开始

```powershell
.\build.ps1                 # 构建全部四个变体（beacon/dnsb/extc2/pivot）的 x64 Release
.\build.ps1 -Project dnsb   # 单独构建某个变体
.\tests\run_tests.ps1       # 编译并运行宿主机侧测试（需 MSVC 环境）
```

产物：`x64\Release\<name>.x64.dll` + 同名 `.map`（供 .obj 级体积归因），
同时拷贝到 `bin\`。

## 工具链约束（实机踩坑结论，勿凭记忆覆盖）

| 项 | 要求 | 原因 |
|---|---|---|
| 工具集 | **v142 (14.29)** 默认 | v143 在部分环境触发 `winnt.h C1017` / `winreg.h C1001` ICE；v141 (14.16) 有 CL.exe `0xC0000409` 崩溃 |
| SDK | **10.0.19041.0** 默认 | 26100 有回归 |
| 编译器架构 | 64 位 cl（HostX64） | 默认 32 位 `HostX86\x64\CL.exe` 编大文件会 C1060（4GB 地址空间限制） |
| LTCG | 关 | 开启对体积无收益且有 ICE 风险 |

以上默认值集中在 `common.props`，命令行可用 `/p:BeaconToolset=` `/p:BeaconSDK=` 覆盖；
`build.ps1 -Toolset v143` 即覆盖工具集（CI 上即如此——runner 只有 v143，
CI 冒烟的意义正是让"工具链漂移"尽早暴露）。

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
