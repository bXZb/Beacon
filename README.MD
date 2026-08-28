# CobaltStrike Beacon Source Code / CobaltStrike Beacon 源代码

[English](#english) | [中文](#chinese)

## English

This repository contains the source code of CobaltStrike's Beacon, which is ready to use out of the box. I purchased this from China's Xianyu trading platform.

### Why Share This?

I've decided to make this public because I'm tired of seeing people profiting from selling Beacon source code in various forms. While this repository might face DMCA takedown in the future, I believe that when a whale falls, it creates life - everyone should have the opportunity to learn.

I despise the behavior of certain individuals who have been shamelessly profiting from this for years. It's time to end this cycle.

### Dependencies

Prebuilt dependency libraries are **vendored in this repository** — no manual
preparation is needed:

1. `lib\tomcrypt.x64.lib` / `lib\tommath.x64.lib` — prebuilt (see `lib\VERSIONS.md`;
   headers in `tomcrypt-headers\` are **LibTomCrypt 1.17** and must be replaced
   together with the lib)
2. Build: VS2019/2022 with the **v142 (14.29)** toolset + **SDK 10.0.19041.0**
   (see `common.props` / `docs\BUILD.md` for why)
3. `.\build.ps1` — builds all four variants (beacon / dnsb / extc2 / pivot) as
   x64 Release DLLs, with size + MAP report
4. `.\tests\run_tests.ps1` — host-side unit tests; `tests\test_crypto.cpp`
   is the executable spec of the C2 crypto wire format
   (`docs\WIRE-PROTOCOL.md`)

Docs: `docs\BUILD.md` (build & toolchain), `docs\WIRE-PROTOCOL.md` (crypto wire
spec), `docs\CONCURRENCY.md` (threading model audit), `thirdparty\README.md`
(trimmed LibTomCrypt rebuild recipe).

### Purpose

I hope this can:
1. Provide reference for more open-source C2 projects
2. Promote the maturity of more open-source projects
3. Help improve AV/EDR detection capabilities
4. Contribute to overall cybersecurity

This is dedicated to both red and blue teams.

---

## Chinese

这个仓库包含了开箱即用的CobaltStrike Beacon源代码，购买自中国闲鱼交易平台。

### 为什么要分享？

我决定公开这份源码，因为我看不惯一些人通过各种方式变相售卖Beacon源码来牟利。虽然这个仓库未来可能会面临DMCA下架，但我相信一鲸落万物生 - 每个人都应该有学习的机会。

我很鄙夷某些人这些年来恬不知耻、反反复复的圈钱行为。是时候结束这个循环了。

### 依赖项

预编译依赖库已随仓库提供，无需手工准备：

1. `lib\tomcrypt.x64.lib` / `lib\tommath.x64.lib` —— 预编译库（版本与验收见
   `lib\VERSIONS.md`；`tomcrypt-headers\` 是 **LibTomCrypt 1.17** 头，必须与
   lib 成对替换）
2. 构建：VS2019/2022 + **v142 (14.29)** 工具集 + **SDK 10.0.19041.0**
   （原因见 `common.props` 注释与 `docs\BUILD.md`）
3. `.\build.ps1` —— 一键构建四个变体（beacon / dnsb / extc2 / pivot）的
   x64 Release DLL，输出体积与 MAP
4. `.\tests\run_tests.ps1` —— 宿主机侧测试；`tests\test_crypto.cpp` 即
   C2 加密线缆协议的可执行规格（`docs\WIRE-PROTOCOL.md`）

文档：`docs\BUILD.md`（构建与工具链）、`docs\WIRE-PROTOCOL.md`（加密协议规格）、
`docs\CONCURRENCY.md`（并发模型审计）、`thirdparty\README.md`（精简重编 LTC 配方）。

### 目的

希望这份代码能够：
1. 为更多的开源C2项目提供参考建议
2. 促进更多开源项目的成熟
3. 帮助提升AV/EDR的检测能力
4. 为网络安全做出贡献

献给各位红蓝队。

---

## Disclaimer / 免责声明

This code is for educational and research purposes only. The author assumes no responsibility for any misuse.

本代码仅用于教育和研究目的。作者对任何滥用行为不承担责任。