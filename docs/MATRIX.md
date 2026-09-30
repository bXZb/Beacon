# 功能与矩阵完成度（2026-09-11）

范围：`CobaltStrikeBeaconCppSource-main` 分支 **`4.9.1`**，官方 4.9.1 TeamServer（`192.168.100.98:50050`），探针机 `192.168.100.198`。

图例：**过** = 活体对官方 TS 行为符合；**失败** = 已测且未过；**范围外** = 明确未做，不要当缺口。

判定只认 **OUTPUT / ALT / PS / LS / DATA_STORE / CHECKIN 字节 / screenshot 文件**。TASKED 只说明任务入队。空闲 GET 经常没有 CHECKIN，用 lastf。

---

## 1. 总览

| 通道 / 架构 | 主循环 | 核心任务矩阵 | cmd 117（store EA） | 备注 |
|---|---|---|---|---|
| HTTP WinINet x64 | **过** | **过** | **过** `grok-ea-117` | 父会话曾用 `988387210` / `1403836542` |
| HTTP WinHTTP x64（我方 `winhttpb.x64.dll`） | **过** | **过**（B1 子集） | **过** `grok-ea-117` | 子 `1204167688` CHECKIN **290312**；旧 `1117505292` lastf 31h 已不用 |
| HTTP WinINet x86（我方 `beacon.dll`） | **过** | **核心过** | **过** `grok-ea-117` | GargleSleep 堆分配；store EA 同架构；见 §4.1 |
| dnsb / SMB·TCP pivot / ExtC2 | — | — | — | **范围外**（C1 完成前不做） |
| UDRL / rl0k | — | — | — | **范围外** |
| Post-Ex prepend | — | — | — | **范围外** |
| steal `PROCESS_QUERY_LIMITED_INFORMATION`（A3） | — | — | — | **范围外**；跨会话 ERROR 5 是官方语义 |

---

## 2. x64 WinINet（完整）

证据：`docs/LIVE-HTTP-X64.md`。会话 `988387210` 等。

| 项 | 结论 |
|---|---|
| checkin / 不掉线 / Cookie RSA-1024 128B | **过** |
| spawn + exit | **过** |
| pwd / cd / ls / ps / shell / getuid | **过** |
| steal 同会话 + rev2self + token-store | **过** |
| steal 跨会话 | **官方语义** ERROR 5 |
| syscall None/Direct/Indirect 运行时 + 生成期 Direct | **过** |
| clipboard BOF cmd 100 | **过** |
| data-store add/list/remove + cmd 116 BOF | **过** |
| upload / download | **过** |
| screenshot / keylogger + jobkill | **过**（screenshot 缺 sleeved postex-loader，回落 jar） |
| SOCKS5 TCP | **过**（绑 TS，不是 Windows 客户端） |
| SOCKS5 UDP ASSOCIATE | **过**（DST.PORT 必须是本机 UDP 端口，禁止 `0.0.0.0:0`） |
| Host Profiles | **过** |
| Guardrails 匹配上线 / 不匹配无 INITIAL | **过** |
| sleep_mask ON / OFF | **过** |
| **cmd 117** store execute-assembly | **过**，OUTPUT `grok-ea-117` |

---

## 3. x64 WinHTTP 我方套筒

CI `winhttpb.x64.dll` 槽 `0x05624CC0`（编码 cap 309280）。B1 子 `1117505292`（已 stale）。cmd 117 补测子 **`1204167688`**（2026-09-11，CHECKIN **290312** = 明文 290304+8，profile 当时 `r2_winhttp`，随后 TS 已改回 `r2_nosm`）。

过：spawn/INITIAL、syscall Direct、pwd/ps/ls/shell、getuid、steal+rev2self、clipboard、cmd 116、upload/download、screenshot、SOCKS5 TCP、**cmd 117** store EA `grok-ea-117`。

2026-09-23 补测（profile `r2_winhttp`，子 **`952730060`** pid **2508**，CHECKIN **290312**，随后 TS 已改回 `r2_nosm`）：

| 项 | 结论 |
|---|---|
| 运行时 syscall Indirect → Direct | **过** `Current syscall method: Indirect/Direct` |
| token-store steal + show | **过** `TOKEN_STEAL` / `TOKEN_STORE` `Administrator (admin)` |
| keylogger | **过** TASKED + CHECKIN **83770**（作业下发） |
| SOCKS5 UDP ASSOCIATE | **过（复测）** ASSOCIATE 须等 implant 下一轮 CHECKIN（sleeptime 60s）；12s 超时是测试窗口不是套筒。`c1_winhttp_four.py` 90s 过 |
| Host Profiles `http_hp` | **过（复测）** hosts `192.168.100.98 hp1.test.local` 后 INITIAL `1903551958` + pwd |
| Guardrails | 旧 `http_gok` 仍 33。匹配 `http_whgok` **过**。不匹配 `http_whgbad` **过**（CHECKIN 290312、无 INITIAL） |
| sleep_mask true | **过（真掩码，2026-09-30）**。`5c753e1`：自建 PE 掩码表（跳 .pdata/.fptable/.reloc），子 `1305512946` 3+ 掩码睡眠周期存活、pwd 过、reloc=0、还原 diffs=0。根因=TS 下发表按官方布局，pair 5 打中我们 .pdata 的 CRT unwind 条目 → 窗口期异常分发 fail-fast。详见 `SLEEP-MASK-FEEDBACK.md` |

---

## 4. x86 WinINet 我方套筒

明文 cap **247808**，编码 cap **247840**，槽 `0x054968E0`。profile `r2_nosm.profile`（`syscall_method "Direct"`，`sleep_mask false`）。

**上线修复（保留）**：`GargleSleep` 16KB 改堆分配，避免 x86 `__chkstk` 第一次 GET 后死。与 cmd 117 无关。

| 项 | 结论 | 证据摘要 |
|---|---|---|
| spawn x86 / INITIAL / 二次 checkin | **过** | GargleSleep 修复后主循环稳定 |
| pwd / ls / shell / getuid / ps | **过** | |
| syscall Direct | **过** | |
| steal 同会话 + rev2self | **过** | |
| clipboard cmd 100 | **过** | `clipboard.x86.o` |
| data-store + **cmd 116** BOF | **过** | |
| upload / download | **过** | |
| screenshot | **过**（同架构作业） | |
| keylogger | **过** | |
| SOCKS TCP + UDP | **过** | |
| Host Profiles | **过** | 子 `1146059844` |
| sleep_mask true | **过** | 子 `1975336374` lastf 56s→11s |
| **cmd 117** store EA | **过** | 见 §4.1；收敛后再测仍过 |
| 非 store `execute_assembly` | **过** | 子 `1026850514`：无 Data Store 横幅，CHECKIN **112904**，OUTPUT `grok-ea-117` |
| hashdump | **过** | 同子；SAM hashes + 后再 pwd |
| mimikatz | **过** | 子 `1026850514`：`privilege::debug` → OUTPUT `Privilege '20' OK`；后再 pwd |

### 4.1 x86 cmd 117（2026-09-11 过）

官方 store EA 在 x86 上是 **同架构作业**（`ExecuteAssemblyJob`：`beacon.is64() ? x64 : x86` → inner 70/87，x86 `invokeassembly.dll`）。不要用 Heaven’s Gate / `spawn_patsy(TRUE)` 当修复。

过线活测（implant **`1ffbde2`** 仍含探针，Headless `grok-hl117k`）：

| 项 | 值 |
|---|---|
| 父 | `890778478` / pid **17600** `beacon_x64.exe` |
| spawn CHECKIN | **245768** B |
| 子 | **463543496** / pid **1216** |
| 进程标记 | CI `TimeDateStamp` + ReWolf；**无**官方 `0x64F88C5F` |
| store | **Stored** index 0 |
| banner | `Executing the .NET program from Data Store` |
| OUTPUT | **`grok-ea-117`**（无 `0x8007000b`） |
| EA 后再 pwd | PASS |

**收敛后再测（`b243338` / CI `34593437113`，无 `cmd117probe`）**：Headless `grok-hl117m`，overlay 明文 ts **`0x6AA3E415`**，编码头 `9b980d33…`。子 **`1026850514`** pid **13476**。SCAN `ci_ts`×4 ReWolf×2 **probe=0** stock=0。store 117 仍 OUTPUT **`grok-ea-117`**。unload 完成后再非 store EA：**无** Data Store 横幅，CHECKIN **112904**，OUTPUT **`grok-ea-117`**。hashdump OUTPUT 含 `Administrator:500:aad3b435…`，随后 pwd 仍过。

真修复（保留）：

- **`1050045`**：68 字节 guardrails needle 只留在 `guard_region`，避免 Java `indexOf` 盖掉 LTC / 公钥 → checkin 前 `abort`
- **`1ffbde2`**：cmd 117 作业参数 = store 余下的 `[len][assembly]` + extra 宽参数，不再把 extra 单独当 CLR 输入

排查插桩已从树里拿掉（**`b243338`**）：`cmd117_probe.h`、管道 `'1'/'2'/'3'`、`C:\Users\Public\cmd117_force_x86`。注入仍是 `9539bb2` 行为。CI 收敛后全绿：https://github.com/bXZb/Beacon/actions/runs/34592888623

交付：`bspawn` 走 Headless `exportLocal`，overlay **client jar** + CWD 影子，不是 TS 槽。步骤见 `docs/LIVE-OPS.md`；经过见 `docs/CMD117-X86-FEEDBACK.md` 结案、`docs/CMD117-X86-DELIVERY.md`。

hello.exe：`cs-agscript-mcp/scripts/ea/hello.exe`（PE x86 / 0x14c），stdout `grok-ea-117`。

---

## 4.2 三 DLL 全量回归（2026-09-30 晚，HEAD 5c753e1，CI 36700547283）

`regr_drive.py`（scripts/）对三条已过线通道整体重测，套筒=当日 CI 重新编码 overlay（jar 备份 `.pre_regr_E51B9BD2`）：

| DLL | profile / listener | spawn 针 | 结果 |
|---|---|---|---|
| beacon.x64.dll | r2_nosm / http | **292872** | **21/21 过**：pwd/ls/ps/shell/getuid、upload+download 回环（47B）、steal(`Impersonated`)+rev2self(静默)、clipboard(1488B)、syscall 查询+Indirect+Direct、data-store 存/列/卸、cmd117 store EA、keylogger、screenshot、矩阵后存活 |
| winhttpb.x64.dll | r2_winhttp / http_wh2 | **291848** | **10/10 过**：pwd/ls/ps/shell/getuid、data-store、cmd117 store EA |
| winhttpb.x64.dll（sleep_mask true） | r2_winhttp_sm / http_wh2 | 291848 | **过**：2+ 掩码睡眠周期存活（lastf=1s）、pwd、0 reloc 错误 |
| beacon.dll (x86) | r2_nosm / http | **245768** | **11/11 过**：pwd/ls/shell/getuid、hashdump（`Administrator:500:aad3b435…`）、mimikatz（`Privilege '20' OK`）、非 store EA + cmd117 store EA（两次 `grok-ea-117`） |

驱动脚本判定期望的四个已知坑（非 beacon 缺陷，原始日志均验证）：upload 成功静默（用 download 回环判定）、rev2self 静默、data-store 存/卸确认走 OUTPUT 类型（非 DATA_STORE）；sleep 单位是秒。测试后 TS 已回 `r2_nosm`，进程已清。

## 5. 本机不编、以 CI 为准

本工作站无 MSVC。C++ 对错只看 GitHub Actions `build.yml`：

- `dll`：beacon/dnsb/extc2/pivot x64 + beacon WinHTTP
- `dll-x86`：现场编 trimmed x86 lib → `Win32\Release\beacon.dll`
- `tests`：宿主机单测（`BEACON_TEST_ENABLE_KEYGEN`）

推送与套筒步骤见 `docs/LIVE-OPS.md`。C1 已结案后的下一会话：`docs/NEXT-HANDOFF.md`（mimikatz、WinHTTP 未重复项、dnsb）。
