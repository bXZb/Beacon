# 功能与矩阵完成度（2026-09-11）

范围：`CobaltStrikeBeaconCppSource-main` 分支 **`4.9.1`**，官方 4.9.1 TeamServer（`192.168.100.98:50050`），探针机 `192.168.100.198`。

图例：**过** = 活体对官方 TS 行为符合；**失败** = 已测且未过；**范围外** = 明确未做，不要当缺口。

判定只认 **OUTPUT / ALT / PS / LS / DATA_STORE / CHECKIN 字节 / screenshot 文件**。TASKED 只说明任务入队。空闲 GET 经常没有 CHECKIN，用 lastf。

---

## 1. 总览

| 通道 / 架构 | 主循环 | 核心任务矩阵 | cmd 117（store EA） | 备注 |
|---|---|---|---|---|
| HTTP WinINet x64 | **过** | **过** | **过** `grok-ea-117` | 父会话曾用 `988387210` / `1403836542` |
| HTTP WinHTTP x64（我方 `winhttpb.x64.dll`） | **过** | **过**（B1 子集） | 未在该子会话重复（通道无关，WinINet 已过） | 子 `1117505292` `http_wh2:8091` |
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

CI `winhttpb.x64.dll` 槽 `0x05624CC0`（编码 cap 309280）。子 `1117505292`。

过：spawn/INITIAL、syscall Direct、pwd/ps/ls/shell、getuid、steal+rev2self、clipboard、cmd 116、upload/download、screenshot、SOCKS5 TCP。

未在该子会话重复（WinINet 已过、通道无关）：Host Profiles、Guardrails、sleep_mask、SOCKS UDP、运行时切 syscall、token-store、keylogger、cmd 117。

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
| **cmd 117** store EA | **过** | 见 §4.1 |

### 4.1 x86 cmd 117（2026-09-11 过）

官方 store EA 在 x86 上是 **同架构作业**（`ExecuteAssemblyJob`：`beacon.is64() ? x64 : x86` → inner 70/87，x86 `invokeassembly.dll`）。不要用 Heaven’s Gate / `spawn_patsy(TRUE)` 当修复。

过线活测（implant **`1ffbde2`**，Headless `grok-hl117k`，`-XX:+UseParallelGC -Xms256m -Xmx1g`）：

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

真修复（保留）：

- **`1050045`**：68 字节 guardrails needle 只留在 `guard_region`，避免 Java `indexOf` 盖掉 LTC / 公钥 → checkin 前 `abort`
- **`1ffbde2`**：cmd 117 作业参数 = store 余下的 `[len][assembly]` + extra 宽参数，不再把 extra 单独当 CLR 输入

排查插桩已从树里拿掉（**`b243338`**）：`cmd117_probe.h`、管道 `'1'/'2'/'3'`、`C:\Users\Public\cmd117_force_x86`。注入仍是 `9539bb2` 行为。CI 收敛后全绿：https://github.com/bXZb/Beacon/actions/runs/34592888623

交付：`bspawn` 走 Headless `exportLocal`，overlay **client jar** + CWD 影子，不是 TS 槽。步骤见 `docs/LIVE-OPS.md`；经过见 `docs/CMD117-X86-FEEDBACK.md` 结案、`docs/CMD117-X86-DELIVERY.md`。

hello.exe：`cs-agscript-mcp/scripts/ea/hello.exe`（PE x86 / 0x14c），stdout `grok-ea-117`。

---

## 5. 本机不编、以 CI 为准

本工作站无 MSVC。C++ 对错只看 GitHub Actions `build.yml`：

- `dll`：beacon/dnsb/extc2/pivot x64 + beacon WinHTTP
- `dll-x86`：现场编 trimmed x86 lib → `Win32\Release\beacon.dll`
- `tests`：宿主机单测（`BEACON_TEST_ENABLE_KEYGEN`）

推送与套筒步骤见 `docs/LIVE-OPS.md`。
