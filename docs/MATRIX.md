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
| dnsb / SMB·TCP pivot / ExtC2 | **过** | **过** | **过**（§6.3） | 见 §6 |
| SMB·TCP pivot | **过** | **过** | — | 见 §6.1 |
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

## 7. 全量替换 + 六通道全量回归（2026-10-01 晚，HEAD ebf98d3，CI 36833611193）

### 7.1 替换范围（client + teamserver 两条链全部换成当日构建）

编码产物（CrackSleeve，明文 cap 全过）：beacon.dll 245792、beacon.x64.dll 292896、winhttpb.x64.dll 291872、dnsb.x64.dll 289312、extc2.x64.dll 280096、pivot.x64.dll 282144。

**client 链**（spawn 真正走的路，三处哈希一致）：CWD 影子 `4.9.1\out\artifacts\sleeve\`、fat jar `4.9.1.jar` 的 `sleeve/*` 条目（备份 `.pre_36833611193`）、源树备份 `4.9.1\src\sleeve\`。

**TS 链**（六槽一次打齐，sha256 逐一核对 + 尾部清零 + r2_nosm 重启）：

| `--slot` | VA | enc cap | 本轮 enc |
|---|---|---|---|
| x86 | `0x054968E0` | 247840 | 245792 |
| x64 | `0x04B40EE0` | 307232 | 292896 |
| winhttp | `0x05624CC0` | 309280 | 291872 |
| extc2 | `0x0553E9A0` | 295968 | 280096 |
| **dnsb64（新定位）** | `0x055DA860` | 304160 | 289312 |
| **pivot64（新定位）** | `0x058CD600` | 297504 | 282144 |

dnsb64/pivot64 槽定位方法：官方 client jar 的 sleeve 条目（官方编码字节）做 96B 指纹在镜像内搜索，各**唯一命中**且 slot-4 长度前缀=官方 enc 尺寸。全量备份 `TeamServerImage_patched.pre_full_36833611193`。`patch_ts.py` 已收录两个新槽。

### 7.2 回归结果（父会话本轮新引导：EXE `beacon_r2a.exe` → bid 973130948）

| 通道 | 驱动输出 | 裁定 | 关键证据 |
|---|---|---|---|
| x64 WinINet（http） | 16/21 | **21/21 过** | 四静默坑同 §4.2（upload 静默→download 47B 回环、rev2self 静默、ds 存/卸走 OUTPUT）；steal 死 PID 假失败→活 PID 9656 补测 `Impersonated DESKTOP-4CPCB7A\Administrator` + rev2self 清空 |
| x64 WinHTTP（http_wh2，r2_winhttp） | 8/10 | **10/10 过** | Stored/Removed 各 ~1s 往返、store EA `grok-ea-117` |
| x64 WinHTTP 真掩码（r2_winhttp_sm） | — | **过** | 5+ 掩码周期存活（lastf 23→38→53→回绕）、pwd 过、0 ERROR（sm_build_own_table 未动，行为与 5c753e1 一致） |
| x86 WinINet（http） | 10/11 | **11/11 过** | hashdump `Administrator:500:`、mimikatz `Privilege '20' OK`、非 store EA + store EA 双 `grok-ea-117` |
| pivot SMB bind（smb_r2b/regr2smb） | — | **过** | 双向 `established link`、pwd/shell `regr2-pivot-smb`/getuid |
| pivot TCP bind（tcp_r2b:4446） | — | **过** | 双向 link、pwd、shell `regr2-pivot-tcp` |
| extc2（ext_r2b:2222/RegrExtC2） | — | **过** | TS 给载荷 280064B（=TS 槽新构建，经 stage 变换后与 CI 明文同尺寸不同哈希，官方行为）；INITIAL+pwd/shell `regr2-extc2-ok`/getuid 全部秒级、224 帧 0 错 |
| dnsb（dns_go/go.regr.test） | — | **过** | 空 session 1907877810(=0x71b7e7b2) → task pwd → 39s 后 CHECKIN+ALT+INITIAL（bootstrap 语义复现）；shell `regr2-dnsb-ok` 22s 往返；60s 周期轮询稳定 |

过程要点：残留 8 个 extc2 监听器抢 2222（hd_ext2 先绑成功）→ 全删后 ext_r2b 正常起；`sm_drive.wait` 有 pos 追踪 bug 会报假超时（dnsb INITIAL 实际 20:37:30 已到，看原始 r1.log）；`regr_drive.py` 已修 steal PID（env）与 ds 类型期望。测试后监听器/子会话/Headless 已清，TS 留 r2_nosm。原始日志 `ci-artifacts/regr2_*.log`。

## 6. dnsb / pivot / extc2 首轮活测（2026-09-30 深夜，套筒=CI 36700547283 重新编码 overlay）

### 6.1 pivot.x64.dll —— **两种链路全过**

cna 新增 `smb_listener_create`/`tcp_listener_create`/`smb_link`/`unlink`（bind_pipe 监听器的**管道名存 `port` 选项**，payload 类型串=`windows/beacon_bind_pipe`/`bind_tcp`）。

| 链 | 步骤 | 结果 |
|---|---|---|
| SMB bind | `spawn smb_li3 x64`（staging **282159**）→ 子自动 bind `\.\pipeegr3pipe` → `established link to parent` → INITIAL | **过**（INITIAL `140939900`） |
| SMB 转发 | 经链 pwd（ALT `Current directory…`）/ shell `pivot-smb-marker`（OUTPUT）/ getuid（ALT `You are …Administrator (admin)`） | **过** |
| TCP bind | `spawn tcp_li x64`（端口 4445）→ `established link to parent` → INITIAL `1362593722` | **过** |
| TCP 转发 | pwd / shell `pivot-tcp-marker` | **过** |

要点：`beacon_link(bid, ".", listener)` 对本地已 bind 的子是**接管**语义；spawn 到 bind 监听器的载荷会自行 bind 并回连父。

### 6.2 dnsb.x64.dll —— **过线（2026-10-01 凌晨，根因定位并绕开 TS bootstrap 语义）**

**根因（反编译 4.5 jar `BeaconDNS`/`BeaconC2`/`BeaconData`/`Beacons` + dig 实证）**：TS 应答器语义——新 DNS beacon 首查 `<hexid>.<domain>` 只会 `update()` 创建**空会话**（fire 无消费者的 `beacon_initial_empty` 事件）并回 idle；**元数据信号（A=idlemask^240|x）只发给 `isCheckinRequired==true` 的会话**（= 有排队任务/SOCKS/下载/分片/pivot 子链）。无人 task 空会话 → 官方载荷也永远 idle。`isDNSBeacon` 门槛 = `(agentid & 0x4B2)==0x4B2`（官方/我方 agentid 生成均强制此位模式，验算通过）。

**操作闭环（每步 dig/wire 实证）**：spawn → 空会话出现在 dump（如 `1571999486`，pid/user 空）→ **target 空会话并 task（pwd）** → 下轮轮询应答变 `0.0.0.243`（240|1|2）→ beacon 经 `www.` 信道上传元数据 → 真会话 INITIAL → 任务经 `cdn./api.` 下行、`post.` 上行回包 → 稳态（无任务时回 idle）。

| 项 | 结果 |
|---|---|
| 监听器/显式 resolver | `dns_listener_create`（cna 键 **`dnsresolver`**=setting 66）；:53 单实例（第二个 `Address already in use` 会打残应答器） |
| 上线 | **过**：INITIAL `1571999486`（rundll32，internal=192.168.100.198，listener=dns_go） |
| 任务 | **过**：pwd（ALT `Current directory…`）、shell（OUTPUT `dnsb-marker-ok`）、多周期 CHECKIN（60s 周期）、进程持续存活 |
| 信道证据 | 轮询 `5db2cefe.go.regr.test`→idle/243 按任务状态切换（tshark）；stager 路径 `aaa.stage.<domain>` TXT 亦活（alpha 编码 stage 可下载） |

遗留：上一轮子会话在收到 243 后曾无声消失一次（WER 未捕获，本轮未复现）；后续回归若再现在意。**sing-box TUN 开启时本机 UDP:53 出站会被吞——测 DNS 须关 TUN 或加 LAN 直连。**

### 6.3 extc2.x64.dll —— **过线（2026-10-01 晨，全矩阵秒级往返）**

**关键前提**：TS 交付的 extc2 载荷来自 **TS 镜像槽 0x0553E9A0**（cap 295968），不是 client jar sleeve——必须 `patch_ts.py --slot extc2` 打槽（已打，`TeamServerImage_patched.pre_extc2_x64` 备份）。

**beacon 侧真修复与一次回滚**（槽内当前构建 `8195ac9`）：
- `926be56`/`e83a243`：SMB/extc2 通道读循环丢弃 **<4 字节的保活帧**（TS 空转储 1B 帧直接转发会把 beacon 线程杀死），且检查在解密**之前**
- ~~`39799bd` 零长度心跳帧~~ → **`8195ac9` 已回滚**：心跳发射基于对规范的误读——`block` 选项是 **TS 侧读超时**，会话循环自己推进，空闲 beacon 无需发任何帧；实测带心跳的构建输出时延 43-313s（输出帧被排在心跳后滞留），无心跳构建亚秒往返
- `patch_ts.py` 曾有 **ETXTBSY 静默失败**：对运行中镜像 `open('wb')` 写入被 Linux 拒绝，报错被输出过滤吞掉——已改为写临时文件 + `os.replace`（rename 对运行中二进制合法）

**控制器契约**（`ci-artifacts/extc2_controller.py`，全部实测钉死）：

| 规则 | 内容 |
|---|---|
| 帧格式 | 两侧 [4B 小端长][载荷]；选项帧 arch/pipename + 字面 go；载荷=PE |
| 载荷启动 | LoadLibrary 后手动调 DllMain(reason=4)（PE32+ 入口在 opt+0x10）；beacon 自 bind 管道（setting 15） |
| 写侧 | **4B 头与载荷分两条消息写**（对齐 beacon read_all 粒度；合并写→ERROR_MORE_DATA→周期结束断连） |
| 读侧 | 客户端切 PIPE_READMODE_MESSAGE：每次 ReadFile=一条消息（心跳=1B 0x00；帧=4B 头+载荷消息，8KB 拆分） |
| 线程模型 | **单线程严格交替**（同句柄另一线程阻塞 ReadFile 会把同步 WriteFile 卡死） |
| 排水 | 转发输出后 PeekNamedPipe 短窗探测，静默即回主循环取 TS dump（否则 me-beacon-TS 三边环形死锁） |
| 心跳 | **无**——空闲 beacon 不发帧（TS `block` 超时自推进）；TS 空转储 1B 帧=beacon 护栏丢弃 |

**过线证据**（子 `679261210`，listener=ext_regr，python.exe 载体）：

| 项 | 结果 |
|---|---|
| 会话 | **过**：INITIAL + alive lastf=209ms（长连接心跳 ~10Hz 持续） |
| pwd | **过**：ALT `Current directory is C:/Users/Administrator/Desktop/cobaltstrike/ci-artifacts`（1s 往返） |
| shell | **过**：OUTPUT `extc2-matrix-ok`（1s 往返） |
| getuid | **过**：ALT `You are DESKTOP-4CPCB7A/Administrator (admin)`（1s 往返） |
| 错误 | 0 ERROR 行 |

cna：`extc2_listener_create <名> <端口> <管道名>`（pipename 选项；默认 externalc2）。官方规范 `externalc2spec.pdf` 存 ci-artifacts/（含 block 选项语义=TS 空转储超时）。

## 5. 本机不编、以 CI 为准

本工作站无 MSVC。C++ 对错只看 GitHub Actions `build.yml`：

- `dll`：beacon/dnsb/extc2/pivot x64 + beacon WinHTTP
- `dll-x86`：现场编 trimmed x86 lib → `Win32\Release\beacon.dll`
- `tests`：宿主机单测（`BEACON_TEST_ENABLE_KEYGEN`）

推送与套筒步骤见 `docs/LIVE-OPS.md`。C1 已结案后的下一会话：`docs/NEXT-HANDOFF.md`（mimikatz、WinHTTP 未重复项、dnsb）。

## 8. 加固批次 1–21 + own-table 回归缺陷（2026-10-02 晨，HEAD 2050a30，CI 36897836605）

### 8.1 代码批次（全部 CI 绿）

| 批次 | 内容 | commit |
|---|---|---|
| A | 线缆/解析缺陷 ×10：pivot listen 未初始化 parser、DNS UAF、GET 末块越界、loginuser/hotbeef 泄漏、BOF entry/reloc 边界、dns 尾写、hostprof 越读（新 `setting_length`）、recv_all 前进序、security 丢帧代替 exit | 95fb5c3 |
| B | 掩码覆盖：`TRACK_MEMORY_STATIC` 类型；security 密钥/IV/密钥表入掩码；strategy/client/pivot/link/gargle/extc2/pivot-beacon 缓冲注册；metadata 栈密钥即用即清 | f69a96f |
| C | RWX 收敛：syscall 桩移出 .data（独立页 RW→RX，永不 RWX）；BOF 映射 RW + 缓存页闲置 RW；apcthread/wow64/inlineexec RW→RX 拆分 + 错误路径释放 | c1afdf6 |
| D | 收敛：`client_smb_common.h`（SMB/extc2 共体）、`channel_http_common.h`（malleable 组装公共化）、own-table 下沉 gargleint、`GARGLE_TRAMPOLINE_STUB` 宏、use_tokenzz 委托、MAX_GET 括号、死代码（tcp.c/interfaces.c/kerberos.c/registry.c/水印族 ~580 行） | 1d87bb1 |
| 修复 | **own-table 回归缺陷**：conv==1 把 info.sections（官方表）赋回 gparms 后没有重推 own 表 → 掩码窗口 fail-fast（beacon_b2.exe 实测死亡）。`gargle_own_sections` 改公开并在赋值后重跑 | 2050a30 |

教训：beacon.h 曾无 include guard（公共头引入后 sessdata 重定义）；track_memory.h 曾不自含 Windows.h。

### 8.2 回归（套筒=36897836605，client 三处 + TS 六槽全 MATCH）

**r2_nosm（掩码关）六通道全绿**：x64 WI 裁定 21/21（针=明文+8，脚本 needle 已按新尺寸修正）、x86 11/11、pivot SMB/TCP（b1pipe/4451）、extc2（B1ExtC2，秒级 3 任务）、dnsb（bootstrap 39s + shell 60s）。WinHTTP phase2 矩阵 9/9 任务全过（needle 旧值 FAIL 不计）。

**掩码开（sm true）——关键实验记录**：

- **B3 轮（01:23–01:36，r2_hostprof）**：修复后构建 3 实例全健康——wininet 父 5+ 掩码周期（pwd 过）、**x86 子 6+ 周期（x86 own-table 首测过线）**、**SMB pivot 子掩码首测过线**（GarglePipeWait 路径，历史从未测过）。
- **01:42 后（r2_winhttp_sm / 复位回 r2_hostprof / 干净重试）**：所有**新启动**实例在第一次掩码睡眠窗口消失或卡死（INITIAL 后无联系；b5 系进程消失、b3 系进程存活但零通信；无 WER dump = fail-fast 形态）。同文件 beacon_b3.exe：B3 轮实例（3016）跨多次 TS 重启持续健康、新实例必死。
- **未解**：同代码同 stage，健康（01:23–01:36）与必死（01:42+）之间无已知变量。静态推理已穷尽（own 表在 .bss 被自掩、mask 随机数、heap_records 扩张、ASLR 均无法同时解释两轮结果）。**下一步**：x64dbg GUI 附加新实例，断 gargle BOF 恢复路径（`beacon_sleep_mask_set_exec` 区间 + info.mask 联动），或对 #11/#13/#19 三改动做 bisect 构建。
- 期间发现：老 pivot 链（601008948+1310891412）在多次 TS 重启后重连并继续工作，pivot 链路本身健壮。

测试后全部进程/监听器清理，TS 复位 r2_nosm，WER LocalDumps 临时键已删。原始日志 `ci-artifacts/regr3_*.log`。
