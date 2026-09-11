# x86 cmd 117 排查反馈

接手会话写回。不要改 `CMD117-X86-HANDOFF.md`。

填完后告诉原来的会话：读 `docs/CMD117-X86-FEEDBACK.md`。

---

## 元数据

| 项 | 值 |
|---|---|
| 日期 | 2026-09-11 |
| 会话 | Composer（1+2 对照开关 + 管道埋点） |
| 代码 commit | **24d52af**（其上 e082908 引入 probe/force） |
| CI run | https://github.com/bXZb/Beacon/actions/runs/34571186915 |
| 套筒 DLL 体积（明文 / 编码） | 245760 / 245792 B |
| TS 槽核对（slot16 hex） | `4a58e46ea994782e7cba1f2226f6cda1` |
| profile | `r2_nosm` |
| Headless 用户名 | grok-hl117d |
| Defender 实时保护 | 关 |

---

## 本轮做了什么（1 + 2）

### 对照开关（实验，非最终修复）

- `src/cmd117_probe.h` + `datastore.cpp`：若存在 `C:\Users\Public\cmd117_force_x86`（或 force 管道 listening），`command_data_store_execute_assembly` 强制 `x86=TRUE` 再 `spawn_patsy`。
- **重要限制**：store 里的作业 DLL 仍是 **x64 invokeassembly**。只改 spawn 架构、不换 DLL，**不能**当作「同架构 EA 应成功」的对照组；最多观察「还会不会把 beacon 主线程卡死」。

### 管道三档埋点

- `cmd117_probe('1')`：`inject_process_logic` 入口  
- `cmd117_probe('2')`：`remote_mirror_data` 返回后  
- `cmd117_probe('3')`：`pExecuteX64` 返回后（wow64 路径）  
- 观察端：`cs-agscript-mcp/scripts/cmd117_pipe_observer.ps1`（须 `wmic process call create` 拉起；旧实例会占满 pipe）  
- 驱动：`cmd117_ab_clean.py`（严格按 child bid 认 OUTPUT）

未加回 dump / HKCU / `http_flush_post`。未把 force-x86 当最终方案。

---

## 活测会话（干净 A/B）

| 项 | A 官方 x64 作业 | B force-x86 spawn |
|---|---|---|
| x64 父 | 1403836542 / 4820 | 同左 |
| x86 子 bid / pid | **1987959988** / **9148** | **2094333652** / **5308** |
| 子 lastf（117 前） | 1s | 1s |
| 子 lastf（脚本采样） | 16s（随后 pwd 后升到 1m） | 16s |
| store 横幅 | 是 | 是 |
| CHECKIN 55B | 是 | 是 |
| OUTPUT `grok-ea-117` | **否**（严格按 child bid） | **否** |
| pwd ALT | **否**（50s 窗口内） | **否** |
| 作业子进程 | 有 rundll32 pid=6720（父=9148） | 有 rundll32 pid=7932（父=5308） |
| 探针字节 1/2/3 | **未收到**（仅 `listening sync`） | **未收到** |

---

## 探针结论（198，已过时）

198 上观察端 `listening sync`，implant 零字节。当时还不能区分 mirror vs Gate。

**本机已定位**：不是管道超时那么简单。活体 dump 里 **没有** `cmd117probe` / `cmd117_force`（ASCII 和 UTF-16 都没有），也没有 ReWolf `66 8C D8 66 8E D0`。当前 spawn 出来的 x86 套筒 **没有编进探针，也没有编进 df42b94 Gate stub**。slot16 对得上只说明编码 blob 头 16 字节一致，**不能**证明进程里跑的是那份源码。

---

## 对照结论（目前）

- [ ] **已过**
- [x] **仍失败**（官方路径仍无 `grok-ea-117`）
- [x] **本机已定位为崩溃，不是挂死**

| 假设 | 为何排除 / 修正 |
|---|---|
| 仅 VirtualAllocEx / 仅缺 ReWolf stub | **修正**：活体 Gate 仍是旧 MSF stub（`add eax,0x25` / `mov edi,[esp]`），源码里的 ReWolf **没有进这颗 x86 进程** |
| 198 lastf 爬升 = 主线程阻塞 | **修正**：EUEJDE2 上同等现象是 WOW64 `rundll32` **c0000005 退出**；TS 仍显示 alive、lastf 往上走，并留下空的 x64 作业 rundll32 |
| force-x86 应直接跑通 EA | **实验无效**：x86 进程 + x64 invokeassembly DLL，不能期望 `grok-ea-117` |
| 探针可定位卡点 | 套筒未包含探针字符串；本机用 WER dump 替代 |

---

## 本机 DESKTOP-EUEJDE2 定位（2026-09-11 15:32–15:44）

操作机就是 beacon 主机。x64 父 **890778478** / pid **17600** `beacon_x64.exe` lastf 秒级。

### 两次活测（同一条 inject 路径）

| 项 | 第一次（EA 抢在 store 完成前） | 第二次（真 cmd 117） |
|---|---|---|
| x86 子 bid / pid | 131267330 / **12112** (`0x2f50`) | 513259158 / **10044** (`0x273c`) |
| 日志 | TASKED `run .NET program` + CHECKIN **225777 B** | DATA_STORE `hello.exe` + **Executing the .NET program from Data Store** + CHECKIN **55 B** |
| OUTPUT `grok-ea-117` | 否 | 否 |
| 探针 1/2/3 | 否（观察端自测 `'0'` 成功） | 否 |
| 作业 rundll32 | pid 5740 父=12112，`sysnative\rundll32`，~1.8MB，线程 Waiting | pid 21596 父=10044，同样空壳 |
| x86 子进程 | 随后消失 | 随后消失 |
| WER | 15:38:51 `syswow64\rundll32` **c0000005** offset **0x028e002a** | 15:44:16 同模块 **c0000005** offset **0x0435002a** |

两次 fault offset 都是 **VirtualAlloc 页基址 + 0x2A**。

### dump（第二次）

- 文件：`C:\Users\Public\cmd117_dumps\rundll32.exe.10044.dmp`（WER LocalDumps，62MB）
- ExceptionAddress **0x0435002a**，tid 4116，CS=0x23 SS=0x2B ESP=0x0283F860 **EDX=0**
- 页 `0x04350000` 上的 `migrate_executex64` 实字节：

```
55 89 E5 56 57 8B 75 08 8B 4D 0C E8 00 00 00 00
58 83 C0 25 83 EC 08 89 E2 C7 42 04 33 00 00 00
89 02 E8 09 00 00 00 83 C4 14 5F 5E 5D C2 08 00
8B 3C 24 FF 2A 48 31 C0 57 FF ...
```

这是 **旧 MSF Heaven’s Gate**（`add eax,0x25`，`call +9`，`mov edi,[esp]`），**不是** 仓库 `df42b94` 的 ReWolf（`add eax,0x2B` / `mov ax,ds; mov ss,ax` / `mov edi,[esp]` SIB `8B 3C E4`）。

+0x2A 指令是 32 位收尾里的 `pop esi`（`5E`）。Gate 用 `edx` 当 far pointer；崩溃时 **EDX 已是 0**。

静态数组（stub 后面紧跟 `migrate_wownativex`）同样是旧 stub。进程里找不到探针字符串。

### 和 TS 槽的矛盾

当时读 `TeamServerImage_patched` x86 槽：

- slot16 = `4a58e46ea994782e7cba1f2226f6cda1`（文档里的 24d52af）
- 编码长度 = 245792

编码 blob 头 16 字节对得上，**活体镜像对不上源码**。下一步应 **CrackSleeve decode 该槽**，在明文 DLL 里搜 `83 C0 2B` / `66 8C D8` / `cmd117probe`，确认 CI 产物是不是根本没链上 `inject_rtlcreateuserthread_wow64.cpp` 新字节。

未改 Gate stub。未把 force-x86 当修复。未加回 HKCU / `http_flush_post`。

本机 WER 项：`HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\rundll32.exe` → `C:\Users\Public\cmd117_dumps`。需要的话原会话用完删掉。

---

## 改了哪些行

- `src/cmd117_probe.h`（新）：probe + force 文件/管道  
- `src/datastore.cpp`：force 时 `x86 = TRUE`  
- `src/inject.cpp`：probe `'1'` / `'2'`  
- `src/inject_rtlcreateuserthread_wow64.cpp`：probe `'3'`  
- `inject_rtlcreateuserthread_wow64` 的 Heaven’s Gate 字节：**未再改**（仍为 df42b94 ReWolf 版）

---

## 下一步建议（给原会话）

1. **先核对 CI 套筒明文**：把 TS x86 槽 245792 B decode，确认有没有 ReWolf 字节和 `cmd117probe`。slot16 一致但 dump 是旧 stub，优先当 **打槽/CI 产物与源码不一致**。
2. 明文若已是 ReWolf+probe，再查为什么 spawn 到 EUEJDE2 的 rundll32 仍是旧数组（错槽、缓存、打进了别的 image）。
3. 明文若仍是旧 MSF Gate：重新从 `df42b94`/`24d52af` 编 x86 DLL，CrackSleeve encode，`patch_x86_stop_first.py` 打槽后再活测。过线仍是 child OUTPUT `grok-ea-117`。
4. 198 上 lastf 爬升 + 空作业 rundll32：先看 Application 日志有没有同样的 `syswow64\rundll32` c0000005，不要再当成单纯挂死。
5. 不要在 dump 对不上 ReWolf 之前改 Gate stub。不要把 force-x86 spawn 当最终修复。

---

## 修复路径（本机 dump 之后）

**不要先改 Gate 字节。** 源码 ReWolf 已经在 TS x86 槽里，但崩溃进程跑的不是那份 DLL。

| 核对 | 结果 |
|---|---|
| CI `34571186915` `beacon.dll` | 有 ReWolf `66 8C D8 66 8E D0`，有 `cmd117probe`，TimeDateStamp `0x6aa3a389` |
| TS 槽 decode（SleeveSecurity） | **与上述 CI DLL 字节级相同** |
| 崩溃进程 `rundll32.exe.10044.dmp` | **官方套筒**：DOS `MZRE`，TimeDateStamp `0x64f88c5f`，旧 MSF `add eax,0x25`，无探针/ReWolf |
| TS 进程内存（spawn 之后） | 有 `MZRE`，**没有** CI 时间戳 / probe / ReWolf |

cmd 117 崩在 stock Heaven’s Gate（+0x2A `pop esi`，EDX=0）。仓库里的 ReWolf **还没进过这个 x86 进程**。

### 修复顺序

1. **先打通交付**：让新的 x86 beacon 确实是 CI DLL。过线：新进程或 dump 里能看到 `cmd117probe` 或 ReWolf 字节；管道能收到 `'1'`。
2. 交付过后再跑 cmd 117。若 OUTPUT 有 `grok-ea-117`，这个问题结束。
3. 若已是 ReWolf 仍崩，再改 `migrate_executex64`。现在改只是改一份 spawn 没用到的数组。
4. 仍然不要把 `spawn_patsy(TRUE)` 当产品修复。

交付候选（按这个顺序试）：

- spawn 走了官方 x86 模板，槽里的我方 DLL 没被这次 `bspawn http x86` 用上。先 **用 TS 直接 generate 一份 x86 stageless**，在落地文件里搜 `cmd117probe`，确认后再上线测 117。
- 若 generate 出来仍是 `MZRE` + `0x64f88c5f`：Graal `getResourceAsStream("sleeve/beacon.dll")` 读的不是 `0x054968E0` 那份（或 client jar 套筒）。要对真正被 readResource 读到的那份 blob（或 `4.9.1.jar` 的 `sleeve/beacon.dll`）再打一次。
- 不要把 245760 B 的我方 DLL 塞进 `beacon.rl0k.dll` 槽（编码 cap **242208**，塞不下）。

过线标准不变：child OUTPUT `grok-ea-117`，lastf 仍为秒。

---

## 原会话复核（2026-09-11 16:12–16:18，DESKTOP-EUEJDE2）

同意「活体是官方、磁盘槽是 CI」。新鲜 spawn 钉死：

- 父 `890778478` pwd 正常 → `spawn http x86` → child **362655368** pid **15612**
- CHECKIN **247816** B
- 进程内两份 `MZRE` PE，`TimeDateStamp 0x64F88C5F`；无 `cmd117probe` / ReWolf / `0x6AA3A389`
- `live_2520000.bin` 与官方明文 `0x200:0x400` 相同
- TS 文件槽仍是 `4a58e46e` / 245792；TS 进程里有该编码头、无官方编码头 `7fdd3cb9`
- listener generate：**x86 无** `setExportName() failed`，**x64 有** → x86 用的是带 strings table 的官方 PE

`export_sleeved` / `artifact_payload` 走 Headless 的 `4.9.1.jar`，也是官方。细节：`docs/CMD117-X86-DELIVERY.md`。

下一步仍是交付（谁在给 x86 generate 供数），不要先改 Gate。

- [x] 没有加回 HKCU / Public dump / `%TEMP%` dump（Public 仅 force 标记文件 + 探针日志，由 shell 读写）
- [x] 没有加回 `http_flush_post` / BeaconOutput sendNow
- [x] 没有把 force `spawn_patsy(TRUE)` 当成最终修复
- [x] 没有把 4.10.1 Indirect crash 套到这条 Direct hang

---

## 结案（2026-09-11 18:56，DESKTOP-EUEJDE2）

官方 store EA 在 x86 上是 **同架构**（`ExecuteAssemblyJob`：`beacon.is64() ? x64 : x86` → inner 70/87）。崩/无 OUTPUT 不是 Gate 缺 ReWolf，是交付读错套筒，加上两处 implant 真修复。

### 根因

| # | 问题 | 修复 |
|---|---|---|
| 1 | `bspawn` 在 Headless `exportLocal`，读 jar/CWD 官方 `sleeve/beacon.dll`；TS 槽 `0x054968E0` spawn **不用** | overlay client jar + CWD 影子（见 DELIVERY / LIVE-OPS §3.1） |
| 2 | Guardrails `indexOf` 先命中 `.rdata` 副本，2048B blob 盖掉 LTC / 公钥 → checkin 前 `abort` | **`1050045`**：68 字节 needle 只留在 `guard_region` |
| 3 | cmd 117 把 extra（宽参数）当作业参数 → CLR `Assembly.Load` 垃圾 → **`0x8007000b`** | **`1ffbde2`**：参数 = store 余下 `[len][assembly]` + extra |

未改 Heaven’s Gate / ReWolf。未把 force-x86 当产品修复。

### Overlay（`1ffbde2` 活测用）

CI https://github.com/bXZb/Beacon/actions/runs/34590500649 artifact `beacon-x86` **10195459635**。明文 **245760**，`TimeDateStamp 0x6AA3DB62`。CrackSleeve 编码 **245792**，头 **`4ee3dde3a7053d73238e0ca0b346d6cf`**。

同时写入：

- `C:\Users\Administrator\Desktop\4.9.1\out\artifacts\sleeve\beacon.dll`（Headless CWD 影子）
- `C:\Users\Administrator\Desktop\4.9.1\out\artifacts\4.9.1.jar` 条目 `sleeve/beacon.dll`（备份 `4.9.1.jar.pre_1ffbde2`）
- `C:\Users\Administrator\Desktop\cobaltstrike\4.9.1\src\sleeve\beacon.dll`

### 活测 PASS

Headless `grok-hl117k` java pid **22556**，CWD artifacts，**`-XX:+UseParallelGC -Xms256m -Xmx1g`**（未用 AggressiveHeap）。父 `890778478` / 17600 未动。旧子 `402162100`（1050045）未用来测 117。

| 步骤 | 结果 |
|---|---|
| spawn http x86 | CHECKIN **245768**；INITIAL **463543496** pid **1216** |
| 进程扫描 | `ci_ts`×4 ReWolf×2 probe×2；官方 ts **0** |
| 子 pwd | PASS |
| `data_store_load dotnet hello.exe` | **Stored** index 0 |
| `execute_assembly` | banner + OUTPUT **`grok-ea-117`**（无 `0x8007000b`） |
| EA 后再 pwd | PASS |

驱动：`cs-agscript-mcp/scripts/c1_x86_1ffbde2_live.py`。hello.exe 仍是 PE32 x86 3584 B。

### 收敛

**`b243338`** 删除 `src/cmd117_probe.h`、inject 管道 `'1'/'2'/'3'`、datastore `cmd117_force_x86_job`。保留 `1050045` / `1ffbde2` / ReWolf / GargleSleep。

CI https://github.com/bXZb/Beacon/actions/runs/34592888623 **全绿**（host-side tests、beacon x86/x64、dnsb/extc2/pivot x64）。artifact `beacon-x86` **10196379698**。

收敛后二进制不再含 `cmd117probe`；以后判别用 TimeDateStamp / ReWolf，不要再用探针字符串。
