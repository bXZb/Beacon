# 交接：查清 x86 spawn 为什么用官方套筒

> **已结案。** `bspawn` 走 Headless `exportLocal`，读 **client jar / CWD `sleeve/beacon.dll`**，不读 TS 槽 `0x054968E0`。写回见 `CMD117-X86-DELIVERY-FEEDBACK.md`；overlay 步骤见 `LIVE-OPS.md` §3.1。下面正文是排查当时的交接。

给**另一个会话**。不要改 `CMD117-X86-HANDOFF.md`（那是 Gate/注入）。本文件只覆盖 **交付**：TS 生成 x86 时没用我们打进 `0x054968E0` 的 CI DLL。

**写回**：`docs/CMD117-X86-DELIVERY-FEEDBACK.md`（按表填）。不要把实验笔记写进本文件。

背景摘要：`docs/CMD117-X86-DELIVERY.md`、`docs/CMD117-X86-FEEDBACK.md` 末尾「原会话复核」。规范：`docs/LIVE-OPS.md`。

---

## 0. 任务一句话

**找出 4.9.1 TeamServer 在 `Generating Payload ... Arch: x86` / `bspawn http x86` 时，实际读的是哪一份 `beacon.dll`，以及怎样让它改用槽里的 CI 编码 blob。**

过线（交付通了）：新 spawn 的 x86 `rundll32` 进程内存里出现 **`cmd117probe` 或 `TimeDateStamp 0x6AA3A389` 或 ReWolf `66 8C D8 66 8E D0`**。此时 **先不要跑 cmd 117**，把证据写回 FEEDBACK，交给原会话。

---

## 1. 已经钉死（不要再验证一遍当主线）

| 事实 | 证据 |
|---|---|
| 活体 x86 是 **官方 4.9.1** | 2026-09-11 16:16 父 `890778478` spawn → child `362655368` pid **15612**；PE `MZRE` + **`0x64F88C5F`**；`ci-artifacts/delivery-check/live_2520000.bin` 与官方明文 `0x200:0x400` 相同 |
| 磁盘槽是 **CI DLL** | `/root/4.9.1/TeamServerImage_patched` 槽 `0x054968E0` 编码头 `4a58e46ea994782e7cba1f2226f6cda1` 长 **245792**；decode = CI `34571186915`（`0x6AA3A389` + probe + ReWolf） |
| 运行中 TS 也有这份编码 | pid 见 `ts.pid`（当时 16007）；`enc_ours`×2，**没有**官方编码头 `7fdd3cb9b7663ec70e539f759792632f` |
| x64 用的是我方套筒 | listener generate **x64** 有 `setExportName() failed. beacon.dll not found in strings table`；x64 矩阵已过 |
| x86 generate **没用我方 PE** | 同一段 ts.log：**x86 只有** `new string table not found (MalleablePE)`，**没有** setExportName。官方有 strings table，我方没有 |
| Headless `export_sleeved` / `artifact_payload` 不能当 TS 槽证据 | 走 `4.9.1.jar` 里的官方 `sleeve/beacon.dll`（编码 247840 / `7fdd3cb9…`） |
| 生成后 DOS 变成 `MZRE` | MalleablePE；磁盘官方明文仍是 `MZ\x90`。判别用 **时间戳**，不要用 MZRE |
| cmd 117 崩在旧 Gate +0x2A / EDX=0 | 因为跑的是官方 stub，不是 `df42b94` ReWolf。**先不要改 Gate** |

官方明文：`ci-artifacts/official-x86-beacon.dll`。我方：`ci-artifacts/34571186915/x86/Win32/Release/beacon.dll` 或 `ts_slot_x86_dec.dll`。

---

## 2. 未解问题（按这个顺序查）

### 假设（要能证伪）

1. **Graal 资源表按名字解析到的文件偏移不是 `0x054968E0`**（map 是按体积对上的，可能对错）。x64 槽 `0x04B40EE0` 是对的（活体是我方）。
2. **x86 模板来自另一份 sleeve**（`beacon.rl0k.dll` `0x053E0BC0` cap 242208、`winhttpb.dll` `0x05771C80`、`beacon.rl100k.dll` 等）。spawn CHECKIN **247816 = 247808+8**，体积上仍最像 `sleeve/beacon.dll` 官方明文大小，所以「换了一份更小的 rl0k」要先对体积。
3. **native-image 在 svm_heap 里另有一份官方 x86 明文/解码缓存**，`getResourceAsStream("sleeve/beacon.dll")` 走缓存，不走我们改过的编码槽。进程里搜不到官方编码头，和这个相容。
4. **监听器在启动时 generate 并缓存了 payload**；spawn 复用缓存。ts.log 每次启动都会 `Generating Payload: http -- Arch: x86`，缓存若在 `data/` 或 Java 堆，改槽但不清缓存就会一直官方。注意：当前 TS 是 **打槽之后才启动的**（14:47），若启动时已经 generate 成官方，则是启动当下读错源，不是「更早的旧缓存」。
5. **client 生成 spawn 载荷再交给 TS**。若成立：只改 TS 镜像不够，还要改 Headless 用的 `4.9.1.jar`。反证：listener **启动时**的 x86 generate 写在 **TS 的 ts.log**，那是 server 侧。优先信 TS 侧读错源，jar 是次要。

### 建议手法

1. **对 ts.log 再打一次 generate 时间戳**  
   现网再 `spawn http x86`（父 `890778478` 若仍 pwd 秒级），立刻 `tail ts.log`：有没有新的 `Generating Payload ... x86`、有没有 `setExportName`。  
   - 有 generate + 无 setExportName → 仍在用官方 PE。  
   - 有 setExportName → 开始用我方 PE，再扫子进程时间戳（可能只是日志变了、实际还是官方，以进程为准）。

2. **在 TS 上把「读资源」钉到名字**  
   不要再盲搜 `MZRE`。对 Graal/`SleevedResource`/`BeaconPayload`：`sleeve/beacon.dll` 这个字符串在 `0x03120e60`，附近是名字表，**没有**直接指向 `0x054968E0` 的 u32/u64。  
   资源图：`4.9.1/_re/tsimage_resource_map.txt`。  
   要找到：名字 → (offset, length) 真正记录。length 若仍是 **247840**（编码 cap）而我们改的是槽前 4 字节 **245792**，说明 catalog 没用我们写的 length。

3. **启动瞬间扫 TS 堆**  
   listener generate 发生在 TS 起来后几秒。那时搜 `5f8cf864`（官方 ts）和 `89a3a389`（CI ts）。现在进程里两者都是 0，多半已经 GC。需要 generate **当时**抓，或在 `readResource` 下断/打日志。

4. **不要用第二份 AggressiveHeap Headless 并行**  
   本机 `grok-hl117d` 已占堆。再起一个 `-XX:+AggressiveHeap` 会秒退。要新 client：先停旧的（需用户同意），或只用 `-Xmx512m` 且确认它还活着再写 inbox。inbox 不要和 `r1_inbox.txt` 抢。

5. **过线后再动 implant**  
   交付未通：禁止改 `migrate_executex64`、禁止 force-x86 当修复、禁止加回 `http_flush_post` / HKCU dump。

---

## 3. 环境

- 本机现是 **DESKTOP-EUEJDE2**（`172.18.0.1` / `192.168.100.194`），不是 4CPCB7A。
- TS `192.168.100.98` root/`password`；镜像 `/root/4.9.1/TeamServerImage_patched`；profile `r2_nosm`；日志 `/root/4.9.1/ts.log`。
- Headless：`grok-hl117d` pid 曾是 10384，jar `Desktop\4.9.1\out\artifacts\4.9.1.jar`，CNA `cs-agscript-mcp/scripts/headless_drive.cna`，inbox `r1_inbox.txt`。用户杀掉的会话不要自行拉起。
- 优先保活：x64 父 **`890778478`** pid **17600** `C:\Users\Administrator\Desktop\cobaltstrike\beacon_x64.exe`。
- 打槽：`cs-agscript-mcp/scripts/patch_ts.py --slot x86 ...`（重启 TS 会踢 Headless、父会话还在但要重连 client）。
- 本机不编 C++；PAT 一次性推送，见 LIVE-OPS。
- 探针管道 `\\.\pipe\cmd117probe` 只有 **CI 套筒进了进程** 才会在 inject 时写。官方进程里没有这个字符串。

---

## 4. 写回 FEEDBACK 的最低内容

文件：`docs/CMD117-X86-DELIVERY-FEEDBACK.md`

- 真正被 `Arch: x86` generate 读到的资源名 / 文件偏移 / 长度
- 为什么磁盘 `0x054968E0` 是 CI 编码，吐出的 PE 却是 `0x64F88C5F`
- 改了什么（镜像 catalog、另一槽、清缓存、jar…）
- 新 spawn：child bid/pid、进程里是否出现 `cmd117probe` 或 `0x6AA3A389`
- ts.log 里这次 x86 generate 是否出现 `setExportName() failed`
- **不要**在交付未通时报告 cmd 117 的 grok-ea-117
