# 下一会话：C1 已结案后的工作

给**另一个会话**。cmd 117 / x86 交付 / guardrails needle **不要再当主线重开**。日常步骤：`docs/LIVE-OPS.md`。矩阵：`docs/MATRIX.md`。写回：`docs/NEXT-FEEDBACK.md`。

客户端工程：`C:\Users\Administrator\Desktop\4.9.1`，规范 `AGENTS.md`（overlay copy-then-edit；`src/sleeve/beacon.dll` 由 `build.ps1` 打进 fat jar）。

---

## 0. 当前结论（2026-09-11 夜，HEAD `8e2a8b6`）

| 项 | 状态 |
|---|---|
| x64 WinINet 矩阵 + cmd 117 | **过** |
| x64 WinHTTP 我方套筒 + cmd 117 | **过**（子 `1204167688` CHECKIN **290312**） |
| x86 WinINet 核心矩阵 + store 117 + 非 store EA + hashdump | **过**（子 `1026850514`） |
| implant 真修复 | `GargleSleep` 堆；`1050045` guard needle；`1ffbde2` cmd 117 作业参数 |
| 探针 | **`b243338` 已删**。判别用 TimeDateStamp / ReWolf，不要 `cmd117probe` |
| 交付 | `bspawn` = Headless `exportLocal` → **client jar + CWD 影子**。TS 槽只给监听器 generate |

保活：x64 父 **`890778478`** pid **17600** `beacon_x64.exe`（EUEJDE2）。TS 测完 WinHTTP 后已改回 **`r2_nosm`**。Headless 用 `-XX:+UseParallelGC -Xms256m -Xmx1g`，CWD = `4.9.1\out\artifacts`。不要并行 AggressiveHeap。

---

## 1. 不要做

- 不要改 Heaven’s Gate / `spawn_patsy(TRUE)` / 加回 `http_flush_post` / HKCU dump / `cmd117_probe.h`
- 不要用 `r2_nosm` 去 spawn `http_wh2` 当 WinHTTP 套筒（会得到 WinINet **307208**，不是 **290312**）
- 不要 `CrackSleeve encode | Select-Object -First 1`；encode 会重写 Decode 目录全部 sleeve，overlay **只拷你改的那一个** Encode 文件
- GitHub artifact zip 302 到 Azure：**重定向不要带 Authorization**
- 本机不编 C++

---

## 2. 建议顺序（按这个做，不要并行开三条线）

### A. 收口 HTTP 矩阵（仍属 C1 尾巴，一天内能做完）

MATRIX §3 写明 WinHTTP 子会话**没重复**（不是失败）：Host Profiles、Guardrails、sleep_mask、SOCKS UDP、运行时切 syscall、token-store、keylogger。

另：FEEDBACK 结案写 **mimikatz 未测**。CNA 已有 `hashdump`/`mimikatz`。

**实施（mimikatz，优先）**

1. 确认 Headless 活着、CWD artifacts、影子 `sleeve/beacon.dll` 编码头仍是当前 CI（x86）或本次不 spawn 新 x86。
2. 用已有 x86 子（若 lastf 仍为秒）或从 `890778478` `spawn http x86`，CHECKIN 须 **245768**。
3. inbox：`target <bid>` → `mimikatz`（参数按 `headless_drive.cna`）→ 等 OUTPUT，再 `pwd`。
4. 过：OUTPUT 有 mimikatz 特征且 pwd 仍回。写进 `NEXT-FEEDBACK.md`。

**实施（WinHTTP 补测，一项一项）**

1. `patch_ts.py --restart-only --profile r2_winhttp`（会踢 Headless）。
2. 新 `grok-hl*`，CWD artifacts。从 x64 父 `spawn http_wh2 x64`。CHECKIN 必须 **290312**，否则停下来查套筒。
3. 只测 MATRIX 列出的缺口，不要重跑已过的 cmd 117。
4. 测完立刻 `--restart-only --profile r2_nosm`。

### B. screenshot postex-loader（可选，低优先）

x64 screenshot 仍「缺 sleeved postex-loader，回落 jar」。若要我方 loader：CI 没有单独 job 就先别做。有产物则按 LIVE-OPS §3.1 同样 overlay `sleeve/` 对应条目，再跑 screenshot，确认不再回落。

### C. C2 第一项：dnsb（C1 完成后的正式范围）

`bspawn` 仍走 **client jar** `sleeve/dnsb.x64.dll`（或 x86）。监听器启动 generate 走 **TS 槽**（`tsimage_resource_map.txt` 里 `sleeve/dnsb.x64.dll` 等）。两条都要打，只打槽会重演 x86「槽是 CI、spawn 是官方」。

**实施**

1. 读 `4.9.1/_re/tsimage_resource_map.txt` 记下 dnsb 槽 VA / 编码 cap。明文必须 ≤ cap-32。
2. CI `dnsb-x64` artifact → Decode → encode →  
   - `patch_ts.py` 增加 `--slot dnsb` 或一次性打槽（先核对 cap，打错槽会毁镜像；**先备份** `TeamServerImage_patched`）。  
   - overlay `src/sleeve/dnsb.x64.dll` + CWD 影子 + fat jar 条目（`build.ps1` 已 copy 整个 `src/sleeve/`）。
3. profile / listener：DNS beacon 需要 DNS 监听，不是 `http`。不要拿 HTTP 父硬 spawn dnsb 当过线。
4. 过线最低：INITIAL + 二次 checkin + pwd/shell。不要一上来跑 EA。
5. 写回槽 VA、编码头、CHECKIN 字节、bid。

pivot / extc2 同样双路径，**dnsb 绿了再做**。

### D. 更后（本会话不要开）

UDRL / `beacon.rl0k.dll`（x86 编码 cap **242208**，245760 **塞不下**）、Post-Ex prepend、A3 `PROCESS_QUERY_LIMITED_INFORMATION`。

---

## 3. 改 implant 时的交付清单（每次 CI 之后）

x86 HTTP spawn：

1. 等 Actions `dll` / `dll-x86` / `tests` 全绿。
2. 下 `beacon-x86` → `Win32/Release/beacon.dll` ≤ 247808。
3. 拷到 `CrackSleeve4.9\Resource\Decode\sleeve\beacon.dll` → `java -cp cobaltstrike-client.jar;. CrackSleeve encode`（cwd=CrackSleeve4.9）。
4. 只取 `Encode\sleeve\beacon.dll`（≤ 247840）写到：  
   `4.9.1\src\sleeve\beacon.dll`  
   `4.9.1\out\artifacts\sleeve\beacon.dll`  
   并 `build.ps1` 打 jar（或 `jar uf` 只换条目）。改 jar 前备份 `4.9.1.jar.pre_<sha>`。
5. 停旧 Headless，**一份** JVM，CWD=`out\artifacts`，用户名换 `grok-hl*`。
6. spawn CHECKIN = 明文+8；扫 TimeDateStamp ≠ `0x64F88C5F`。

x64 WinHTTP spawn：TS `r2_winhttp` + overlay `winhttpb.x64.dll`（若 spawn 也走 jar；监听器 generate 仍打 TS 槽 `0x05624CC0`）。

---

## 4. 写回

`docs/NEXT-FEEDBACK.md`：做了 A/B/C 哪一项、commit/CI、CHECKIN 字节、bid/pid、OUTPUT 针、TS profile 是否改回 `r2_nosm`。
