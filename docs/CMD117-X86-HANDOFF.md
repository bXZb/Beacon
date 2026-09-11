# x86 cmd 117 排查交接

给**另一个会话**用。本仓库已去掉排查插桩（HKCU tracer、Public/%TEMP% dump、BeaconOutput sendNow、`http_flush_post`）。注入逻辑回到 4.5 泄漏树在 `9539bb2` 时的 `inject_process_execute` / `SetThreadContext` / `pipe_try`。

**反馈写到**：同目录 `CMD117-X86-FEEDBACK.md`（空模板，按表填）。不要改本文件当实验笔记。

规范与套筒：`docs/LIVE-OPS.md`。矩阵快照：`docs/MATRIX.md`。调用 `cs-agscript-mcp/scripts/patch_ts.py` 打槽，不要再手写一次性 SSH。

---

## 1. 现象（关 Defender 后仍在）

x86 Beacon 上 `data-store load dotnet hello.exe` 再 `execute_assembly`（cmd **117**）：

- TASKED：`Executing the .NET program from Data Store`
- CHECKIN：`sent: 55 bytes`（任务已下到 implant）
- **没有** OUTPUT `grok-ea-117`
- lastf 从秒变成 1–11 分钟，pwd 不再回
- **进程没退出**：ps 里该 x86 rundll32 仍在，并且多出一个 **x64 rundll32 子进程**

对照：

| 对照 | 结果 |
|---|---|
| 同机 x64 父会话 cmd 117 | **过**，`grok-ea-117` |
| x86 screenshot（同架构作业） | **过** |
| 关 Windows Defender | 仍卡住 |

hello.exe：`cs-agscript-mcp/scripts/ea/hello.exe`（PE x86 / 0x14c），stdout `grok-ea-117`。

---

## 2. 这不是 4.10.1 那条

官方 4.10.1：「x86 beacons **crashing** when using the **indirect** syscall method」。

我们：4.9.1 端口；profile `syscall_method "Direct"`；现象是**线程卡住**不是崩；触发是 EA 跨架构注入。

---

## 3. 官方语义（已核实）

Raphael 2019 [Process Injection 详解](https://www.cobaltstrike.com/blog/cobalt-strikes-process-injection-the-details-cobalt-strike) + 手册 OPSEC 附录：

- execute-assembly / hashdump / mimikatz / powerpick **能 x64 就 spawn x64 作业**
- x86 Beacon 做这件事靠 **x86 → x64 注入**
- SetThreadContext：**不能** x86→x64，x86 **不能传参**
- NtQueueApcThread-s：仅同架构
- CreateRemoteThread：**不能** x86→x64
- **RtlCreateUserThread：能 x86→x64**（Heaven’s Gate + RWX stub 调 RtlCreateUserThread）

活测 `rundll32 <x86 beacon pid> → <x64 child>` **符合官方**，不是 inner_type 解错。

源码对应：`datastore.cpp` `x86 = (inner_type == 70 \|\| inner_type == 87)` → 71/88 则 `spawn_patsy(FALSE)` 起 x64；`inject.cpp` x86 分支 `!sameArch && inject_via_remotethread_wow64(...)` 才是跨架构路。

---

## 4. 已排除

| 假设 | 为何排除 |
|---|---|
| Defender 杀 rundll32/CLR | 关实时保护后仍卡；x64 EA / x86 screenshot 过 |
| wait 解析成超大值 | `data_short` 最大 ~65s；官方 wait=20000；x64 同一 parse 过 |
| store unwrap `jobblob+8` 错 | x64 117 同代码过 |
| 作业进程崩导致 beacon 退出 | ps：x86 beacon 仍为 PPID；子 x64 rundll32 还在 |
| PeekNamedPipe 堵死（唯一原因） | 改成 `WaitForSingleObject`+`TerminateProcess` 后仍卡，卡在 **inject 返回之前** |
| SetThreadContext 远程 RWX stub | 去掉 stub、忽略参、只劫持 EAX 后仍卡 |
| 跳过 CRT/APC-s 就能好 | 跳过后官方 x86→x64 路没了，WOW64 `VirtualAllocEx` 写 x64 **把 beacon 线程卡住** |
| HKCU / Public / %TEMP% dump | CreateFile/RegCreateKey 在 beacon 里经常写不上；`reg add` 从 shell 可以 |
| BeaconOutput sendNow 不 close+init | GET 后 `connect_h` 不能用，`http_post_maybe` 直接 return |
| http_close+init 再 POST | spawn 仍发生（说明 dump 函数返回了），TS 仍无 OUTPUT；加密入队或 POST 解析仍失败，**不要再在这条 dump 路上耗时间** |

---

## 5. 已撤回的排查补丁（本收敛）

下列已从树里拿掉，**不要再加回来当“修复”**：

- `src/x86trace.h` 与所有 `x86_bc(...)`
- Public / `%TEMP%\x86ea.txt` / BeaconOutput `inner=` / `ea117-enter`
- `http_flush_post`
- x86 挂起进程 skip CRT / RtlCUT / APC-s
- x86 SetThreadContext 忽略 `lpParameter` 只改 EAX
- job 超时 `TerminateProcess`（已回到 `pipe_try`）

**保留（真修复，与 cmd117 无关）**：`GargleSleep` 16KB 改堆分配，避免 x86 `__chkstk` 第一次 GET 后死。

当前注入 = `9539bb2` 行为：x86 挂起 + 有参 → SetThreadContext 失败 → 尝试 `inject_via_remotethread_wow64`。

---

## 6. 建议的下一步（给接手会话）

按这个顺序，不要再开 dump 文件/HKCU：

1. **读** `inject_rtlcreateuserthread_wow64.cpp`，对照官方 Heaven’s Gate。确认 `!sameArch && isSuspended` 时这条会被调用，且不会在 `remote_mirror`（WOW64→x64 VirtualAllocEx）里堵死调用线程。
2. 若 wow64 注入本身会堵：给跨架构 mirror/execute 加超时或改到官方 stub 顺序（先 Heaven’s Gate 再 RtlCreateUserThread）。
3. 活测：x64 父 spawn x86 子 → datastore load `ea/hello.exe` → execute_assembly。过：OUTPUT 含 `grok-ea-117`，lastf 仍为秒，beacon 继续 pwd。
4. 不要用「强制 spawn x86」当最终方案：官方作业 DLL 是 **x64 invokeassembly**。同架构 spawn 只是实验，不是对齐。
5. 插桩若必须：用 **命名管道/已有 job 回调**，或只在 wow64 注入前后 `post_error_dd` 打一次（走下一轮 POST）。不要再 `http_flush_post`。

---

## 7. 环境（接手时核对）

- 仓库：`https://github.com/bXZb/Beacon.git` 分支 **`4.9.1`**
- 本机不编 C++；CI 编；PAT：`Desktop\cobaltstrike\GITHUB_PERSONAL_ACCESS_TOKEN.txt`（勿提交）
- TS：`192.168.100.98:50050` 密码 `123456`；HTTP `8080`
- 交付：CrackSleeve encode → `apply_beacon_x86_sleeve.py` / 文档里的 `patch_ts.py`；槽 `0x054968E0` 明文 cap **247808**
- 不要 `CrackSleeve encode | Select-Object -First 1`
- Headless：JDK 21 + `4.9.1.jar` + `headless_drive.cna`，用户名 `grok-hl*`
- 活测判定：OUTPUT/ALT/PS/LS，**不要**只认 TASKED
- 规范：`docs/LIVE-OPS.md`；矩阵：`docs/MATRIX.md`

---

## 8. 请写进 FEEDBACK 的内容

见 `CMD117-X86-FEEDBACK.md`。最少要有：commit、CI run、child bid/pid、ps 里作业 arch、是否出现 `grok-ea-117`、lastf、改了 `inject_rtlcreateuserthread_wow64.cpp` 的哪几行。
