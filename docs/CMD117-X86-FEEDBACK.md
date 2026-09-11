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

## 探针结论

观察端已确认 `listening sync`，但 implant 从未连上写入。可能原因：

1. `WaitNamedPipe(50–200ms)` 在 WOW64 下对挂起的 `WaitForConnection` 不可靠（下一轮已把等待加到 200ms，仍可能要改成带超时的 CreateFile）。  
2. 或主路径在进 `inject_process_logic` 前就返回（与「已有 rundll32 作业子进程」不太一致，更像探针失败）。

**还不能**用 1/2/3 区分 mirror vs Gate。

---

## 对照结论（目前）

- [ ] **已过**
- [x] **仍失败**（官方路径仍无 `grok-ea-117`）
- [x] **部分**：A/B 都会 spawn 出作业 rundll32，且 55B CHECKIN 后短时间内 lastf 仍为秒；但无 stdout，随后 pwd 也无回。

| 假设 | 为何排除 / 修正 |
|---|---|
| 仅 VirtualAllocEx / 仅缺 ReWolf stub | 前轮已排除；本轮仍 FAIL |
| force-x86 应直接跑通 EA | **实验无效**：x86 进程 + x64 invokeassembly DLL，不能期望 `grok-ea-117` |
| 探针可定位卡点 | 本轮探针零字节，**尚未定位** |

---

## 改了哪些行

- `src/cmd117_probe.h`（新）：probe + force 文件/管道  
- `src/datastore.cpp`：force 时 `x86 = TRUE`  
- `src/inject.cpp`：probe `'1'` / `'2'`  
- `src/inject_rtlcreateuserthread_wow64.cpp`：probe `'3'`  
- `inject_rtlcreateuserthread_wow64` 的 Heaven’s Gate 字节：**未再改**（仍为 df42b94 ReWolf 版）

---

## 下一步建议（给原会话）

1. **修探针**：确认 x86 implant 能写到 pipe（可先在 `inject_process_logic` 入口用更长 `WaitNamedPipe`，或 `CreateFile`+短超时）；先看到 `'1'` 再谈 Gate stub。  
2. **合法同架构对照**：需要 **x86 的 invokeassembly / inner_type 70|87** 作业包，而不是只 `spawn_patsy(TRUE)` 硬塞 x64 DLL。  
3. 探针若停在 `'1'`→无 `'2'`：WOW64 `NtMapViewOfSection` 仍堵 → 再做 Heaven’s Gate 内镜像 stub；若到 `'3'` 仍无 OUTPUT：查 `pipe_try` / job 回调。

---

## 禁止项核对

- [x] 没有加回 HKCU / Public dump / `%TEMP%` dump（Public 仅 force 标记文件 + 探针日志，由 shell 读写）
- [x] 没有加回 `http_flush_post` / BeaconOutput sendNow
- [x] 没有把 force `spawn_patsy(TRUE)` 当成最终修复
- [x] 没有把 4.10.1 Indirect crash 套到这条 Direct hang
