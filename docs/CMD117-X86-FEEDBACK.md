# x86 cmd 117 排查反馈（模板）

接手会话把结果写进**本文件**，不要改 `CMD117-X86-HANDOFF.md` 当实验笔记。Handoff 里的「不要再加回来」仍然有效。

填完后告诉原来的会话：读 `docs/CMD117-X86-FEEDBACK.md`。

---

## 元数据

| 项 | 值 |
|---|---|
| 日期 | YYYY-MM-DD |
| 会话 | （Grok / 其它） |
| 代码 commit | |
| CI run | https://github.com/bXZb/Beacon/actions/runs/ |
| 套筒 DLL 体积（明文 / 编码） | |
| TS 槽核对（slot16 hex） | |
| profile | `r2_nosm` / 其它 |
| Headless 用户名 | grok-hl |
| Defender 实时保护 | 开 / 关 |

---

## 活测会话

| 项 | 值 |
|---|---|
| x64 父 bid / pid | |
| x86 子 bid / pid | |
| 子 lastf（117 前） | |
| 子 lastf（117 后，等 2–3 个 sleep） | |
| TASKED 是否出现 store 横幅 | 是 / 否：`Executing the .NET program from Data Store` |
| CHECKIN 55B | 是 / 否 |
| OUTPUT 是否含 `grok-ea-117` | 是 / 否 |
| 之后 `pwd` 是否还有 ALT/OUTPUT | 是 / 否 |
| ps：x86 beacon 是否仍在 | 是 / 否 |
| ps：是否出现 **x64** rundll32 作业（子进程） | 是 / 否；pid / arch |
| 作业是否一直挂起 | |

把 `r1.log` 里 117 前后约 30 行贴在下面（可打码无关 HEART）。

```
（日志摘录）
```

---

## 改了什么

只列与 `inject_rtlcreateuserthread_wow64.cpp` / `inject.cpp` / `inject_mirror.cpp` 相关的行。不要贴整文件。

- 文件：
- 行为变化（官方 Heaven’s Gate 是否被调用、是否还在 `remote_mirror` 的 VirtualAllocEx 里堵）：
- 同架构回归：x86 screenshot / x64 cmd 117 是否仍过：

---

## 结论

- [ ] **已过**：x86 子 OUTPUT `grok-ea-117`，lastf 仍为秒，pwd 继续回。
- [ ] **仍失败**：卡点现在认为是：
- [ ] **部分**：例如作业起了但 stdout 没回来。

还排除了哪些新假设（表格，一行一个）：

| 假设 | 为何排除 |
|---|---|

下一步建议（给原会话，三条以内）：

1.
2.

---

## 禁止项核对

- [ ] 没有加回 HKCU / Public / `%TEMP%` dump
- [ ] 没有加回 `http_flush_post` / BeaconOutput sendNow
- [ ] 没有把「强制 `spawn_patsy(TRUE)` 只起 x86 作业」当成最终修复
- [ ] 没有把 4.10.1 Indirect crash changelog 当成这个 Direct hang
