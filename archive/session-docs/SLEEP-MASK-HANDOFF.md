# 交接：x64 sleep_mask BOF 卡死（不换 rcx 类型）

给**另一个会话**。cmd 117 / 交付 / Gate **不要重开**。规范：`docs/LIVE-OPS.md`。写回：`docs/SLEEP-MASK-FEEDBACK.md`。

客户端：`C:\Users\Administrator\Desktop\4.9.1`（`AGENTS.md`）。WinHTTP spawn 走 jar/CWD `sleeve/winhttpb.x64.dll`。

---

## 0. 任务一句话

**官方 `sleepmask.x64.o` 已能链接（ADDR32NB、reloc=0），按 `sleep_mask(gparms, Sleep, time)` 调用后第一次 GargleSleep 不返回。**  
段表和 heap 表进 BOF 时**不是 NULL、不是 -1 死循环**。下一步盯 **XOR `beacon_ptr+sec[]` / heap XOR 是否打到还在跑的东西**，或 **`call rbp`（Sleep）是否带着坏 ecx**。不要再把 rcx 换成 `BEACON_INFO*`。

过线：`r2_winhttp_sm` 下 spawn `http_wh2` x64，reloc 报错=0，**约 60s 内第二次 CHECKIN + pwd**，且 `C:\Users\Public\sm_gparms.txt` 能解释为什么不再挂。  
然后 **删掉** `sm_dump_gparms` / Public 文件 dump。

---

## 1. 实验室安全套筒 vs HEAD

| | commit | 行为 |
|---|---|---|
| **能 checkin** | **`44161e2`** | type 3 失败 → `Sleep()`，每轮约 1 次 reloc error |
| **会挂** | `4080c68` 起 invoke BOF | reloc=0，INITIAL 后 lastf 爬、无第二次 CHECKIN |
| HEAD | **`d1a3699`** | 摘掉 sections 的 heap mask 后 **仍挂**（`1320170966`） |

CWD 套筒曾换回 44161e2（290336）。测 BOF 必须 overlay **当前 HEAD** 的 `winhttpb.x64.dll`，profile **`r2_winhttp_sm`**。测完 **立刻** `--restart-only --profile r2_nosm`。

父：`457034960`（若仍在）。不要并行 AggressiveHeap。Headless dump 64 会话后易退。

---

## 2. 已钉死（不要当主线再验）

### 对象（CrackSleeve Decode `sleepmask.x64.o`）

`.text` **0 条 reloc**（PIC）。type 3 **只有 3 条，全在 `.pdata`**：Begin/End/Unwind（End addend `0x198`=.text 大小）。

入口（capstone，`cs-agscript-mcp/scripts/disasm_sleep_mask.py`）：

```
rcx → rbx = GARGLEP*
rdx → rbp = Sleep
r8d → esi = time ms
[rcx+0]  beacon_ptr
[rcx+8]  sections  DWORD 对，(0,0) 结束
走完段表后：
  [rbx+0x10] heap_records  {ptr,size}×16B，ptr==NULL 结束
  [rbx+rax+0x18] mask[13]   钥匙（imul 0x4ec4ec4f ≈ 1/13）
  mov ecx, esi ; call rbp    Sleep(time)
  再 XOR heap、再 XOR 段（揭开）
  ret
```

**没有读** `BEACON_INFO.sleep_mask_ptr` / sizes。OpenBeacon `BEACON_INFO` 的 `+8` 是两个 DWORD 长度，**不能当 rcx**（会把 16384 当指针）。

### 调用链上已做过、仍挂

| commit | 做了什么 | 活体 |
|---|---|---|
| `4080c68` | ADDR32NB = RVA from BOF mapping | 挂 |
| `47f9ddc` | `sleep_mask(gparms, Sleep, time)` 不是 `go(args,alen)` | 挂 |
| `f253075` | invoke 前 `gargle_setup_parms`（以前 gparms 只在 trampoline 里建） | 挂 |
| `bdda2af` | BOF 路径 sections 的 `-1` 槽改成 0,0（避免 32 位截断自 mask） | 挂 |
| `011dec0` | 填 `BEACON_INFO` 再拷到 `GARGLEP` rcx | 挂 `1861081748` |
| `8e302c1` | **不 invoke**，dump 后 `Sleep()` | checkin；dump 如下 |
| `d1a3699` | `SETTING_GARGLE_SECTIONS` mask=FALSE + heap 表摘 sections，**再 invoke** | **仍挂** `1320170966` |

### dump 实值（`8e302c1`，`C:\Users\Public\sm_gparms.txt`，也在 `ci-artifacts/sm_gparms.txt`）

```
t=60000
bof        = 00000288CB2F0000  blen=440
gparms     = 00000288CB18EAF0
beacon_ptr = 00000288CB230000
sections   = 00000288CB149C90
heap       = 00000288CB166720
```

sections（相对 beacon_ptr，**无 NEG1、无 BAD_ORDER、有 END**）：

```
sec[0] 00000000 00001000
sec[1] 00001000 0002FCB0    ; ~188KB，像整段 .text
sec[2] 00030000 0003DD90
sec[3] 0003E000 0005D318
sec[4] 0005E000 00060880
sec[5] 00061000 00061100
sec[6] 00062000 00062360
sec[7] 00000000 00000000 END
```

BOF 在 `beacon_ptr+0xC0000`，**不在**这些段里。

heap：24 条都有 ptr（16–2048B），dump 窗口没印到 `ptr==NULL`（终止符应在 `[24]`）。  
**`heap[18] ptr == sections`，size=64**（8 对×8B）。对象会先走段表 XOR，再 XOR 整张 heap——把 **sections 自己也 XOR 掉**，Sleep 后再 XOR 回来。`d1a3699` 按理已摘掉这条；`1320170966` 的 Public 文件内容和 13:11 那次**指针完全一样**，不能肯定是新写的。无论 dump 新不新，**invoke 仍挂**。

卡死发生在 **第一次 `call rbp` 之前或之中**（没有第二次 CHECKIN）。不是 NULL sections / NULL heap。

---

## 3. 不要做

- 不要把 rcx 换成 `BEACON_INFO*`（`+8` 不是指针）
- 不要 `spawn_patsy` / Gate / `http_flush_post` / HKCU / 重开 cmd 117
- 不要本机编 C++；PAT 一次性推送；artifact zip 302 **不要**带 Authorization
- 不要 `CrackSleeve encode | Select-Object`
- 不要并行 AggressiveHeap
- 测完 WinHTTP **必须**改回 `r2_nosm`
- **不要把会 invoke 且未过线的 HEAD 留在实验室 CWD 套筒**（会再挂）。过线前 overlay 回 `44161e2` 或测完改回
- `sm_dump_gparms` / `Public\sm_gparms.txt` 是排查用，过线后删

---

## 4. 建议顺序

1. **确认 `d1a3699` dump 是新的**  
   spawn 前删 `Public\sm_gparms.txt`，INITIAL 后立刻看 mtime 是否是这一秒。heap 里是否还有 `ptr==sections`。若还有，compact 循环有 bug。

2. **XOR 范围 vs 正在跑的东西**  
   对象在 `call rbp` 前会 `xor [beacon_ptr+off], mask` 覆盖 `sec[1]` 整段 .text（含 `GargleSleep` / `command_inline_execute` 的返回地址）。BOF 自己在独立 VirtualAlloc（dump 里 `bof`），返回地址在 BOF 内，按设计应能 Sleep 再揭开。用 IDA/`disasm_sleep_mask.py` 核对 `0x69` 之后到 `call rbp`（约 `0xce`）是否还有对 `[rbx]`/`[rbx+8]`/`[rbx+0x10]` 的异常走法（例如 heap 记录 stride 不是 16）。

3. **heap 表 stride**  
   对象：`shl r9, 4` 再 `add rax, r9`，记录 16 字节。我们的 `HEAP_RECORD { char *ptr; size_t size; }` 是 16。若 dump 新文件里某条 `size` 极大，XOR 会打飞。

4. **`call rbp` 的 ecx**  
   dump `t=60000`。若 invoke 时 `esi` 被段循环打坏，Sleep 会变成超大毫秒。可在 invoke **前**把 `t` 和 `gparms` 指针 `post_error_dd` 一次——但若卡在 XOR、`Sleep` 没回来，error 要等下一轮 POST，**仍发不出去**。所以继续用 Public 文件，或 OutputDebugString。

5. **对照实验（最小）**  
   invoke 前把 `sections` 改成只 `{0,0}`（空段表），heap 只留 `{NULL,0}`。若这样能 Sleep 回来：卡在 XOR 内容。若仍挂：卡在 `call rbp` 或 BOF 序言。

6. **过线后** 去掉 dump，只留 ADDR32NB + 三参数 + `gparms` 初始化 + sections 不进 heap mask。

---

## 5. 写回 `docs/SLEEP-MASK-FEEDBACK.md`

- 新 spawn bid/pid、CHECKIN 字节、reloc 次数、是否第二次 CHECKIN、pwd  
- 新 `sm_gparms.txt`（mtime + heap 是否还含 sections）  
- 若做了空表对照：结果  
- 改了 `boff.cpp` / `gargleint.cpp` 哪几行  
- 实验室套筒是否已改回 `44161e2` 或过线 HEAD  
- TS 是否已 `r2_nosm`
