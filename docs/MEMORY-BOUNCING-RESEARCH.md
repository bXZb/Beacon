# 1c MemoryBouncing 调研与可行性设计（memorybouncing-research 分支）

**日期**：2026-10-13 · **基点**：evasion-research 8a4cae0 · **状态**：调研完成，未开工实现

## TL;DR

1. **"MemoryBouncing" 公网零索引**（多轮英文/中文检索均无命中）——它是我们
   路线图的自研名词。**公开世界不存在任何"免权限翻转睡眠掩码"的完整实现**，
   路线图"自研机会"判断成立。
2. 公开睡眠混淆全部是**翻转系**（Ekko/Foliage/Zilean/Cronos/Shelter/KrakenMask/
   doublepulsar-rs 三变体）：靠 ROP/APC/timer 在合法调用栈里调
   `VirtualProtect`+`SystemFunction032`，再用 gadget/栈伪装骗 Elastic 式
   调用栈特征——翻转依然发生，只是"看起来合法"。
3. 唯一能**真正零翻转**的底层原语是**双视图别名**：同一 pagefile section
   映射两个视图（RW 写入径 + RX 执行径，同一批物理页）。该原语以**注入**
   形态公开（写经 RW 视图、执行经 RX 视图，全程无 VP），但从未被公开
   应用于**周期性睡眠掩码**。
4. 我们的现状恰好是"半个半个"：**gen3 睡眠 = 零翻转但只掩可写页**
   （`.text/.rdata` 睡眠期明文，`g3_page_writable` 过滤）；**bofwin = 全覆盖
   但每窗口 N 次 VP 翻转**。1c = 用双视图别名把两者合成：全覆盖 + 零翻转。
5. **代价是一个架构级取舍**：双视图要求镜像活在 pagefile section 里，
   与 Phase 4 的 image-backed module stomping（spwizimg）不兼容
   （SEC_IMAGE section 无法映射 RW 视图）。见 §6 取舍表。

## 1. 公开全景（检索 2026-10-13）

| 实现 | 机制 | 翻转? | 对我们的参考价值 |
|---|---|---|---|
| [S3cur3Th1sSh1t/Caro-Kann](https://github.com/S3cur3Th1sSh1t/Caro-Kann) ★432 | RW 段放已知恶意密文 + RX 段放自写解码器；线程创建时无已知 RX 内容；解码器 sleep→解密→**VP RW→RX**→JMP | 1 次 | 防**创建时扫描**，非睡眠；同名巧合（路线图曾把 Caro-Kann 归为免翻转系，实测否） |
| [NtDallas/KrakenMask](https://github.com/NtDallas/KrakenMask) ★274 | APC + `call NtTestAlert` gadget 让 VP 的返回地址落在 KiUserApcHandler；2.2 加延时期间栈掩蔽 | 每周期 | 绕 Elastic `defense_evasion_virtualprotect_call_via_nttestalert` 规则——VP 仍发生；与 gen3 1b 的栈伪装同代 |
| [Kudaes/Shelter](https://github.com/Kudaes/Shelter) ★391 (2025-06) | 纯 ROP（无 APC/HWBP/timer）+ AES + "removal of execution permission during sleep"（= 显式翻转）+ Unwinder 栈伪装 | 每周期×2 | 最新的 ROP 系全掩码；仍是翻转 |
| [Cracked5pider/Ekko](https://github.com/Cracked5pider/Ekko) ★838 | CreateTimerQueueTimer + NtContinue ROP 链调 VP+RC4 | 每周期 | 我们 gen3 1b 的原型 |
| [Idov31/Cronos](https://github.com/Idov31/Cronos) ★627 | 可等待定时器 + ROP | 每周期 | 同上 |
| [memN0ps/doublepulsar-rs](https://github.com/memN0ps/doublepulsar-rs) | Rust UDRL；sleep-ekko/foliage/zilean 三变体全是 **RC4 + NtContinue 链**经 IAT 钩子 | 每周期 | 已知（2026-10-03 复查项），确认无免翻转变体 |
| [joaoviictorti/hypnus](https://github.com/joaoviictorti/hypnus) ★290 (2025-12) | Rust 睡眠混淆 | 翻转系 | 未细读，README 无免翻转主张 |
| [TheFlink/Hunt-Sleeping-Beacons](https://github.com/TheFlink/Hunt-Sleeping-Beacons) | 检测侧 | — | 1c 完成后须过它的 NG 版 |
| MDSec Nighthawk | 闭源；公开资料无内部细节 | ? | 无参考 |

检测侧背景：[Elastic 内核 ETW 调用栈](https://www.elastic.co/doubling-down-etw-callstacks)、
[Binary Defense: Understanding Sleep Obfuscation](https://binarydefense.com/resource-center)、
[oblivion-malware.xyz Foliage 分析](https://oblivion-malware.xyz/posts/sleep-obf-foliage)——
共识：`MiProtectVirtualMemory` 事件 + unbacked RX + 调用栈归因是三根支柱。
双视图方案三根全不碰：无 protect 事件、无 RWX、（配 PEB 伪装）无 unbacked。

## 2. 底层原语契约（决定可行性的事实）

- **双视图别名**：`NtCreateSection(SEC_COMMIT, PAGE_EXECUTE_READWRITE)` →
  同一 section 两次 `NtMapViewOfSection`：一次 `PAGE_READWRITE`、一次
  `PAGE_EXECUTE_READ`。视图级保护落在各自 PTE，物理页共享；经 RW 视图
  写入，RX 视图立即可见可执行（x86 物理别名天然一致，无 icache flush）。
  注入领域的成熟原语；**用于周期睡眠掩码无先例**。
- **SEC_IMAGE 不能当别名基底**：image section 的视图保护必须与节属性相容，
  无法给 RX 镜像再要一个 RW 视图（STATUS_SECTION_PROTECTION 一族）。
  → 双视图只能以 **pagefile SEC_COMMIT** 为基底——这是与 image-backed
  module stomping 的**硬冲突**。
- **MEM_RESET / DiscardVirtualMemory 救不了写回**：丢弃语义作用于物理页，
  经别名丢弃等于把 RX 侧内容一起清掉；且重提交/重写回仍需 RW → VP。
  它们只能当"纯消失"原语（如丢弃明文 heap 影子），不是翻转替代。
- **每周期事件预算对比**（.text+.rdata+可写节+heap 全掩码）：
  - bofwin 现状：~N 块 × 2 次 `NtProtectVirtualMemory`/窗口
  - 双视图目标：2 次 `NtMapViewOfSection` + 2 次 `UnmapViewOfFile`/周期
    （掩码时映射 RW 别名→RC4→解除；唤醒回调同构），**protect 事件恒零**，
    RX 视图保护常量、内容态翻转。

## 3. 我们的现状盘点（代码锚点）

- `src/sleepmask_gen3.cpp`：`g3_page_writable()`（:58）只收可写页 →
  gen3 睡眠**零翻转、部分覆盖**（.text/.rdata 明文睡）。`gen3_sleep`（:741）
  + 1b timer ROP 栈伪装已过线。
- `src/sleepmask_bofwin.cpp`：`bw_snapshot` 收**全部**节 + tracked heap；
  掩码循环经 `ctx->pVirtualProtect` 每块 RW→orig → **全覆盖、翻转**。
  三段私页 stub（enter/exit/watchdog）+ 页上 RC4-PRGA = 已验证的
  窗口过渡机制，与双视图所需的过渡机制**同构**（把"VP+PRGA"换成
  "map 别名+PRGA"即可复用整套骨架）。
- `src/ReflectiveDll.cpp` / `udrl/ReflectiveLoader.c`：镜像装载归属我们
  （module stomp 路径），双视图改造的落点在 loader。

## 4. 架构提案（"Bouncing" = 视图弹射）

```
装载期（一次性）：
  NtCreateSection(pagefile, SEC_COMMIT, ERW, size=镜像)
  NtMapViewOfSection -> base_rx  (PAGE_EXECUTE_READ)   ← 活镜像
    节铺位按 base_rx 重定位 + IAT + PEB Ldr 伪装条目指向 base_rx
  （RW 别名不常驻——见 §5 风险 r2）

睡眠周期（gen3 窗口框架内，全部动作在私页 stub 上）：
  掩码：map RW 别名 -> RC4 全镜像+heap（经别名写）-> unmap 别名
        -> 线程以伪装栈停在 ntdll wait（现状 1b）
  唤醒：timer 回调（私页 stub）-> map 别名 -> RC4 解 -> unmap
        -> 释放 wait -> 线程回 base_rx 明文代码
```

与 bofwin 的关系：bofwin 的 BOF 窗口可直接换底——掩码/恢复全走别名后，
enter/exit stub 里的 VP 调用删除，watchdog 的强解同样走别名。1c 与
bofwin 共用一套"别名窗口"原语，属于同一战役的两个消费者。

## 5. 风险清单

- r1 **image-backed 回退**：镜像从 spwizimg 挪进 pagefile section 后，
  PE-sieve/Moneta 的分类从 Replaced(模块) 变 mapped-RX-无文件——Phase 0
  的"unbacked 整镜像命中消失"战果部分回吐（PEB 伪装条目仍在，但 backing
  变 pagefile）。须实测两家扫描器的实际分类再定。
- r2 **常驻 RW 别名 = 常驻明文副本**：别名与 RX 视图共享物理页，运行期
  别名里就是明文镜像（RW 区域含 PE 特征）。对策=别名按周期映射/解除
  （事件换类别），不做常驻。
- r3 栈上返回地址/伪装链：睡眠期 base_rx 是密文，真实返回地址作为值
  留在（伪装）栈上没问题——唤醒时先解密再放行 wait，时序由 timer 回调
  保证（bofwin 已验证同类时序）。
- r4 别名基地址不定：RC4 按字节流经别名写，不解释指针 → 重定位无关。
- r5 API 前置验证缺口：双视图在同一进程、同 section、不同保护的双重映射
  在 Win10 19045/Win11 上的一致性（尤其写入后 RX 侧立即可见、无 TLB/icache
  陷阱）须先在 evasion-lab 做 ctypes PoC 实证——这是 P0 步。
- r6 TS/客户端面无涉（纯 beacon+loader 侧），但槽容量：别名窗口原语若进
  beacon 主体须量 xl（rl0k 无上限路径已通）。

## 6. 架构取舍表（本轮唯一的用户决策点）

| | 现状：image-backed stomp + gen3/bofwin | 1c：双视图别名 |
|---|---|---|
| 睡眠期覆盖 | gen3=可写页 / bofwin=全镜像 | **全镜像 + heap** |
| protect 事件 | gen3=0 / bofwin=~2N/窗口 | **恒 0** |
| map/unmap 事件 | 0 | 4/周期 |
| image-backed | ✓（spwizimg Replaced） | ✗（pagefile+PEB 伪装） |
| 常驻新增区域 | 无 | 无（别名按需） |
| 实现落点 | — | loader（我们 own）+ 窗口原语 |

可选折中：**双形态并存**——stomp 镜像保留为"白天形态"，双视图形态由
profile/任务切换（loader 侧分叉）。成本=两套装载路径都要养。

## 7. 分阶段落地计划（若批准开工）

- **P0 原语 PoC（本机，1 轮）**：evasion-lab ctypes——双映射、RW 写→RX 执、
  RC4 roundtrip 经别名、按需 map/unmap 循环 ×1000 稳定性；Moneta+PE-sieve
  对双视图进程的分类实测（定 r1 的真实代价）。
- **P1 loader 侧（CI，1-2 轮）**：ReflectiveLoader.c 增加 pagefile-双视图
  装载路径（开关编译），RL0K jar 链验证 INITIAL。
- **P2 窗口原语（CI+活测，2-3 轮）**：别名版 enter/exit/watchdog stub
  （复用 bofwin 骨架，VP 删除）；先 bofwin 消费者活测（窗口仍绿 + 外部
  扫描确认零 protect 事件侧的变化），后 gen3 睡眠消费者。
- **P3 验收**：Phase 0 矩阵回归（重点 EtwTI-FluctuationMonitor 类 +
  Hunt-Sleeping-Beacons-NG + Moneta/PE-sieve）+ 六通道回归。

## 8. 开放问题

- PE-sieve 对 mapped-RX-pagefile-含-PE 的分类名与阈值（P0 实测定）。
- 别名 map/unmap 的最优节奏：每周期 vs 掩码期间常驻（检测面 vs 事件数）。
- spwizimg 假模块是否保留作诱饵（双镜像 vs 单镜像决策，P1 定）。
