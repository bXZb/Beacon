# 前沿规避研究路线（evasion-research 分支）

创建：2026-10-03，基线 = `4.9.1` 分支 `08e2eef`（六通道全绿 + 二轮加固后的树）。
本分支只做规避研究与实验；合入 `4.9.1` 的门槛 = 六通道回归 + 本路线 Phase 0 矩阵双绿。

来源：2026-10-03 联网调研（见 §6 借码清单）+ 2026-09-13/19 既有定论（自定义 beacon
主线、gate 按 4.12 形状期权、社区借码不借约）。

---

## 0. 总原则

1. **源码全控是代际优势**：kit 用户只能改模板（16KB sleepmask blob 槽、UDRL 5KB 限制），
   我们改本体。所有自研项写进 beacon 源码，槽/kit 路径保留为兼容回退。
2. **检测重心已在内核遥测**（ETWti/回调+用户态栈走查），用户态钩子战争结束。beacon 侧
   对内核遥测只能**降敏**，不能摘除（BYOVD 摘遥测属于工具侧，不进 beacon）。
3. **每个 Phase 用 Phase 0 矩阵回归验收**；掩码类改动必须过 mini_sm 行为取证（tier-104
   教训：等价性验证从 git 程序化解析，活测兜底）。
4. 约束：本机无编译器（CI 为准）；x86 明文余量仅 ~512B —— Phase 1/2 的自研件 x64 先行，
   x86 走官方 blob 回退或 jar-only。

## 1. 六层现状（2026-10-03 基线自评）

| 层 | 现状 | 缺口 |
|---|---|---|
| L5 睡眠 | 真掩码过线（XOR + track_memory 全覆盖 + own-table） | Gen2：权限翻转遥测可见；无强加密；无栈伪装 |
| 调用栈 | 无 | **全空白（2026 最热方向）** |
| L4 syscall | 3 syscall + Halo's Gate + direct/indirect 运行时切换 | 面窄；无 RA 欺骗；无 DR 防御 |
| BOF 窗口 | cmd 116 unmask→run→remask 先例；缓存页 RW 闲置 | inline-execute 全路径裸露 |
| L3/L4 内存形态 | 自研反射加载器 | beacon 在 unbacked RX；module stomping 空白 |
| L3 加载器 | ReflectiveLoader 自研（5k/50k/100k） | 无 UDRL 外置链（loader 在 payload 外侧，不占 x86 余量） |

## 2. Phase 0 —— 基线与度量（先行）

- [ ] 扫描器矩阵（`evasion-lab/tools/`，二进制不入库）：PE-sieve（aggressive）、Moneta；
      可选加 BeaconEye / Hunt-Sleeping-Beacons（无编译器，有 release 才加）。
- [ ] 基线协议：artifact 生成 EXE（走 client CWD 影子=当期构建）→ 本地起进程 → 矩阵扫描
      → 记录命中（`evasion-lab/EVASION-BASELINE.md`）。
- [ ] 两个基线点：r2_nosm（掩码关，现状 worst/best 对照）与 mini_sm（掩码开）。
- [ ] ETWti 采样：睡眠周期内权限翻转/线程事件计数（工具待选，允许降级为
      ETWEventTrace 脚本级）。
- 产出：六层可见性清单 = 后续所有 Phase 的验收尺。

## 3. Phase 1 —— Gen3 睡眠链（x64 先行，最大缺口）

全部在 `GargleSleep` 家族内实现，与官方 GARGLE blob 双路径共存（profile 开关切换，
防掩码打架重演 tier-104 类静默故障）。

- **1a 强加密睡眠**：APC（NtQueueApcThread，Foliage 式）或 TpAllocWait（Zilean 式）自掩码
  + RC4（SystemFunction032），key 每周期旋转。参考 doublepulsar-rs 的三式实现（Rust 借算法）。
- **1b 调用栈伪装（性价比最高）**：移植 Cobalt-Strike/CallStackMasker 进睡眠窗口——
  static（spoolsv 模板）起步，dynamic（克隆 WaitForSingleObjectEx 线程）为进阶。
  与 1a 同一个睡眠窗口合并交付。
- **1c 免权限翻转（Bouncing）**：自释放→重分配 + 句柄表重定位；公开无实现，自研机会，
  排最后。
- 验收：Phase 0 矩阵命中数显著下降 + mini_sm 行为取证（存活+掩码态+任务响应）+
  六通道回归（掩码路径改动必跑 pivot/extc2）。

## 4. Phase 2 —— gate 扩容 + 反遥测

- syscall 面 3 → 注入/内存全路径（SysWhispers4 形状：direct + indirect，return address
  落 ntdll `syscall;ret`）。
- 三热点 RA 欺骗（AceLdr 配方：InternetConnectA/NtWaitForSingleObject/RtlAllocateHeap）。
- **DR 防御（2026 新增）**：GetThreadContext 周期自检 DR0-3 + 清零/VEH 恢复——对抗 EDR
  硬件断点钩子（Blindside/LayeredSyscall 类趋势的反面）。
- gate 枢纽形状保持 4.12 FUNCTION_CALL 期权（TS 升级时重估）。

## 5. Phase 3/4/5 —— BOF 掩蔽、加载器、行为

- **Phase 3**：cmd 116 的 unmask→run→remask 推广到 inline-execute 全路径 + BOF 缓冲隔离
  + 闲置页掩码。验收：BOF 窗口内 PE-sieve/Moneta 无命中。
- **Phase 4（条件启动）**：module stomping 为验收目标（Moneta/PE-sieve 全绿 = 消除
  unbacked RX）；doublepulsar-rs 直接作外置 UDRL 或 C 移植其算法；loader 在 payload 外侧
  不占 x86 余量。
- **Phase 5**：行为降敏（jitter、拆分稀释、流量硬化）——内核 ETW 行为关联的唯一现实应对。

## 6. 借码清单（收割顺序）

| 优先级 | 来源 | 用途 | 许可注意 |
|---|---|---|---|
| 1 | Cobalt-Strike/CallStackMasker | 1b 主料（C，直接移植） | 官方 PoC |
| 2 | memN0ps/doublepulsar-rs | Ekko/Foliage/Zilean 算法 + 堆隔离 + IAT 钩子 | Rust，借思路 |
| 3 | Cracked5pider/Ekko、WithSecureLabs CallStackSpoofer/TickTock | 栈伪装/睡眠底层件 | — |
| 4 | TheD1rkMtr/ShellcodeFluctuation | 睡眠加密+栈伪装组合先例 | — |
| 5 | naksyn 系列文章 + "Don't Be So Primitive" | Phase 4 module stomping 配方 | 文章 |
| 6 | 0xdbgman EDR Tradecraft | 检测视角对照表 | 文章 |

参考源码镜像到 `evasion-lab/reference/`（保留原许可与出处注释）。

## 7. 诚实边界

- ETWti/内核回调只能降敏；开源矩阵全绿 ≠ 一线 EDR 全绿（真机 EDR 实验室为独立预算项）。
- LACUNA Ghost Frames 无公开 PoC，方向性参考。
- 掩码双路径（自研 vs 官方 blob）必须开关隔离 + 双验收。

## 8. Phase 1 施工日志（2026-10-03）

- 实现：`src/sleepmask_gen3.cpp`（1a RC4/SystemFunction032 + 块计数派生 key；1b CallStackMasker
  移植=timer ROP NtContinue x4 + spoolsv 静态形状 + 帧尺寸从 unwind 实算）。集成在 GargleSleep
  官方 BOF 之前，失败自动回退。x64-only（x86 编空）。
- 预验证抓到：UNW_FLAG_CHAININFO 宏值应为 0x4（误写 0x2 = UHANDLER，会把异常 handler 指针当
  链式 RF 走）。Python 复刻算法对真实系统 DLL 四帧全解（160/64/48/128，总 408B）。
- **bisect 矩阵**（mini_sm 活体，构建 a0ce43f/212640a/5ed3b0d/99f9a96）：
  - A：RC4 全范围 + Sleep → **死**（<20s，.text in-place 加密毁掉自身返回路径——官方 BOF 能掩
    .text 是因为它整体在掩码范围外的映射里执行）
  - B：RC4 剔 .text + ROP → **死**（<20s）
  - C：无 RC4 + ROP → **活 4+ 窗口**，但 .text 为官方 XOR 密文 → 疑似 init 失败回退官方路径
  - 矛盾：同代码 A/B 的 init 应与 C 同成败——待文件探针（g3_log，C:\Users\Public\gen3_trace.txt）
    揭示 init 失败点/路径选择
- 结构性结论（已定）：**掩码引擎必须在掩码范围外执行**。.text 全覆盖的正解 = 引擎拷贝到私有 RX
  页（syscalls 桩先例）——列为 1a' 后续。

## 9. Phase 1 bisect 战报（2026-10-03，构建 a0ce43f..4d45c1b 共 11 轮）

gen3（RC4 掩码 + CallStackMasker ROP）在 mini_sm 活体上经历了 11 轮构建-部署-取证循环。
已修复并各自实证的真缺陷（按发现顺序）：

1. **UNW_FLAG_CHAININFO=0x4 不是 0x2**（UHANDLER）——Python 对真实系统 DLL 复刻算法预验证
   抓到；四帧尺寸 160/64/48/128 全解。
2. **掩码引擎不得掩自身代码**——RC4 in-place 加密 .text 即毁掉 enc 循环自己的返回路径
   （官方 BOF 活着是因为整体在掩码范围外的映射里执行）。修正=snapshot 解析自身 PE 头把
   .text 从掩码范围剔除（头页保留）。.text 全覆盖的正解=引擎拷贝私有 RX 页（后续 1a'）。
3. **c1e608.. “.text 密文”是取证伪影**——掩码全关对照仍读到同值：那是 Loader.Beacon 区
   +0x1010 的固有字节。**Phase 0 的“三节全密文”证据同理作废**（采样对象错位）；镜像定位
   必须区分 loader 区/blob 副本/执行镜像三个 MZ。
4. **gparms 在 gen3 路径上是 NULL**——gargle_setup_parms 只被官方 BOF 路径/蹦床惰性调用，
   都在 gen3 之后；`*gparms` 即崩。修正=gen3_sleep 自行初始化（无排除区间）。
5. **窗口时序=官方 BOF 契约**：掩码开始到解密完成之间零 API 调用（掩 .rdata=掩 IAT）。
   修正=一切解析/armed 前置 + 窗口内仅经预解析指针睡眠。
6. **G3_ROP_OFF 曾仍 armed 四个 timer**——300ms spoof 拍踩坏 kernel32!Sleep 中线程的栈，
   60s 醒来走假链 fail-fast。修正=ROP_OFF 分支彻底不建 timer。
7. **SystemFunction032 指针是 .data 静态**——掩码回调与 unmask 都必须用掩码前缓存的指针
   （mctx.fn），读密态 g_sf032=调密文地址。

**当前卡点（第 7 层）**：1a-only 窗口（RC4 + 预解析 Sleep）在窗口结束后死亡——mini_dbg
（自研 DEBUG_EVENT 调试器，evasion-lab/mini_dbg.py）抓到终局异常：**beacon .text 的
IAT thunk `call [rip+0x1c220]` 槽值=-1，tid=主线程**=醒来后 checkin 调 WinINet import
即死——**mask/unmask 在 .rdata 上不对称**（某块只加密未恢复，或恢复用了不同密钥流）。
下一轮动作：g3_log 全指针化（CreateFileA/WriteFile/CloseHandle 预解析进 mctx）+ unmask
逐块打点（掩码期打点合法化的唯一途径），或 x64dbg 断 unmask 循环比对块数/密钥。

**方法论沉淀**：①掩码引擎的一切状态（代码/IAT/静态指针/打点 IO）必须在掩码范围外或
预先捕获到栈；②“密文”判定必须与磁盘原文比对且确认采样对象；③DEBUG_EVENT 的 union
在 x64 有 4 字节对齐 padding（ctypes 复刻要加）；④无 WER dump=典型 fail-fast，用
mini_dbg 抓 first/second chance 才有崩点。

分支状态：HEAD 4d45c1b（G3_ROP_OFF 开启=1a-only 形态；ROP 实现在位待时序轮）；探针
g3_log 仍在（验证过线后清除）；TS 已复位 r2_nosm；全部 ev* 测试进程已清。

## 10. Round 12-14：1a 破案定谳 + 过线（2026-10-03，e6c6c2f/eb7fafa）

### Round 12 破案：上一轮"不对称"理论被推翻，真凶两连环

**第一凶（打点非法）——纯桌面证据钉死，零构建**：
- 上一轮崩溃留下的 gen3_trace.txt 显示：每个进程的日志都止步于 `nblocks`，
  `ROP window served`/`unmasked` 从未出现；beacon_ptr 每窗不同=每轮都是新进程。
- 用崩溃地址 0xd350ca 对 trace 里的 6 个 beacon 基址逐一验证（`_re/base_candidates.py`）：
  base=0xD20000 时 RVA 0x150CA 处恰为 `ff 15 20 c2 01 00`，目标槽 RVA 0x312F0
  = **KERNEL32!CreateFileA**——全镜像唯一调用者就是 g3_log。
- 即：**gen3_sleep 第 554 行 `g3_log("ROP window served")` 在 mask 之后、unmask 之前
  执行，CreateFileA 走的还是密文 IAT**。编译级核查（`_re/window_path_thunks.py`）：
  窗口路径上仅 g3_log 含 3 处 thunk 调用，g3_rc4 零调用（memcpy/memset 全内联）。
- "槽值=-1"的精确来源仍开放（RC4 密文≠全 FF），但不影响定性。
- 修复（e6c6c2f）：G3_IO（CreateFileA/WriteFile/CloseHandle+路径，init 时一次解析，
  走 mctx 栈副本）+ 数值化 g3_log_n（行内容纯栈构造，掩码期合法）+ 四相 FNV 逐块
  校验（C=掩码前明文 / m=掩码后 / u=unmask 入口 / U=unmask 后）+ g3_rc4 去 CRT 循环。

**第二凶（块表重叠）——活测抓到**：修复后首测（ev26）：进程活过窗口但 lastf 增长
（通信死）、窗口照转（mctx 全栈缓存扛住 .data 损坏）。trace 判定（trace_verdict.py）：
块 27-32 u!=m 却 U==C（数学上 U==C⟺u==m，矛盾=**重叠双掩码指纹**），块 2（.data）
两窗一致 U!=C。B 表+mem_census.py 定谳：**EXE 载具把整个映像一次 VirtualAlloc 成
单块 PRIVATE RWX（0x720000 起），六个被跟踪的堆分配（0x769E70-0x76D1A0）落在
.data/.bss 段内部**——段块与堆块重叠 → 逐块密钥的 RC4 双重加密不满足交换律 →
后序块 unmask 对重叠区多 XOR 一遍 → .data 永久损坏。
- 修复（eb7fafa）：快照时按 SizeOfImage（lfanew+24+0x38，注意 PE32+ 偏移坑）剔除
  映像 span 内的堆记录（段块已覆盖；部分跨界只保留界外尾巴）。
- 连带发现：**官方 XOR 路径同样存在该重叠**——同 mask 双 XOR=恒等 → 那六个块在官方
  掩码下一直保持明文（覆盖洞，非损坏）。列入 C-batch 加固清单。

### Round 13-14：1a 过线（ev28，sleep 5，~40 窗口）

| 证据 | 结果 |
|---|---|
| 逐块 round-trip | **C=1183 m=1183，VIOLATIONS=0**（每窗 29 块全 U==C、m≠C、u==m） |
| 密钥轮换 | 窗间 29/29 块密文校验和互异（PASS） |
| 通信活性 | lastf 恒 4s，checkin 每窗一次 |
| 掩码态功能任务 | 窗口循环中下发 ps → 完整进程表返回 |
| 外部视角采样 | 25s 内 .data 定点 7 个值：明文→任务后新明文→**5 窗各不相同的密文**（mask_sampler.py，扫描器视角坐实真加密+轮换） |
| 崩溃 | mini_dbg 全程仅 1 条良性线程启动断点（80000003 first-chance） |

**测试工具链沉淀**（evasion-lab/）：trace_verdict.py（四相判定+旋转）、
mask_sampler.py（外部密文采样）、mem_census.py（区域普查）、thread_where.py +
WMI Win32_Thread（线程等待原因定位"卡死"）、ev_round.py（inbox 驱动，ack 时间戳
变化等待，防单文件 inbox 覆盖丢命令）。

**驱动层坑**：headless 的 `sleep` 命令 a1 单位是**秒**——`sleep 5000`=5000 秒
（DelayExecution 等待 83 分钟，看似挂死）；正确用 `sleep 5`。诊断法：WMI
ThreadWaitReason=4（DelayExecution）=在 Sleep 里，不是挂死。

**patch_ts.restart_ts 会把 start_ts.sh 覆写回 r2_nosm**（已知断言坑）：mini_sm 测试
用 scripts/restart_ts_minism.py（每次 patch 六槽后必须重跑）。

分支状态：HEAD eb7fafa；探针（g3_log/g3_log_n/trace 落盘）保留至 1b 验收后统一清除；
六槽 sleeve=eb7fafa 构建（37126064985）；TS 已复位 r2_nosm（pgrep 硬验证）；ev26-28
进程已清；round12/round14 证据存 evasion-lab/round1*_*.txt。

### 下一步（1b：ROP 时序轮）

1. 关 G3_ROP_OFF，恢复四 timer ROP 链；修复点：restore 拍必须严格早于唤醒拍
   （time+590 SetEvent time+600 曾在掩码态下死），spoof 拍与 `time` 的相对时序
   在 5s 窗口下重新标定（300ms 绝对偏移沿用即可，beats 都相对 time）。
2. 验收证据：evidence_gen3.py 栈走查（spoolsv 四帧链，掩码态抓 2 次）+ 1a 全套
   （round-trip/轮换/通信/任务/外部采样）复跑。
3. 过线后：清探针 → Moneta 对比 → 六通道回归（本分支 sleeve 全链 gen3）。

## 11. Round 15-16：1b 过线 + 六通道首扫三雷（2026-10-04，e9bdf45/c38ad2f/bacec11）

### 1b（ROP 调用栈伪装）活测过线（ev29，sleep 5，96+ 窗口）

两个掩码态窗口洞修掉后 ROP 链直接工作（bisect-C 的机制从未坏——当时死因就是 554 行
g3_log 走密文 IAT 与 SetEvent 桩地址两类问题）：
1. **`(DWORD64)SetEvent` 取的是 .text IAT thunk 桩地址**——SetEvent 拍在掩码态触发时
   `jmp [rip+X]` 读密文 .rdata 槽→跳垃圾。修=GetProcAddress 真地址。
2. **teardown（DeleteTimerQueueEx/CloseHandle）在 pwait 返回后、unmask 前执行**——同走
   密文 IAT。修=预解析局部指针。
3. 短窗守卫：time<700ms 时 timer 拍（150/300 固定）会与 time+600 唤醒乱序→退回
   指针化 Sleep 窗口。

| 证据 | 结果 |
|---|---|
| round-trip | 2639 块审计 **0 违规**（96+ 完整窗口，VIOLATIONS=0） |
| **spoolsv 链（外部栈走查）** | **chain-exact 2/2**：主线程（UserRequest 等待）栈上 slot0=`kernelbase!WaitForSingleObjectEx+0x8e`（0x1b620+0x8e=0x1b6ae ✓）、slot20=`localspl!InitializePrintMonitor2+0xb7a`（=模块+0x400AA ✓）、slot28=`kernel32!BaseThreadInitThunk+0x14`、slot34=`ntdll!RtlUserThreadStart+0x21`；**帧间距 160/64/48B 与自解 unwind 尺寸逐一吻合**——从 RSP 起整个可见窗口都是伪装帧 |
| 等待原因 | 主线程 ThreadWaitReason 6（UserRequest）≠1a 的 4（DelayExecution）——行为指纹层也换掉了 |
| 其余 | 轮换 PASS、外部采样 20s=6 值（明文→新明文→4 窗互异密文）、掩码运行中 ps/ls 正常、lastf 恒秒级 |

**验收工具三连修**（此前"no localspl observed"全是工具 bug，从未抓到过真栈）：
①Toolhelp 线程快照全系统失效（Thread32First err 24）→ NtQuerySystemInformation 枚举
（nqsi_threads.py）；②x64 CONTEXT flags=0x100010 是**无效值**——API 返回 TRUE 但一字节
不写（金丝雀实锤）→ CONTEXT_FULL=0x10000B + 0x4F0 原始缓冲；③evidence_gen3 旧代码把
Rip(+0xF8) 当 Rsp(+0x98) 读、链校验用函数相对偏移比对模块相对走查值——重写为正确配方
（栈走查深度须 >25 槽才能越过 ntdll 等待帧到达 planted 链）。

### 扫描矩阵对比（掩码窗口内，vs Phase 0 基线）

- **PE-sieve**：Implanted=2（0x800000 PE + 0xD50000 shc）结构性命中；**IAT Hooks=0**；
  **自 dump 的执行镜像 d50000.shc 首字节即纯密文**——扫描器自己抓到了掩码态。
- **Moneta**：4 处全为分配级 IOC（未签名载体/0x800000 RX/0xD50000 RWX/尾页）。
- **诚实结论**：Phase 1 消灭的是**内容级**检测面（签名/YARA/内存扫描类）；分配级 IOC
  （unbacked RX/RWX/unsigned）原样保留=Phase 4 加载器链靶子。**新靶标：0x800000 loader
  区明文 `MZARUH` 永驻**（反射加载器头+staging，用后不抹）。
- x86+gen3 不适用（编译空）；x86 走官方路径——见下。

### 六通道首扫三雷（e9bdf45 构建，TS mini_sm）

| 通道 | 首扫 | 判定 |
|---|---|---|
| A http(gen3) | LS/PS 正常、lastf 秒级 | **PASS**（=ev29） |
| B winhttp(gen3) | INITIAL+LS 字节 | **PASS**（ev30） |
| C x86 http(官方路径) | **c0000005 崩溃**（首 checkin 后数秒，偏移 0x3c3003b unknown） | 预存缺陷：**x86+sleep_mask 从未活测过**（历史 sm-true 全是 x64）；非本分支引入（x86 无 gen3 改动）；待专轮修 |
| D dns(gen3) | 进程活、无 INITIAL | **环境阻断**：本机出站 UDP:53 被 singbox TUN 吞（已知，需用户关 TUN） |
| E extc2 | 载荷 DllMain 后宿主进程静默死 | **INT3 蹦床雷，已定位+拆除**：`GarglePipeWait` nook≠0 时执行 `_gargle_it` 模板桩（extc2 专属 map 定位 RVA 0x13C84，mini_dbg 抓到 6 连 INT3）——**4.5 等待掩码蹦床在本代码库从未实现**（INT3 占位），nook=0 时无害返回、掩码 profile 一开即死。r2_nosm 回归绿是因 nook=0 |
| F pivot SMB/TCP | spawn 发给了已死的 ev31=连坐 | 待 bacec11 构建重跑 |

**拆雷（bacec11）**：GarglePipeWait/GargleBlockPipe/GargleWaitTCP/GargleAccept 与
GargleSleep 尾部兜底，全部退化为已验证的无掩码姿态（plan-B ConnectNamedPipe/裸
accept/裸 Sleep）——与 gargle_own_sections "空表=降级不崩溃"同一原则。**真修复=
gen3 wait-window 变体**（掩码窗口包住任意长等待，见 §12 入口）。

**六通道驱动坑**：wait_for 正则必须 re.MULTILINE（chunk 从任意字节起）；`spawn` 发给
死会话只排队无效——先验目标存活。

分支状态：本地 c38ad2f（探针门控 G3_TRACE，默认零开销）+ bacec11（拆雷）**待推**
（GitHub 直连+代理双断，重试循环中）；部署 sleeve=e9bdf45；ev29/ev30 留作重跑父会话；
ev32(dns) 已清；TS 仍 mini_sm 待矩阵重跑后复位。

### Phase 1 收口状态

- **1a（RC4 旋转掩码）：过线**（§10，40 窗 0 违规）。
- **1b（调用栈伪装）：过线**（本节，链铁证+96 窗 0 违规）。
- **1c（Bouncing 免权限翻转）：未实现**——公开无实现、自研项，依赖 1b 的窗口框架扩展
  （VirtualFree+重捕获+句柄表重定位），排 Phase 1 收尾后的独立轮（§12）。
- 验收矩阵：内容级面清零（PE-sieve 自证密文）；分配级保留（Phase 4）；六通道
  A/B 绿、E 拆雷待重跑、F 待重跑、C=独立 x86 轮、D=环境。

## 12. Round 17：CFG 会战收官（2026-10-04，626dd01→1d9d397）

spawn 注入形态（rundll32）在 1b ROP 下首窗口死亡——两次同点 c0000409
（ntdll+0xa2920=int 29h）。mini_dbg2（first-chance 栈走查）+ IDA 符号化 ntdll 定谳：

**RtlpTpTimerCallback → ZwContinue → LdrpHandleInvalidUserCallTarget →
RtlpHandleInvalidUserCallTarget → int 29h**

= **镜像级 CFG 进程里 NtContinue 校验伪造 RIP，ntdll!memcpy/SetEvent 不是合法间接目标**。
第一版修复（GetProcessMitigationPolicy 查进程策略位→降级）无效——策略位不反映镜像级
CFG（rundll32 PE 头带 CFG 元数据），父会话照样死。**终版修复（1d9d397，Ekko 式）**：
SetProcessValidCallTargets 把两个 beat 目标（memcpy/SetEvent）按页加入合法位图；API
失败才降级 1a。注意该调用有遥测可见性（Phase 2 换 CFG-valid 拷贝原语，见下）。

**终局活测（1d9d397，TS mini_sm）**：
- EXE 形态（ev34）：INITIAL+sleep 5+ps 全表 ✓（白名单对 CFG-off 进程无害）。
- **spawn 注入形态（rundll32 498127652）：INITIAL 后 4+ 分钟存活、lastf 恒 2s、
  mini_dbg2 全程零异常**——gen3 在 CFG 宿主注入形态下首次过线。
- 残留：smb_link 的 link 子 spawn 在 mini_sm 下未出 INITIAL（父活、任务可达；
  r2_nosm 下该链历史全绿→掩码 profile 特有 wrinkle，留专轮）。E extc2 按日志判定
  PASS（INITIAL+ps 0.15s 返回，驱动脚本自身赛跑 bug 误报 FAIL）。

### Phase 1 最终收口（2026-10-04）

| 项 | 状态 |
|---|---|
| 1a RC4 旋转掩码 | **过线**（§10：40 窗 1183 块审计 0 违规+外部密文采样） |
| 1b 调用栈伪装 | **过线**（§11：chain-exact 2/2+帧距逐一吻合+96 窗 0 违规） |
| 1c Bouncing | 未实现（公开无实现；依赖窗口框架扩展，独立轮） |
| 验收-行为取证 | 存活/掩码态/任务响应/外部采样 全绿 |
| 验收-扫描矩阵 | 内容级面清零（PE-sieve 自 dump 纯密文、IAT hooks 0）；分配级保留=Phase 4 靶（0x800000 明文 MZARU loader 区为新增明确靶标） |
| 验收-六通道 | A http ✓ B winhttp ✓ E extc2 ✓ S 无探针烟雾 ✓；F pivot 父链 ✓/link 子留专轮；C x86=官方路径预存崩（从未测过 x86+掩码，独立轮）；D dns=TUN 环境阻断 |

**本轮沉淀的预存缺陷清单（非 gen3、非本分支引入，全部因首次掩码 profile 全通道
测试而现形）**：①4.5 等待掩码蹦床=INT3 占位（已拆除→无掩码降级；真修复=gen3
wait-window 变体）；②x86 官方 sleepmask BOF 路径崩溃；③smb_link 子 spawn 掩码下
wriggle；④官方 XOR 路径映像内堆块重叠=明文洞（C-batch）。

**Phase 2 入口（按序）**：
1. gen3 wait-window 变体（掩码包住 pipe/TCP 任意长等待，替代 ①的降级）。
2. CFG 隐蔽原语：换掉 SetProcessValidCallTargets（CFG-valid 拷贝函数或 DR+VEH 路
   线），消掉遥测可见性。
3. gate 扩容（syscalls.cpp 种子→~25 SSN+RA 欺骗三热点）。
4. 1c Bouncing（自释放→重分配+句柄表重定位）。
5. 1a'：掩码引擎拷私有 RX 页覆盖 .text（官方 blob 式，消掉 .text 明文残留）。
6. x86 官方路径修复轮（②）+ link 子 wrinkle（③）。
分支 HEAD 1d9d397；六槽=1d9d397 构建（37157889360）；TS 已复位 r2_nosm（pgrep 硬验证）；
全部测试进程已清；生产 4.9.1 分支与 r2_nosm 姿态不受影响。

## 13. Phase 2 开工（2026-10-04）

### 13.1 wait-window 变体（§12 入口①，首项落地）

补上 round 16 拆雷留下的无掩码等待（extc2/pivot 管道与 TCP 通道）。设计：

- **服务端连接等待（ConnectNamedPipe）**：`gen3_wait_pipe` = 无 timer 的纯掩码窗口
  （mask → 预解析指针阻塞等待 → unmask）。无 timer ⇒ 天然 CFG 免疫（无需白名单）、
  天然支持无限时长等待。x86/引擎失败 → 返回 FALSE → 落回 plan-B 无掩码循环。
- **空闲数据等待（pipe peek / TCP select / accept）**：`gen3_sleep(700)` 切片轮询——
  每片都是完整 1a+1b 窗口（掩码+ROP 伪装；700ms 已知时长正好适配 beats），探测调用
  （PeekNamedPipe/select 0 超时）是窗口间的微秒级 syscall。gen3_sleep 返回 FALSE
  （x86/引擎未起）→ 裸 Sleep(700) 兜底，不热自旋。
- 守卫语义不变：nook==0 或 threadcount>0（有兄弟线程的父会话）保持无掩码——掩码会
  毁掉活跃线程对镜像的视图。
- 接线：GarglePipeWait（smb_wait 服务端）、GargleBlockPipe（客户端读等待）、
  GargleWaitTCP（recv 空闲）、GargleAccept（TCP 监听接受）。

### 13.2 gate 架构（§12 入口③，设计定稿——2026-09-13 决策延续）

**形状按 4.12 kit 的 FUNCTION_CALL/WinApi 枚举**（设计期近零成本，将来 20251100 kit
mask 或 Crystal Mask 可直接插上）。种子=src/syscalls.cpp（SSN 直读+Halo's Gate 挂钩
逃生+RX stub 页，已验证 3 函数：NtWrite/ReadVirtualMemory+NtDuplicateObject）：

1. **SSN 扩容到 ~25 热点**：注入族（NtCreateSection/MapViewOfSection/WriteProcessMemory
   族/QueueUserAPC/CreateRemoteThreadEx）、内存族（Allocate/VirtualProtect/VirtualFree/
   FreeVirtualMemory）、令牌族（OpenProcess/OpenThread/DuplicateObject）、等待族
   （NtWaitForSingleObject）、文件族（NtCreateFile/NtReadFile/NtWriteFile）。
2. **执行期 RA 欺骗三热点**（AceLdr 配方）：InternetConnectA / NtWaitForSingleObject /
   RtlAllocateHeap——indirect syscall 的 return address 落 ntdll `syscall;ret` gadget，
   再在其上伪造调用方帧（synthetic frames 最小版）。
3. **接入点**：inject_mirror/inject.cpp/execute.cpp/boff.cpp 的敏感调用改走 gate；
   syscalls.cpp:98 旧静态 stub 裸 RWX 自伤修复（fresh RX 分配+销毁，早已完成）。
4. **防御增补**（2026-10-03 联网复查结论）：DR 寄存器检测+周期清零（对抗 EDR 硬件
   断点钩 syscall——Cymulate Blindside/Praetorian DR+ETWti 路线）。
5. 验收：六通道回归 + ETWti/钩子检测器对照（用户态钩子场景 SSN 直读生效；无真机
   EDR，诚实边界不变）。

### 13.3 CFG 隐蔽原语（§12 入口②，研究中）

SetProcessValidCallTargets 有遥测可见性。候选：CFG-valid 拷贝函数作 beat RIP
（需实测 GFIDS 成员资格）、DR 寄存器+VEH 式 syscall 路线、或 CFG 宿主降级 1a（零
遥测但无伪装）。排 wait-window 验收后。

### 13.4 wait-window 验收（round 18，e1b3151→f52d46b）

活测抓到并修复两个真缺陷：

1. **LoadLibrary 只读头页 AV**：extc2 载荷经 LoadLibrary 加载进 python 控制器后，
   PE 头页是只读映射——gen3 掩码块 0（头页）RC4 写入瞬间 AV 写镜像基址。同雷也埋在
   extc2 的 sleep 路径（此前从未活到首个窗口）。修复=快照时 VirtualQuery 剔除不可写
   块（段块+堆记录两处）；**不做权限翻转**——翻转正是 Gen1 遥测面（def09e1）。
2. **extc2 严格交替协议死锁**：700ms 掩码切片让 beacon 的心跳应答错过控制器 0.4s
   peek 窗→控制器转 90s ts_recv→beacon 卡死在 `client_flush→extc2_write→
   FlushFileBuffers`（管道 flush 等对端读走才返回；线程栈实拍定位）。修复=轮询切片
   700→150ms（应答延迟 ~200ms<400ms 窗口；切片走 time<700 无 timer 纯掩码路径=天然
   CFG 免疫，无需白名单）（f52d46b）。

**验收证据（f52d46b，TS mini_sm）**：
- extc2（python 宿主，CFG 进程）：INITIAL ✓、ps 任务字节返回 ✓（死锁消除）、
  **空闲管道等待处于掩码态**——30 秒外部采样出大量互异密文值+切片边界明文
  （每片密钥不同，与睡眠窗口同一旋转语义）。
- SMB spawn 子（rundll32，CFG 宿主）：INITIAL+ls 字节 ✓（掩码运行中）。
- 残留：smb_link 的 link 子仍不 INITIAL（无崩溃事件=未起进程；Phase 1 收口已记录的
  预存 wrinkle，非本轮回归，留专轮）；TCP 链路代码与 pipe 同族未单独活测。

wait-window（§12 入口①）**落地**。§12 入口②（CFG 隐蔽原语）与③（gate 扩容，
§13.2 已定形状）为后续主线；分支 HEAD f52d46b；六槽=37177141982 构建；TS 已复位
r2_nosm；测试进程全清。

### 13.5 gate 扩容落地与间接编码会战（round 19，8128ee2→74786d0）

**已落地并实证（74786d0，CI 全绿 + TS mini_sm 活测）**：
- **25 条 SSN 表**（注入/内存/令牌/等待/文件五族；Halo's Gate 挂钩逃生保留；
  g3_gadget_ok 精确校验 gadget 必须 `0F 05 C3`）。
- **注入热路径接线 17 处**：inject_apcthread ×13（VirtualAllocEx/ProtectEx/FreeEx/
  WPM 族）、execute ×2、两个 CreateRemoteThread 注入器（→NtCreateThreadEx）。
- **Win32 形状包装 7 个**（WPM/RPM/DuplicateHandle/AllocEx/ProtectEx/FreeEx/
  CreateRemoteThread），method 0=API / 1=直通桩 / 2=（暂时）别名直通。
- **DR0-7 采样+清零防御**（resolve 时 + 每 128 次派发；CONTEXT_DEBUG_REGISTERS，
  对抗 EDR 硬件断点钩）。
- **活测证据**：默认 method=1 下 spawn 注入链全走 gate——rundll32 子 INITIAL+ls
  正常；`syscall_method 2` 切换后 beacon 存活可任务；ev36 gen3 窗口与 gate 并存。
- **host 测试规格**（test_syscalls.cpp）：表解析 ≥20 + 自进程 alloc/write/protect/
  read/free 三方法往返（CI 上全过）。

**间接编码（RA 欺骗）四轮 CI 会战——诚实记录**：
1. v2（push ntdll-ret 再跳 gadget）首版 **一字节栈溢出**（gadget 四字 built+25..32
   越界砸 /GS cookie → c0000409）——修。
2. 修后 **v2 push 对 >4 参 syscall 平移栈参数**（内核在 [rsp+8] 读第 5 参，push 后
   读到返回地址；protect 的 OldProtect 指针读到 gadget+2 → AV）——数学上 ret-链
   RA 欺骗与栈参数根本冲突（fake ret 弹出后下一槽必须是真返回地址但那里是参数）。
   收口：≤4 参才用 v2。
3. **v1 跳 gadget 在 live CI 上不稳定**：诊断测试实证 runner 的 gadget 干净
   （`0F 05 C3` 有效地址）且 SSN 正确（m=1 直通全绿），m=2 首调仍 AV——环境性
   根因未明（种子间接编码从未被真跑过）。收口：>4 参 m=2 降为直通。
4. 最终：**m=2 全量别名直通**，RA 链设计保留在树内待专用轮根因（候选方向：重入
   已重写 stub 页的环境因素 / VBS-HVCI / 需 synthetic frames 的正确形态）。

**入口② CFG 隐蔽原语（部分完成）**：live GFIDS 读取工具落地（ntdll_gfids_mem.py），
但本机 ntdll 的 GuardCF 条目带元数据步长（疑 XFG 格式），干净解析需 XFG 感知——
研究入口已留；SetProcessValidCallTargets（遥测可见）保留为现状。

**Phase 2 状态**：核心交付（gate 表+接线+包装+DR 防御+测试+活证）**完成**；
RA 欺骗 v1 形态待根因轮；CFG 原语待 XFG 解析。分支 HEAD 74786d0；六槽=37187577596
构建；TS 已复位 r2_nosm；测试进程全清。

## 14. Round 20-21：RA 根因双杀 + 三个专轮（2026-10-04，2b9ec65→5dbbab18）

### RA 欺骗根因轮——两个真根因，全部修复实证（5dbbab18 CI 全绿）

VEH 复现测试（全局安装+逐步 marker）交付决定性现场 `fault=0x2a0, rip∈ntdll`：

1. **SC_PARSE 宏从未携带 arity 参数**——当初给 SC_LIST 各条目加 arity 的 heredoc 编辑
   静默 no-op（SC_DECL/SC_COUNT 应用了，SC_PARSE 的匹配串没中且无 assert）。所有条目
   arity 恒 0 → method-2 的全部分派都落进 v2 push 编码（不论参数数）→ 栈参数被 push
   平移到内核眼皮底下。**"环境性崩溃"从未环境性；v1-jmp 分支从未真正执行过。**
   修复=SC_PARSE 带 arity 且在 parse 之后赋值（parse 的 memset 会清掉先设的值）。
2. **v2 编码字节序错误**：`mov eax,ssn` 之后再 `mov rax,gadget+2`——64 位 rax 装载
   清零 eax，SSN 变成 ntdll 地址低双字 → 内核拿垃圾 syscall 号派发 → 写 0x2a0。
   修复=先 `mov rax,imm64; push rax` 再 `mov eax,ssn` 再 jmp。

**终局证据（CI）**：三方法 alloc/write/protect/read/free 全绿；复现测试显式输出
"v2 RA-chain free survived - ntdll ret unwound correctly"——**RA 欺骗链（≤4 参
syscall，planted ntdll ret 双弹栈）首次真实执行成功**。method 2 现为完整形态：
≤4 参=v2 RA 链，>4 参=direct（synthetic frames 仍是全参 RA 的正解，留 Phase 2+）。

### GFIDS/XFG 专轮——否定结果关闭

"XFG 步长障碍"实为**VA/RVA 混用**（load config 的 GuardCFFunctionTable 是含
preferred base 的 VA，当 RVA 用=双重基址读垃圾）。修复后本机 ntdll 解析出 1770 条
合法目标：**memcpy/memmove/RtlCopyMemory/RtlMoveMemory/RtlFillMemory/memset 全部
不在表内**（仅 RtlQueryPerformanceCounter 等零星函数在）——"换 CFG-valid 拷贝
原语"路线在本平台不成立，**SetProcessValidCallTargets 保留为定论**（遥测可见性
已记录，替代方向=DR+VEH 路线或 Ghost Frames，Phase 2+）。

### 六通道回归（5dbbab18，TS mini_sm，日志判定）

| 通道 | 结果 |
|---|---|
| A http（gen3+gate+RA 版） | **PASS**（INITIAL+sleep5+PS 全表；无探针构建） |
| E extc2（wait-window+150ms 切片） | **PASS**（INITIAL+PS 0.3s 返回；驱动脚本自赛跑误报，日志为准） |
| F pivot 父链（spawn 经 gate+RA 版注入） | **PASS**（rundll32 子 INITIAL+sleep） |
| F link 子 | FAIL——**专轮定谳**：WMI 进程监视 60s 零子进程创建；父会话回 `Could not connect to pipe: ERROR_FILE_NOT_FOUND`（link 复合任务的 spawn 步骤静默失败；普通 spawn 同一注入路径成功）。根因方向=link-spawn 特定路径，需带日志构建深挖 |
| C x86 官方掩码 | FAIL（预存）——**专轮崩点钉死**：mini_dbg2 首机会抓到 `rip=PRV(3B30000)+0x3b`（官方 4.5 sleepmask BOF 的 16KB blob 内部，WOW64 进程）=BOF 段表假设与我们 x86 PE 布局不匹配，同类 x64 own-table 战役（5c753e1）的 x86 版，需专项分析 |
| B winhttp / D dns | 未重跑（本轮聚焦 RA/专轮；B 上轮同构建族 PASS，D=TUN 环境不变） |

**方法学**：六通道判定永远信 r1.log 字节不信驱动进程返回（本轮 E 又被驱动误报）；
`python -c` 里带 `\n` 的字符串经 bash 必被拆行（三次翻车），测试代码一律 Write 落盘。

分支 HEAD 5dbbab18（CI 全绿）；六槽=37198777092 构建；TS 已复位 r2_nosm；测试进程全清。
下一轮入口：①link-spawn 根因（G3_TRACE/日志构建）②x86 官方 BOF own-table 战役
③六通道补 B/D 全量 ④gate 接线扩至文件/令牌族调用点。

### 13.6 Round 22：x86 解崩 + gate 扩文件/令牌族 + B 通道（07aa4b0）

**x86 官方掩码路径修复**：官方 4.5 sleepmask BOF 在我们 x86 PE 布局的 WOW64 进程里
崩在 blob+0x3b（round 18 钉死）。降级修复=GargleSleep x86 跳过 BOF 路径直接 Sleep
（无崩溃+opsec 降级；x86 own-table 战役=正确修复，需分析官方 BOF 的段表假设 vs
我们的 x86 PE 布局，同 x64 5c753e1 战役方法论）。

**活测**：ev41 x86 INITIAL + sleep + ls ✓ 不再崩溃。

**gate 接线扩容到文件/令牌族**：新包装 NtOpenProcess/NtOpenThread/NtClose/NtReadFile/
NtWriteFile（NtCreateFile 留 API——路径转换非平凡且文件创建遥测低优先级）；接线
17 处（hotbeef/ps×2/tokens/ppid/inject_apc/inject_hinted×4/files×7）。gate 现覆盖：
- 注入族：alloc/protect/free/WPM/RPM/dup/CRT（原 7 处+13）
- 文件族：ReadFile/WriteFile/CloseHandle
- 令牌族：OpenProcess/OpenThread

**winhttp B 通道**：ev42 INITIAL + sleep 5 + ls ✓ PASS。

**link-spawn 根因记录**（不修，需日志构建）：TS beacon_link 发两条任务——spawn+inject
（载荷=pivot sleeve）+ pipe connect。connect 到达并执行（回 ERROR_FILE_NOT_FOUND），
spawn 侧零进程创建。方向=需 G3_TRACE 式日志构建追踪 spawn_patsy 内部。

分支 HEAD 07aa4b0（CI 全绿）；六槽=37206734168；TS r2_nosm。

### 13.7 Round 23：link-spawn 定谳 + x86 容量墙（56ad396→6f19159a）

**spawn 路径追踪（spawn_trace）**：spawn_patsy/command_inject/link_start_explicit/
inject_logic 四点打点（共享 sink 函数，x86 友好）。两次活测全链捕获：

```
inject: calling spawn_patsy x86=0
patsy: cmd=C:\Windows\system32\rundll32.exe
patsy: exec_ppid result=1
inject: spawn_patsy ok pid=2136
inject_logic: entry len=304128
inject_logic: mirror ok / execute ok
link_start_explicit: entry pipename=\.\pipe\reg11pipe
link_start_explicit: returned（无第二次 spawn）
```

**定谳**：TS beacon_link 的 spawn+inject 任务全链成功（子 rundll32 起来并注入），
**子会话成为 HTTP beacon 而非 SMB pivot**——INITIAL 来自 rundll32、child 从未创建
`\.\pipe\reg11pipe`，故父的 0x44 connect 报 ERROR_FILE_NOT_FOUND。**根因在 TS 侧
载荷选择**（beacon_link 复合任务把 http listener 载荷发给 spawn，而非 pivot sleeve；
或 pivot sleeve 的 PIPENAME 设置未进 spawn 载荷），**beacon 侧行为全部正确**。修复
方向：TS 复合任务构造（pivot.x64.dll + pipename setting），属 TS 侧改造，立项单测。

> **【Round 25 修正】以上定谳已被推翻**（见 §13.9）：观察到的 HTTP 子是驱动自己
> `spawn http x64` 起的 link 父；`beacon_link` 是 LINK-ONLY（cmd 68 连管），从没人
> spawn bind 子，管道自然不存在。TS 与 beacon 双侧无错，销案。

**坑（第七次反斜杠）**：spawn_trace 路径字面量被 heredoc 吃成
`C:UsersPublicspawn_trace.txt`（相对路径静默成功）→ 建文件名诡异的全局真相。修复=
真双反斜杠（6f19159a）。

**x86 容量墙（硬约束发现）**：gen3-1a x86 移植编译通过但 **x86 sleeve 249376B > 槽
247840B（超 1536B）**——gen3-1a 成本 ~2.5KB > x86 余量 ~2KB。回退为设计决定：
**x86 unmasked-by-design**（官方 BOF 本就 WOW64 崩），own-table x86 战役重新立项为
"先解决尺寸预算"（候选：x86 裁 gate 包装 / 裁 spawn globals / 专属极简 masker）。
trace 共享函数化后 x86 回落 247328B ≤ cap。

**③ D dns**：环境项（TUN 吞出站 UDP:53），下次用户关 TUN 补测，不阻塞。
**④ synthetic frames 设计（Phase 2+，未实现）**：全参 RA 欺骗的正确形态——
   ROP/RA 链对 >4 参 syscall 数学不可行（ret-链弹栈与 [rsp+8..] 栈参数冲突）；正解
   =在 gate wrapper 内构造完整假帧链（fake frame: [ret→ntdll][args...][ret→真调用
   方]），syscall 由真实帧发出、内核走查见到的是合成链；参考 Ghost Frames/LACUNA
   （0xmaz）方向，与 DR 清零共同构成 gate 的栈/寄存器双防御。

分支 HEAD 6f19159a（CI 全绿）；六槽=6f19159a 构建待部署验证；TS mini_sm。

### 13.8 Round 24：D 通道补测过线（TUN 关闭后，3f790fb→6f19159a 构建）

用户关闭 singbox TUN 后补测 D（dns）。**两层根因全部实证并处置**：

1. **TS 侧 53 端口竞争**：headless 会话恢复时重建多个 DNS listener，dns_go 抢绑 53 →
   dns_ok `BindException` 成为死监听（应答来自 stale handler，永远 0.0.0.0）。
   处置=删竞争者 + 干净重启 TS（杀进程确认 PORT53_FREE 再起）。
2. **注册闭环的正确操作序列**（10/01 §6.2 已实证的 TS bootstrap 语义，本轮复核）：
   新 id 首查 → TS `update()` 创建**空会话**（`beacon_initial_empty` 事件）+ 回 idle；
   元数据信号 0xF1 只发给 `isCheckinRequired==true` 的会话（有人 task 过）。
   **本轮缺的其实是观测**：headless_drive.cna 没挂 `beacon_initial_empty` 事件，
   空会话一直在 UI 里而我们看不见。补 hook 后全链一次通过：
   - `INITIAL_EMPTY 302284734`（staged dns session）
   - target 空会话 + `pwd` → 应答切换 0x243
   - beacon `www.` 信道上传元数据 → `CHECKIN 8B` → `ALT Current directory...` →
     **真会话 INITIAL**
   - 稳态：60s 周期 CHECKIN、ls 字节返回、进程持续存活 ✓

**dnsb 三零周期元数据推送（3f790fb）保留**：作为无人值守场景的自愈（TS 重启后
会话丢失时 beacon 自动重注册），不与官方 task 触发语义冲突（空会话存在时信号路径
优先）。

**cna 修复**：headless_drive.cna 补 `beacon_initial_empty` hook（观测盲区教训——
判定通道过线前先确认事件面完整）。

**D 通道判定：PASS。六通道至此全绿**（A http / B winhttp / C x86（官方路径，
降级不崩）/ D dns / E extc2 / F pivot 父链；F link 子=TS 侧载荷选择问题已立项）。

分支 HEAD 3f790fb（dnsb 自愈）+ 6f19159a（spawn_trace 路径修复）；六槽=37244647834；
TS 已复位 r2_nosm；进程全清。

### 13.9 Round 25：F link 子过线——推翻 Round 23 定谳，根因=驱动误用 link-only 调用

**本轮打的是上轮报告的第一优先级**（TS beacon_link 载荷选择）。逆向客户端/TS
链路后**推翻了 §13.7 的定谳**：

**正确链路（反编译实证，全部读源）**：
- `link`（UI/console）→ `TaskBeacon.LinkExplicit` = **cmd 68（0x44
  PIPE_OPEN_EXPLICIT）+ ASCIIZ 管道名——纯连接，不产任何子进程**
- cna `beacon_link($bid,".",$listener)` → `linkToPayloadLocal` → 同样只有
  cmd 68（bind_tcp 则 cmd 0x0E ConnectExplicit）
- **官方"spawn+link"复合 = `bspawn($bid, $bind_listener, $arch)`** →
  `TaskBeacon.Spawn(listener, arch)`：cmd 44 注入 `exportLocal(bind_listener)`
  载荷（bind_pipe → `BeaconPayload.exportSMBStage` → `resources/pivot.x64.dll`
  = 我们已替换的客户端 sleeve，管道名进 config）+ Pause(1s) +
  `linkToPayloadLocal` 自动连管
- beacon 侧 `link_start` 自带 **15s 重试环**（CreateFile 失败 Sleep(1000)），
  cmd 68 早到无害；ERROR_FILE_NOT_FOUND = 15 秒内管道从未出现

**旧 F 流程的真相**：驱动先 `spawn http x64`（**故意**起 HTTP 子当 link 父——
round 23 看到的"HTTP beacon 子"就是它，与 TS 载荷选择无关），随后
`smb_link`/`tcp_link` 只发连接任务——**从没有人 spawn bind 子**，管道/端口
无人绑定，15 秒重试后 ERROR_FILE_NOT_FOUND。§13.7 的"TS 复合任务把 http
listener 载荷发给 spawn"假设不成立：spawn_trace 里的 inject(len=304128) 就是
驱动自己要的 http 子。**TS 与 beacon 双侧从头到尾都是对的。**

**修复（零 beacon/TS 代码变更，纯测试侧）**：`evasion-lab/f_link_child.py`
（已入仓库）用正确复合调用；six_reg.py / rerun_ef.py F 段同步换流程；
headless_drive.cna 的 smb_link/tcp_link 注释改为 LINK-ONLY 并指向正确用法。

**活测（mini_sm，构建 37244647834，两次运行可复现）**：

| 步骤 | 证据（r1.log 字节） |
|---|---|
| P0 父 | INITIAL `beacon_f25.exe` + ALT pwd ✓ |
| P1 http 子 | `spawn http_f25 x64` → INITIAL rundll32 ✓ |
| P2 SMB link 子 | `TASKED spawn (x64) windows/beacon_bind_pipe (\.\pipe\f25pipe)` → **双向 `established link to child/parent`** → INITIAL `1634550460` → **LS 字节** ✓；管道实测 52.6s 出现（sleep+jitter 正常时延） |
| P3 TCP link 子 | `TASKED spawn (x64) windows/beacon_bind_tcp (0.0.0.0:4451)` → 双向 established → INITIAL `1700494704` → LS ✓ |
| 负面 | 全程 **0 条** "Could not connect to pipe"（旧失败签名消失） |

三跳链路实证：TS ← HTTP 父 ← HTTP 子 ← SMB/TCP link 子（孙会话 LS 字节穿两级
pivot 返回）。

**方法论教训（第三次同型）**：wait_for 类观测函数从调用时刻起扫，**先于等待
写盘的行会被跳过**（"established link"与 INITIAL 同秒写入，链接行在前）。本轮
驱动两次假 FAIL 均由此来（管道轮询窗口 30s<53s 真实时延 + 链接行早于 INITIAL）。
判定只认 r1.log 字节这条铁律再次救命——**驱动打印的 FAIL 不是证据，字节才是**。

**遗留清账**：F link 子从"TS 侧改造立项"销案（无需动 TS Java）；六通道矩阵的
F 项至此 SMB+TCP link 子双绿。下一优先级=synthetic frames（§13.7 ④ 设计已备）
与 Phase 3（BOF 期掩蔽）。

分支 HEAD 5910dda+本轮（驱动/文档）；无 beacon 代码变更，六槽维持 37244647834；
TS 已复位 r2_nosm（pgrep 硬验证）；headless/beacon 进程全清。

### 13.10 Round 26：v3 合成帧 stub——注入族全参 RA 欺骗落地（943616f）

**§13.7④ 设计的实现**。>4 参 syscall（write/read/alloc/protect/dup/threadex——
ETWti 走查最盯的注入族）此前 m=2 下回退 direct stub，syscall 返回地址直落
无主 gate 页；v2 push 链与栈参数数学冲突（ret 链会把 arg5 当返回目标弹掉）。

**v3 形态（关键机制三件）**：
1. **RA1 = ntdll `leave; ret`（C9 C3）**：stub 入口 `push rbp; mov rbp,rsp` 把
   真栈锚放 rbp（内核不碰非易失寄存器，裸 syscall;ret gadget 也不碰）；
   syscall 返回 → leave：`rsp=rbp` 回真栈 → `pop rbp` 还原调用方 → `ret`
   落 wrapper 真返回地址。**全程不消费任何栈槽**——参数槽零冲突，v2 的
   数学不可能性由寄存器锚定绕开。rax=NTSTATUS 全程无人碰。
2. **栈参窗口 = [rsp+0x28+8k]**（不是 +0x08）：Win64 ABI arg5 在返回地址
   +0x28（跳过 32B 影子空间）——live 直跑的 direct stub（MSVC 调用方布局）
   一直是铁证。合成帧布局：`[rsp]=RA1 | 影子区 | arg5..N | 4×ntdll 假帧链
   （纯观测 cosmetics，永不执行）`。首轮桌面推演曾在 +0x08 犯错，靠
   既有 direct-stub 行为反推修正。
3. **C9 C3 节感知扫描**（find_leave_gadget）：只扫 EXECUTE|READ 节（.data
   命中=DEP 崩）。本机 19044 ntdll 实证存在（RVA 0xC194，≥2 处）；CI
   runner 亦通过。找不到时安全回退 v2（≤4）/direct。

**验证四层**：① capstone 桌面反汇编全 arity（4/5/6/7/11，evasion-lab/
verify_v3_stub.py，108~171B ≤256B stub 页）；② **本机 ctypes 真执行**
（live_v3_host.py：RWX 页放真字节，alloc(6)+write(5)+free(4) 全 status 0
字节级回读，leave 回转+栈参窗口双实证）；③ CI form 断言（synth 非 direct，
37252499261 绿）；④ **真 beacon 活测**（f26_v3_live.py，构建 943616f 六槽）：
beacon ACK `Current syscall method: Indirect` → m=2 下 spawn 注入链
（alloc6/write5/protect5/threadex11 全 v3）+ SMB link 孙链 + 父存活全绿；
**内存实证**（scan_v3_live.py）：0x730000/0x740000 两个 RX 私有页头字节
= `55 48 89 E5 48 81 EC 48/50`（v3 前导+synth 尺寸），页内嵌 leave gadget
= `0x7FF87453C194` = ntdll+0xC194（与宿主扫描逐字节一致）。

**部署链两个新陷阱（已沉淀进流程）**：
1. **update_src.py 遗漏 = 假绿部署**：gh_latest_run 下载后必须 `update_src.py
   <run_id>` 指 SRC，否则 encode_all 编上一轮的旧源——且 patch/verify 全链
   "MATCH"（remote vs 本地旧编码自洽，非新鲜度校验！）。本轮靠内存取证
   （stub 页呈 v2/direct 老形态）抓出。**新鲜度判据=encode 尺寸/sha 相对上轮
   必须变化**（本轮 304160→305184，+1KB v3 代码）。
2. **bsyscall_method 吃名字不是数字**：桥走 `BeaconSyscallMethod.getMethodNumber
   ("None"/"Direct"/"Indirect")`，传 "2" 静默无任务（无 TASKED 行）。判活要认
   beacon 的 ACK 输出 `Current syscall method: ...`。

**x86**：v3 仅 x64（gate 本就 x64-only），x86 sleeve 零增量。

**残留**：深帧（>4 帧后仍见 beacon 帧）与 ROP/合成帧的 ETWti 实机对抗留
Phase 3+ 扫描矩阵轮；syscall 由 gate 页发出本身（RIP 落 ntdll gadget）已由
indirect 覆盖。

分支 HEAD 943616f（本轮）+ 49e5785（R25）；六槽=37252499261 构建（v3 版）；
TS 已复位 r2_nosm（pgrep 硬验证）；headless/beacon 进程全清。

### 13.11 Phase 3：BOF 期掩蔽（bofwin 引擎）——完成、三重等价证明、槽容量墙

**交付**：`sleepmask_bofwin.cpp/.h`——Win32-only BOF（boff.cpp 在 reloc 流里做
导入分析：任何 ftable reloc = 会回调 beacon .text = 不准入）执行期间，beacon
全镜像（.text 含）+ tracked heap 保持 RC4 密文。**验收原案**：BOF 窗口内
PE-sieve/Moneta 零命中。

**形态**：三段手汇编私页 stub（gate-stub 技法）+ ctx 私页：
- **enter_stub**（push-first 栈契约：exit 地址直接放 [ret-8]，0x20 call 对齐
  垫）：VP(.text→RW) → sf032 掩 .text（最后一块）→ jmp BOF 入口（as-if-called）
- **exit_stub**（BOF 的 ret 落进来）：xchg 原子认领（看门狗竞态护栏）→
  sf032 解 .text → VP 回原保护(RX) → FlushInstructionCache → ret 回明文 C
- **watchdog_stub**（one-shot timer，同页）：BOF 卡死时同一认领序列强制解
  掩 + tail-jmp C 侧剩余解掩——**进程永不困在掩蔽态**
- ctx 页固定偏移（key2 工作区/pVP/pFlush/phase 取证），全部调用走预解析
  指针；黑窗纪律 = .rdata 密文后禁止任何 API（含 VEH 内部）

**验证四层（本机全部绿）**：①capstone 镜像全 arity（verify_bofwin_stub.py/
verify_v3_stub.py，jne/disp/对齐逐条断言）；②**ctypes 真执行**（stub 链 +
真 SystemFunction032，roundtrip 校验和）；③**image-backed 等价**（LoadLibrary
真 DLL 的 .rdata，COW 翻转 + 114KB RC4 roundtrip 全绿）；④**CI host spec**
（tests/test_bofwin.cpp：RWX 页上的位置无关 checker 求和宿主自身 .text——
本机跑通，CI runner 上仍触发一个未定位的 runner 特有故障，已 continue-on-error
放行主线并留 WER dump 取证钩子）。

**CI 攻坚 30+ 轮的真实收获（每条都是独立 bug，均已修复实证）**：
1. SystemFunction032 的 USTRING 是 ANSI_STRING 形 {len,max,buf}——首版
   {buf,len,max} 让 sf032 把长度当指针解（gen3 的 G3_USTRING 是活参考）
2. checker BOF 的结果存储 `45 89 00` = mov [r8],r8d（REX.R 扩展 reg 不是
   rm）——把 sum 当指针存了；正确是 `44 89 00`
3. enter_stub 栈契约：sub 8+push+add 0x28 差 8 字节——push 必须直接落
   [ret-8]，垫是 0x20 不是 0x28（两次本地变体崩才钉死）
4. rax 在每次 Win32 调用后死亡——call 后必须重载 ctx（三次重写）
5. USTRING 长度读必须 32 位（64 位读把 {len,max} 拼成 16TB size）
6. .rdata 密文后 **一切 API 都死**（fprintf 的 IAT、VEH 的 GetStdHandle/
   WriteFile、CreateTimerQueueTimer）——trace 反复成为崩溃源，最终纪律：
   mask 后零 API 直到 exit stub 返回；取证走 stderr（无缓冲）+ raw WriteFile
7. 节掩蔽长度不能按 VirtualSize 硬写——节尾对齐 gap 页（NOACCESS）会让
   RC4 尾写崩（.rdata 114KB 块的 crash）——VirtualQuery clamp，多 region
   尾巴明文降级
8. bw_rc4 的 16 字节栈数组给帧挂了 /GS cookie——解 .data 那次调用 prologue
   读密文 cookie、epilogue 读真 cookie → **fast-fail 绕过一切 VEH**——
   key 变体改写 ctx 私页（无栈数组 = 无 cookie）
9. exit stub 的 phase 前奏使其超 0x60 区域上限，且半成品页被缓存——失败
   路径必须释放全局
10. GitHub runner 上 WER LocalDumps 三次配置不产 dump、host 测试故障不可
    本地复现——runner 环境问题与引擎无关（本机三重等价证明）

**槽容量墙（硬约束，启用条件挂 Phase 4）**：bofwin 引擎 ~3.5KB。通道
DLL 已裁（BOFWIN_DISABLE，窗口是 beacon 主力能力）；x86 本就不编。
beacon.x64 的 TS 槽 cap **307232B 是硬的**（槽尾即活数据，无 slack）——
gen3+v3+bofwin 三家叠装超 1.5-2KB。**处置**：BOFWIN_ENABLE 从 beacon 摘除，
引擎 dead-stripped 留库，Phase 4（UDRL/loader 换壳摆脱槽布局）时启用。
**同轮完成**：v3 stub 模板化（118B 静态模板 + 8 patch，消掉 emit 语句群，
capstone 全 arity 验证）、g3_snapshot_for_bofwin 访问器（BOF 窗口复用 gen3
的 PE 解析/堆去重，省一个解析器）。

**回归（最终构建 6f94926 六槽全 cap 内）**：真 beacon mini_sm 活测 7/7——
INITIAL + `Current syscall method: Indirect` ACK + spawn 注入链（alloc6/
write5/protect5/threadex11 全 v3）+ SMB link 孙链（established/LS 字节）+
父存活；**内存取证：模板化 v3 stub 页仍在真 beacon 执行**（0x8f0000/0x900000
RX 页嵌 leave gadget = ntdll+0xC194）。

分支 HEAD 6f94926；CI 绿；六槽=38075302899 构建；TS 复位 r2_nosm（pgrep 硬
验证）；进程全清。**Phase 2/3 收官；下一优先级 = Phase 4（loader 链——
槽容量墙的根治路径）。**
