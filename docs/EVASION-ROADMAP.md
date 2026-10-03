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
