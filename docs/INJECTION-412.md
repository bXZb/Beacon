# 4.12 注入三式契约（2026-11-09 提取，官方 4.12 "Fix Up, Look Sharp!" 对齐线）

来源：Cobalt Strike 4.12 blog + SafeBreach《Process Injection Using Windows
Thread Pools》(2024-11) + Outflank《Introducing Early Cascade Injection》
(2024-10)。实现状态：**脚手架已落**（inject.h 0xB/0xC/0xD 槽位 + inject.cpp
分发 + TS ProcessInject.java 操作码 11/12/13 + Loader profile 语句），本体=
研究级后续（三式的结构布局/签名扫描均无公开源码）。

## TpDirect (0xB) — SafeBreach 线程池 Variant 7

机制：伪造 TP_DIRECT 结构（Callback 字段=payload 地址），用
`NtSetIoCompletion` 把该结构作为 completion key 直接排进目标进程线程池的
IO 完成端口 → 工作线程以"完全合法的完成动作"执行 payload。

依赖（实现前置）：
- 目标 TP_POOL → IOCP 句柄泄漏：`NtQueryInformationWorkerFactory`(basic info)
  返回 StartParameter 中携带 TP_POOL 指针；IOCP 句柄经 `DuplicateHandle` 取得
- 未文档化 TP_DIRECT 偏移（Callback 相对偏移）
- 触发后无任何线程创建原语 —— 这是它对 EDR 的核心价值

## TpStartRoutineStub (0xC) — SafeBreach 线程池工作线程起始桩

机制：操纵目标线程池触发远线程创建，新线程起始地址解析为合法 ntdll
线程池入口（Tpp* 族），经精心构造的工作结构分发到 payload。

变体族（SafeBreach 帖 8 变体，本式对应工作项插入族）：
- TP_WORK：TpPostTask 把伪 TP_TASK 排进 TP_POOL 任务队列（双链表直改）
- TP_IO/TP_WAIT/TP_ALPC/TP_JOB：把底层对象关联到目标 IOCP，completion key
  =恶意工作项；合法动作（写文件/SetEvent/ALPC 连接/作业赋值）触发
- TP_TIMER：SetThreadpoolTimer → TppEnqueueTimer 把 TP_TIMER 的
  WindowStartLinks/WindowEndLinks 链表项插入定时器队列，到期触发

报告对面：CrowdStrike/SentinelOne/MDE/Cortex/Cybereason 全过。

## EarlyCascade (0xD) — Outflank 进程初始化级联（fork&run 专用）

七个步骤（精确顺序）：
1. `CREATE_SUSPENDED` 起子进程（LdrInitializeThunk 前冻结）
2. 写入两段 payload：stub + 主 payload
3. 定位 ntdll `.mrdata` 的 `g_pfnSE_DllLoaded`（Shim Engine 回调指针，悬停态
   可写，进入用户态初始化第 2 步后变只读）与 `.data` 的 `g_ShimsEnabled`；
   回调指针←stub 地址，`g_ShimsEnabled`=1
4. Resume：kernelbase.dll 初始化期间 `LdrpSendSnapNotifications` 触发回调
   （关键：在 Loader Lock 之外，只持 LdrpDllNotificationLock）
5. stub 立即 `g_ShimsEnabled`=0（防未初始化的兄弟 Shim 指针炸）
6. stub 对本进程初始线程 `NtQueueApcThread`（进程内排队，Loader Lock 下合法）
   指向主 payload
7. LdrInitializeThunk 尾部 `NtTestAlert` 排空 APC → 全部 DLL 就绪后执行
   payload → NtContinue 交棒入口点

约束：仅 CREATE_SUSPENDED（.mrdata 窗口）；stub 只能用 ntdll NTAPI（不能
加载 DLL/建线程）；`g_pfnSE_DllLoaded` 无符号，随 Windows 版本漂移 → 需
对本地 ntdll `LdrpSendPostSnapNotifications` 反汇编推导签名扫描。

## 相对 Early Bird APC / EDR-Preloading 的差异

- 无跨进程 QueueUserAPC（唯远操作=分配/保护/写）
- 触发早于 EDR-Preloading（AvrfpAPILookupCallbackRoutine），且无需改内存
  保护关断（开关布尔在恒可写 .data）

## 实现路线（下一步）

1. EarlyCascade 先行（机制最确定）：本地 ntdll 反汇编推导两全局的签名扫描
   → position-independent stub（模板：DV/ObfSetThreadContext 的手写桩经验）
   → fork&run 分支挂接（isSuspended 已在 dispatch 层强制）
2. TpStartRoutineStub 次之（TP_TIMER 变体最自包含：SetThreadpoolTimer+
   链表插入，攻击者退出后仍可触发）
3. TpDirect 最后（依赖 IOCP 句柄泄漏链最长）
