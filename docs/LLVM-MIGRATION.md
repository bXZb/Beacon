# Beacon LLVM 工具链迁移规划（`llvm` 分支）

创建：2026-10-25，基线 = `feat/post-4.9.1` `dbd1442`（本分支首提交）。
上游动向：官方 4.13 引入 LLVM Beacon（custom C runtime + 显著更小体积），并预告下版弃用
MSVC；其深层动机是 LLVM pass 基础设施可对**整个 payload** 做逐构建变换（Mutator Kit 已先在
sleepmask 对象文件上实证）。

**我们的定位与官方不同**：cs-gradle 线（`192.168.10.254:3000/admin/cobaltstrike`）已把
TS/client 源码化，sleeve 是 `src/main/resources/sleeve/` 普通文件，247808/271852/309248
三个套筒上限**已失效**——官方 LLVM Beacon 的体积卖点对本仓库无意义。本线的目的是：

1. **全量 pass 变形**：每次构建产物形状唯一（对抗静态签名/YARA）；
2. **工具链自主**：消灭 v142/v143 ICE 类漂移（winnt.h C1017 / winreg.h C1001 / CL 0xC0000409），
   CI 不再绑 MSBuild 生态，ARM64 从死配置变期权；
3. **架构终点**（远期，与 cs-gradle 协同）：TS 侧逐任务重编 beacon——payload 不再是冻结
   DLL 而是按 profile/种子现编的产物（官方 4.13 Payload Store + LLVM 组合的方向，我们的版本可以更彻底）。

非目标：体积优化（槽即文件，无意义）；跨平台（Beacon 本体 Win32 全耦合——通道/注入/
syscall/sleepmask/PE 反射加载，LLVM 只带来跨架构期权，不带来 Linux/macOS）。

---

## 1. 现状耦合面盘点（`dbd1442` 实测）

MSVC 特有用法总量很小，clang-cl 全部有对应支持：

| 用法 | 位置 | clang-cl 兼容性 |
|---|---|---|
| SEH `__try` | `src/crashdiag.cpp`、`src/interpreter/binterp.cpp` | x64 SEH 完整支持，Phase 1 验证点 |
| 内联汇编 `__asm { ret }` | `src/thread.cpp:40`（sizer，非 x64 分支） | x86/x64 均支持 |
| `#pragma comment(linker, "/EXPORT:...")` | `src/ReflectiveLoader.cpp:8`（`_ReflectiveLoader@4` stdcall 修饰名） | 支持，修饰名规则一致 |
| `#pragma code_seg(".text$aaa")` | `udrl/ReflectiveLoader.c:298` | 支持（$aaa 节排序语义一致，仍需实证 COFF 节序） |
| `_MSC_VER` / `__forceinline` | 4 处 / 12 处 | 直接兼容 |
| MASM / ATL / Pre-PostBuild | 无（事件全空或纯 copy） | 不存在该耦合 |
| tomcrypt/tommath 预编译 lib | MSVC COFF 静态库 | lld-link 消费同一对象格式，直接链接 |

Release 形态：x64 `/O1 /GS- /MT /Zc:* /Gy /Gw /GR-`、C++17、MinSpace、LTCG 关。
**clang-cl 原生吃 cl 风格参数**，上述 flags 无需翻译；仅 `/GL`→`-flto`（本线 Phase B 才用到）。

已完成的 CRT 减负（Phase D 的地基）：`miniprintf.cpp`（甩 printf 链）、`der_stub/ecc_stub`
（LTC 桩化）、`bw_heap.cpp`。定制 CRT 对我们只剩工程纯净度收益，降为可选。

**关键事实（2026-10-25 复核）**：全树 **0 个 C++ STL 头、0 处 `new`/`delete`、零
`namespace std`**（include 面只有 C 运行时头 + Windows SDK 头，不链 msvcprt）。MSVC 目标
交叉编译最重的 STL 依赖在本仓库不存在——**Linux 主机构建因此成立**，见 §3 Phase A。

## 2. 约束现状（哪些"铁律"已经消失、哪些还在）

| 约束 | 状态 | 说明 |
|---|---|---|
| 套筒容量上限 ×3 | **消失**（cs-gradle 线） | sleeve 文件化，上限即文件大小 |
| GraalVM 打槽 / CrackSleeve / svm_heap 解码缓存 | **消失** | TS 是普通 JVM fat jar |
| 5K INT3 墙（pe.process memcpy 5120B） | 名义还在 | 代码在自家 cs-gradle 源里可改；为保持官方工件形状兼容，默认 DLL 保留墙，rl0k（SIZE=0）路径本就无上限 |
| UDRL COFF 抽取契约（OBJParser.hasSection(".text")→首个可执行段裸字节） | 名义还在 | 同上可改；过渡期 UDRL `.o` 维持 cl 编译不动，见 §4 风险 1 |
| TS 下发表（sleepmask pair）按官方 PE 布局 | 在，但双端自控 | pair-5 打中 .pdata CRT unwind 条目的前科（SLEEP-MASK-FEEDBACK）；clang 的 .pdata/xdata 形状不同，Phase 2 必须重验 |

## 3. 技术选型（分相）

- **Phase A：clang-cl + lld-link，Linux 交叉编译为默认轨**。clang 天生是交叉编译器，
  lld-link 跨主机行为一致。Linux 主机路线：`clang-cl --target=x86_64-pc-windows-msvc`
  + **xwin**（从微软官方源拉取 Windows SDK / MSVC CRT 头与库，可钉住 10.0.19041.0，
  cargo-xwin 同源方案）+ lld-link。产物 ABI 与 MSVC 一致（静态 libcmt/vcruntime/libucrt），
  tomcrypt COFF lib 直接链；`/Brepro` 消时间戳后与 Windows 侧 clang-cl 构建**逐字节 diff**
  作为一致性门。Windows runner 侧车保留为对照轨。备选 llvm-mingw（x86_64-w64-windows-gnu，
  完全自足无微软依赖，但 CRT/ABI 偏离现构建大）列为后期工具链自主期权，不作首选。
  构建脚本纯 bash（`build-llvm.sh`，参数对齐 build.ps1），产物 `*.llvm.dll` 与 MSVC 并存；
  vcxproj 的 `PlatformToolset=LLVM` 路线不采用（把主线耦合进实验）。
  **战略意义**：TS 本就跑 Linux（192.168.100.98）——Linux 交叉编译使 Phase 5 的
  TS 侧逐任务重编管道可原生跑在 TS 同机/同容器，无需 Windows 构建机。
- **Phase B：变形 pass 管线（本线核心）**。两条注入路径，先 1 后 2：
  1. 每 TU in-process：`clang-cl -fpass-plugin=pass.dll`（new-PM 注册），简单、无链接改动；
  2. 全程序：`-flto` 产 bitcode → `lld-link` LTO 挂 plugin（跨 TU 变形、跨界内联后再变形，效果上限更高）。
  pass 来源：自研起步（mba 混淆 / 常量异或 / 子代换 / 控制/数据流扰动，每个 ~百行量级），
  需要更重能力时评估改编 new-PM 化的 O-LLVM 系 fork（Arkari/Pluto 一类），**只借码不借约**
  （沿用 2026-09-13/19 既定原则）。逐构建种子进 pass（`BW_LLVM_SEED`），产物形状按构建唯一。
- **Phase C（架构，跨仓库）**：cs-gradle 侧加重编管道——TS 收到生成请求时按种子触发 beacon
  构建（本仓库 CI/构建服务）+ sleeve 落盘 + 下发。规格另立文档，与本线 Phase 2 的 sleeve
  文件替换流程共用。
- **Phase D（可选）**：定制 CRT 收尾，对齐官方 "custom C runtime" 形态。

## 4. 风险清单（按杀伤力排序）

1. **烘焙 UDRL blob**（`src/ReflectiveLoader.5k/.50k`、`ReflectiveLoader.1000k`）：冻结资产
   不受编译器切换影响，**继续原样使用**；UDRL `.o` 的编译器在 Phase 2 前不动（cl），其
   COFF 抽取契约（无外部符号、.text 首节即入口）最脆，单独设严验关卡后才允许换 clang。
2. **PE 形状 × sleepmask**：clang 的 .pdata unwind 布局与 MSVC 不同（SEH/栈展开条目数量与
   位置都会变），自建 PE 掩码表要重新派生，TS 下发表（自家源码）同步适配；沿用 tier-104
   教训：等价性验证从程序化解析 + 活测兜底。
3. **`_re/` 脚本与 dump-RVA 取证**：MAP 全量重排，历史 offset 全部作废（预期内，无需迁移，
   但排查新旧混跑时要意识到产物来自哪个工具链——artifact 命名必须带 `.llvm` 区分）。
4. **体积归因基线重跑**：`GenerateMapFile` 语义 lld-link 对应 `-print-map` 或 `/MAP`，符号
   归因脚本若按节/名匹配需重跑基线。
5. **SEH 语义**：crashdiag/binterp 两处 `__try` 在 clang-cl 下的行为（展开表、过滤器执行
   顺序）进 Phase 1 冒烟清单。
6. **x86 stdcall 名字修饰**：`_ReflectiveLoader@4` 等导出名必须逐字节一致（客户端按名取
   导出），Phase 1 用 dumpbin/llvm-readobj 双端对照导出表。

## 5. Phase 计划与验收门

| Phase | 内容 | 验收门 |
|---|---|---|
| 0 | CI 双轨编译：**Linux 为主**（ubuntu + 钉版本 LLVM + xwin，容器化可复现）+ windows-2022 侧车对照；`build-llvm` × 4 变体 + winhttp + rl0k + x86 | 编译过/不过清单 + 体积对照表 + 双端 `/Brepro` 字节 diff（差异须逐项归因） |
| 1 | 形状验证：`load_smoke`（blob 补丁→LoadLibrary→导出验证）×4 变体；导出表/MAP/.pdata 对照；tomcrypt 链接确认 | load_smoke 全绿 + 导出名逐字节一致 |
| 2 | 活体 A/B：cs-gradle sleeve 文件替换（非打槽）→ 六通道矩阵 + `evasion-lab` 扫描矩阵（PE-sieve/Moneta）与 MSVC 基线对照；UDRL 链（MSVC 烘焙 blob + clang beacon）混编验证；sleepmask 掩码表重派生 | MATRIX 全绿 + 扫描无回归 + 掩码窗口取证（等价性 diffs=0） |
| 3 | pass 管线 MVP：1-2 个自研 pass + 种子；对自家已知签名做 YARA 自查；变形产物过 Phase 2 同套矩阵 | 逐构建形状唯一（哈希散列）+ 矩阵全绿 |
| 4 | 主线切换决策点：clang-cl 默认或双轨并存 | 按 EVASION-ROADMAP Phase 0 矩阵双绿标准合入 `feat/post-4.9.1` |
| 5 | TS 侧重编架构（跨仓库，与 cs-gradle 协同）——Linux 交叉编译使重编管道可原生跑在 TS 同机，无需 Windows 构建机（本线最强的架构理由） | 另立规格文档 |

## 6. 与其他线的关系

- `evasion-research`（Gen3 睡眠链/调用栈）：pass 变形与其**正交可叠加**；掩码表与堆形状的
  交互在 Phase 2 一并回归，不单独开口。
- cs-gradle `main`（4.11–4.13 parity）：官方 LLVM Beacon 的行为对照参考；其 BOF-PE /
  Payload Store 还原件是 Phase 5 架构的内部参照。
- `linux-4.5`：无关（Linux beacon 是另一条产品线）。

## 7. 立即行动项（Phase 0 细目）

1. `build-llvm.sh`：参数对齐 `build.ps1`（-Project/-HttpLibrary/-Platform），Linux 主机定位
   clang-cl/lld-link（钉版本），`xwin` 预取 SDK/CRT 到仓库外缓存（钉 10.0.19041.0），
   flags 逐项照抄（`/nologo /W3 /O1 /GS- /MT /Zc:* /Gy /Gw /GR- /std:c++17`——按 vcxproj
   Release|x64 实值核对），链接加 `/Brepro`，产物 `<name>.<plat>.llvm.dll` + `.llvm.map`
   （lld-link `/MAP:`）。
2. CI 双轨 job：`llvm-x64-linux`（ubuntu，主）+ `llvm-x64-win`（windows-2022，对照）；
   matrix × 4 变体 + winhttp + rl0k + x86；上传 `.llvm.*` 独立 artifact；记录 clang/xwin
   版本到 step summary；双端产物 sha256 对照表进本文件附录。
3. 体积对照表进本文件附录（Phase 0 产出回填）。

---

## 附录 A：Phase 0/1 结果（2026-10-25，HEAD `5759ff6` 线，CI run 全绿）

**结论：clang-cl 19.1.7 + lld-link + xwin 0.10.0 全树编译链接成功；双主机
（ubuntu-22.04 交叉 vs windows-2022 本机）产物 /Brepro 字节级一致；Windows
对照轨 load_smoke 对三个 LLVM DLL 全过；MSVC vs LLVM 导出表一致。**

### 产物与体积（x64，同提交对照）

| 变体 | LLVM (bytes) | MSVC (bytes) | Δ |
|---|---|---|---|
| beacon (wininet) | 489472 | 561152 | **-12.8%** |
| winhttpb | 489472 | — | |
| beacon rl0k (BOFWIN) | 494080 | — | |
| dnsb | 301568 | — | |
| extc2 | 292864 | — | |
| pivot | 293888 | — | |

意外收获：未做任何定制 CRT，clang 产物已比 MSVC 小 12.8%（/O1 下 clang 的
code sel + 更紧的 CRT 拉入）。体积对我们不是目标，但白赚。

### 双主机确定性

三个共同变体 sha256 **完全一致**（fd565ae8…、a52d3b69…、36c30fc4…）——
同一 LLVM release + 同一 xwin SDK/CRT + `/Brepro` 下，Linux 交叉产物与
Windows 本机产物逐比特相同。这是后续一切"TS 同机重编"信任链的基石。

### 已验收门

- [x] Phase 0：CI 双轨全变体编译链接（llvm-build.yml，llvm 分支每次 push）
- [x] Phase 1：load_smoke ×3 LLVM DLL 全过（blob 补丁→LoadLibrary→CRT 初始化
      →DllMain→settings 解析→ReflectiveLoader 导出→干净卸载）
- [x] Phase 1：导出表对照（compare_exports.py，MSVC vs LLVM 名单一致）
- [x] Phase 0：双主机字节 diff（byte-diff job，实验性转常规）
- [ ] Phase 2：活体 A/B（需实验室基础设施：cs-gradle sleeve 替换 + 六通道矩阵
      + PE-sieve/Moneta）——本线下一站
- [ ] x86：build.py 已支持（Win32 平台名映射 + bw_heap 排除解析验证过），
      待 x86 tomcrypt lib 供给（thirdparty/build_trimmed.ps1 产物）后开轨

### 源码适配清单（全部对 MSVC 无害、已验证 MSVC CI 同绿）

1. `#include` 大小写规范化：`Tlhelp32.h`×7 文件、`Windows.h`/`WinSock2.h`/
   `Winsock2.h` 全量 → 小写规范名（NTFS 大小写不敏感掩盖了 14 年，Linux 一击即中）
2. `strategy.cpp` 三处 `cond ? tokens[x] : ""` 的 const char* 收敛 → 显式
   `(char *)""`（MSVC 宽容扩展，clang 报错）
3. `ReflectiveLoader.h`：`__nop() → __asm nop`（clang 无 `__nop` 内建，5K 墙的
   全部 nop 调用会变成未解析外部符号）；`register` 存储类移除（C++17 已删）

### 基础设施要点（踩坑记录）

- xwin 0.10：`--arch x86_64`（非 x64）且为**全局选项**须置于 `splat` 前；
  splat 架构目录名也是 `x86_64`（build.py 探测两种拼写）
- Windows 主机：xwin `--cache-dir` 必须与 splat 输出**同盘**（跨盘 vsix→splat
  rename 报 os error 17）；runner 预装 LLVM 是失控版本，钉版安装走 NSIS
  `/D=` 进缓存目录
- workflow YAML：`run: |` 字面块内的多行 `python3 -c "..."` 续行若在第 0 列
  会终止字面块、裸露内容变成顶层键——多行脚本一律独立文件（tools/llvm/*）
- CI 缓存：`~/.llvm-cross`（LLVM+xwin splat，约 5GB），job 失败不回存
  （actions/cache post-if: success()），首轮失败会反复重下

---

维护约定：本分支只做工具链迁移与 pass 管线；beacon 功能改动仍在 `feat/post-4.9.1`，
本分支定期 rebase 其上（像 evasion-research 对 4.9.1 的关系）。Phase 4 通过后本分支
使命终结，内容并回主线。


---

## 附录 B：Phase 2 活体 A/B 战报（2026-10-25/26 夜）

### 已达成
- **MSVC 基线全链**：SleeveEncode(+32B 回环) → cs-gradle 容器化 TS/harness/REST
  → 监听器 :80 → 裸配置 DLL（payload_dump）→ 自家 UDRL loader 拼接导出墙
  → ownexe 模板 → **上线/心跳/任务取回/执行副作用（P2-EXECUTED）全部验证**。
- **取证管线**：WER LocalDumps + PUT 上传通道 + minidump 解析（异常/CONTEXT/
  MemoryInfoList/ThreadList）+ lld MAP 符号化——40 分钟内定位任意后续崩溃。
- **LLVM 版生命周期已走到最后一层**：CRT→DllMain(0x0d/1/4)→beacon()→主循环
  80+ 周期（60s/周期节律健康）——只在 http_get 路径上沉默。

### LLVM 侧真 bug（已修，入库 llvm 分支）
1. **lld 隐式入口解析错位**：AddressOfEntryPoint 落在函数中段（.pdata 裁决：
   EP 0x31ee4 ∈ [0x31ec8,0x31eec) 指令内部）→ loader 调 EP 即跳进乱码。
   修复 = `/ENTRY:_DllMainCRTStartup`（build.py，字节级验证过 EP 序言）。
2. **诊断标记自身的 _snprintf 在 LLVM 下崩**（__stdio_common_vsprintf_s 序言
   `mov r9,[rsp+30h]`，进入时栈已坏）→ 标记改无 CRT 手搓后前导链全部点亮。
   ※ 此崩溃的底层机制未定（进入帧即坏栈）——是"根因#3"的同族证据。

### LLVM 侧未决（下一会话接力点）
- **症状**：beacon() 循环健康，但每周期死在 http_init 内部（pre_http 后的
  post_IeOpen 标记从不出现；MSVC 同配置全绿）。历史 dump（EP 修复前）的
  崩溃点呈现"跨函数 call 的目标页不可达 + 寄存器 UTF-16 文本污染"模式。
- **节表差异**（LLVM= .gfids/.retplne/_RDATA，无 .fptable；MSVC= .fptable）。
  _RDATA 是 lld 的 read-only-after-load 特有节——与"call 目标页不可达"模式
  高度相关：**loader 的节保护循环按 MSVC 特征位映射，_RDATA 若被标 RX 而其
  内容实为 lld 特殊数据（retplne=indirect-call thunk）可能就是死点**。下一轮
  第一件事：dump f7 的死亡现场 RIP → 若落在 _RDATA/.retplne 范围即定案。
- rig 侧坑位记录：WinRM 会话关闭杀子进程树（用 wmic）；Defender 会复活
  （Tamper Protection 自动回开，每次重部署前查 (Get-MpPreference)）。

### 基础设施（可复用）
- `cs-gradle/tsboot_run/`：boot_local.sh（容器三件套）、sleeve_swap.sh、
  first_checkin.sh、winrm_cmd.py（自研 SOAP 客户端）、SleeveEncode.java、
  uploads/ 通道（PUT 8124）、8123 取件服务。
- beacon 分支 llvm 的 diag 体系：bw_diag（beacon 循环）、bw_diag2（DllMain
  前导链）、bw_diag_ch（wininet）、BW_DIAG_RETADDR（RNG 调用者）、
  BW_DIAG_RWX（loader 节保护实验开关）、BW_NO_EXC_REG（exreg 杀开关）。
  **根因定案后统一回滚**。


---

## 附录 C：重启后续战 + 根因收敛（2026-10-26 下午）

### 新证据（cdb 10.0 first/second-chance + WER dump 双源）
1. 异常类型其实是 Illegal instruction (c000001d)，不是 AV——之前所有 dump 的
   c0000005 是 crashdiag VEH（用 CRT fprintf，LLVM 下自爆）抢先污染后的二次崩溃。
   BW_PLAIN_SLEEP 下 disarm 后真身现形。
2. 真死点 = spwizimg+0x1cfdc 附近，同一地址每轮一致；栈上调用链 =
   VirtualQuery -> spwizimg+0x314e5 -> +0x316d5 -> +0x1bc83 -> 死点。
   spwizimg 是纯资源 DLL（EP=0，.rdata+.rsrc，无代码节！）——所以
   0x1cfdc 处的"代码"全部是被 stomp 进去的 beacon .text。
3. 内存 vs 文件字节矛盾：文件里该处是合法 call 链，运行时取指为 0xff——
   stomp 覆盖发生过（304 周期在跑）但某个时刻内存被改写/还原。
   嫌疑集中：loader 的 pFL 失败清理路径 FreeLibrary、或系统级 unmap
   （dbg11 抓到过 ZwUnmapViewOfSection + Unload module spwizimg）。
4. 寄存器签名跨所有崩溃一致（Rax=0x1f800010001f、Rcx=UTF-16 "3++S"）：
   = Unicode 比较例程特征，to_wide/资源名字符串处理路径。

### 待下轮一击
- cdb bu 在 spwizimg load 时对页提交前 998 失败 -> 需 sxe ld 精确时机或
  sxe ld 后立即 ba w1（等 beacon stomp 后的第一次写改）。
- 或者最暴力直接：用 cdb !vprot 对比崩溃前后该页属性变化即可判定 unmap
  还是 reprotect。

### 基建状态（重启后）
- 宿主新 IP 192.168.20.169（rig/监听器/取件服务全部已切）。
- Windows 189 无恙；Defender 服务重启后整 STOPPED（比排除更彻底）。
- cdb 10.0（用户安装的 WinDbg Preview）在
  C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps\Microsoft.WinDbg_8wekyb3d8bbwe\cdbX64.exe。
- payloads/g3x.exe 已重拼（llvmK plainsleep + llvmK .o loader + host template）。


---

## 附录 D：真死点终局定性（2026-10-26 晚，收口）

### 决定性事实链（全部有 dump/cdb/字节级证据）
1. 死点 RVA 在 LLVM 各构建间漂移（0x1cc6d/0x1d8a5/0x1cfdc…），但**内存中执行的
   字节恒为同一形态**（movzx eax,[rbp+0xC8] / ff ????），而**文件字节恒为合法
   call 链**（各构建的 crypto_rng_get_bytes 序言）→ **执行页内容 ≠ 交付 DLL 内容**，
   与具体 build 无关。
2. 牺牲模块 spwizimg 是**纯资源 DLL**（EP=0、仅 .rdata+.rsrc、无代码节）——
   该地址的所有"代码"都是 loader stomp 写入的 beacon .text。
3. 因此唯一自洽解释：**stomp 写入发生过（否则到不了 beacon 循环），之后该页内容
   被还原/解映射**——dbg11 实录 ZwUnmapViewOfSection + "Unload module spwizimg"。
   寄存器签名（Rax=0x1f800010001f、Rcx=UTF-16 "3++S"）跨所有崩溃一致，指向
   spwizimg 原始资源数据页被执行/比较。
4. MSVC 构建同机制 300+ 周期稳定 → 差异不在 stomp 逻辑本身，而在 **LLVM 构建
   触发了某个 MSVC 构建不触发的 unmap 路径**（候选：http 失败降级路径里的
   FreeLibrary；loader pFL 残留引用；或 spwizimg 引用计数归零的系统卸载）。

### 下轮第一枪（管线全部就绪）
- **延迟附加 watchpoint**：等 beacon 进 cycle 100 后再 `cdb -p <pid>` 附加，
  `ba w4 spwizimg+0x1cfd8`（8B 对齐）→ 抓"还原者"的精确 RIP 与调用栈。
- 或 `!vprot` 快照周期前后页状态（commit/RW → free = unmap 实锤）。
- 定位 unmap 来源后的修复方向：禁用该路径（编译开关）或换牺牲策略。

### 今晚已入库的确定性成果
- lld EP 错位修复（/ENTRY，字节级验证）+ miniprintf/_snprintf 家族在 LLVM+
  反射组合下的踩栈证据 + CRT-free 诊断技术 + cdb 10.0 自动化取证管线
  （WinRM 驱动、PUT 日志回收、ba 数据断点、sxe first/second-chance）。
- 附录 A/B/C/D 完整战报。所有诊断开关（diag/diag2/diag7~14）待根因修复后统一回滚。


---

## 附录 E：定向重写落地 + 残余 bug 精确刻画（2026-10-27 收口）

### 定向重写已实现并编译（llvm 分支 HEAD）
1. **loader 私有映射**（BW_LOADER_PRIVATE，udrl job 现已定义该宏）：
   VirtualAlloc RWX 目标取代模块 stomp——候选枚举/页翻转/失败 FreeLibrary 全删。
   stomp 架构的"寄生于系统映射"随机性（附录 C/D 的 unmap 根因）从结构上消除。
2. **构建期自描述**（build.py --layout 两遍）：链接后解析最终镜像 → gen/layout.h
   （固定尺寸区域表+校验回路）→ 重编消费者 → 重链 → 终验。gargle_own_sections
   消费该表，删除运行时 PE 解析+节名猜测。
3. **exreg 跳过**（BW_LLVM_LAYOUT）：clang .pdata 不再注册进 ntdll 动态函数表。
4. **crashdiag 永久关闭**（同宏）：CRT-fprintf VEH 自爆源消除。
5. **_vscprintf NULL-buffer 守卫**：core() 支持 buf=NULL 纯计数（UCRT inline
   _vscprintf 以 (NULL,0) 调用我们的 __stdio_common_vsprintf）。

### 实测里程碑（192.168.20.189 活体，全部有 cdb/dump 证据）
- LLVM 构建（私有映射）**完整走通加载链**：hostexe 全阶段 → loader → CRT init →
  DllMain(0x0d/1/4) → beacon() → gates → 主循环。
- 首个 HTTP checkin 往返成功（process_message 收到 TS 响应并派发任务）。
- 排查中额外修复：DONT_RESOLVE 卸载风险、loader 自包含契约破坏（diag15 的
  CreateFileA 直调产生未解析 __imp——拼接不处理重定位）、_snprintf 手工拷贝、
  workflow 的 map 上传缺失、plainsleep 变体缺 --layout、vcxproj 宏映射缺失
  （BW_LLVM_LAYOUT/BW_LOADER_PRIVATE 曾从未编译——本轮多个"无效修复"的真因）。

### 残余 bug（精确刻画）
**症状**：beacon() 内 enter/gates 过后、首个 pre_http 前死；`call [reg+10h]` 落空
（RIP=0）；死点稳定复现。窗口 = agent_init（crypto_rng/security_init/metadata
builder）或 hostcfg_init/strategy_setup。栈上 VirtualProtect+GetCurrentProcess
残留 = syscalls stub 机器（make_exec）；"pre_beacon" 字符串残留 = bw_diag2。
**下一步（单轮可完成）**：cdb `bp` 在 agent_init 入口（私有基址+RVA 查 map）单步
到 null call，读 [reg+0x10] 所属结构 → 修复该结构的初始化/重定位。

### 基建资产（全可复用）
- 192.168.20.189 活体：cdb 10.0、WER dump 管线、8123/8124 服务、WinRM 通道、
  rig 三件套（TS+REST+harness，syscall_method=0 profile）。
- 宿主：build.py 两遍构建、拼接管线、符号化脚本（pdata 函数边界 + lld map）。


---

## 附录 F：残余 bug 精确刻画 + 下一步（2026-10-27）

### 当前状态（HEAD ea88ed3+ 私有映射重写版）
- LLVM beacon（plainsleep 变体）完整加载链全过：hostexe → loader(私有映射) →
  CRT → DllMain(0x0d/1/4) → beacon() → gates。
- 5K 墙问题已修复：clang 把 .5k include 墙折叠到 1280B（不可达代码消除），
  volatile nop 墙 (wall_llvm.h 3200B) 落地于导出函数开头（可达必发射）。
  此前"拼接覆盖真实函数"的判定即由此而来——墙只有 1280B 时 2897B 拼接体
  越界 1.6KB 覆盖 crypto_rng/security 等真实函数。

### 残余 bug（每次进程死于主循环初期，符号随构建漂移）
- c3new dump: AV at walk_parent+0xaa (recurse.cpp), call [rax+0x10]。
- f4x dump: c0000409 fastfail, FAST_FAIL_FATAL_APP_EXIT(7)。
- 寄存器签名跨构建一致: Rax=0x1f800010001f, Rcx=UTF-16 "3++S"。
- 判定: 不是单一函数 bug——是【某个共用结构的字段偏移在 clang 下不同】或
  【某全局初始化依赖 MSVC 零初始化顺序】。候选: bformat/formatp、track_memory
  的全局链表、settings 数组指针。
- 下一步（单步方案，避免再跑 CI 轮）: 用已装 WinDbg Preview 的 TTT
  (Time Travel Debugging): `windbgx -ttt C:\lab\c3.exe` 录制全进程,
  从 AV 逆行到第一个被污染写入。或 cdb `bp` 在 agent_init/strategy_setup
  入口 + `pt` (step to return) 逐函数过。

### 已修复并入库的根因（全部有证据）
1. lld EP 错位 → /ENTRY (字节级验证)
2. crashdiag VEH 自爆 → disarm
3. miniprintf _snprintf 家族踩栈 → 无 CRT 标记
4. stomp unmap → 私有映射
5. 墙折叠 → volatile nop 墙 (3200B 实测)
6. 宏映射缺失 → vcxproj 补全 (重写代码曾从未编译)

---

## 附录 G：拼接槽契约 + 交付管线的三处根因（2026-10-27 深夜，HEAD 7392ea3）

### 根因 1：TS 拼接槽 = 从导出起点的固定 5120B 写入
- udrl loader .o 实际 **4129B**：`.text$mn` 0x4D0 + `/566` 0xB51（长名走 string table）
  两个 COMDAT 块。任何只取"单个 EXEC 节"的自制拼接（splice_final 系）只搬了 2897B
  ——**截断的 loader**。
- 4.9.1 TS（OBJExecutableSimple.getExeSect 聚合 .text$*）把完整 loader 写进导出槽，
  槽总写入 = **5120B 固定**（loader + 填充）。墙 3200B < 5120B → 槽尾部 **~1.9KB
  覆盖墙后真实函数**。实测受害者 `crashdiag_disarm`@RVA 0x1D2CA（被 loader 尾部
  代码顶替）→ DllMain(reason4) 调用落进 miniprintf `core()`、`mov [rsi+rbp],25h`
  双栈指针相加空指针 —— dbg46/47/50 全套现场由此而来。
- **修复**：wall_llvm.h 3200→**8192** nops（5120 槽 + 3KB 裕量）。clang 分支的
  导出函数体 = 墙 + return 0，墙必须独占覆盖整个槽。

### 根因 2：artifact64big.exe 模板槽 ~311KB，LLVM DLL 488KB 溢出
- artifact exe 的 payload 区在 .data raw 内（magic 起 16B 头 + XOR 载荷）。
  MSVC beacon 245KB 放得下；**LLVM 488KB 撕穿 .rdata/.pdata/.idata/.CRT/.tls
  的文件字节** → 头目录指向密文 → LdrInitializeThunk c000007B（能否活全凭密文运气，
  beacon_msvc.exe 今天同样死亡即证）。
- **交付定式**：`artifact_raw <listener> raw x64 <out.dll>` 拿 **TS 打补丁后的裸 DLL**
  （settings/sleepmask/loader 拼接全含），再 host_template 包裹（append 模板无槽限制）。

### 根因 3：sleeve 资源全体加密（含 loader .o）
- `BeaconLoader.VA.x64.o` 也走 SleeveEncode（明文放入 → `[Sleeve] Bad HMAC` →
  OBJParser 拿到解密垃圾 → `Invalid Machine header` → artifact_payload 返回 null）。
- profile 无 `.stage.allocator` → 默认 **VA** 变体 → 替换 `BeaconLoader.VA.x64.o`。

### 全管线定式（同批次产物铁律）
1. CI（llvm-build + build 的 udrl job）同 SHA 产物：`beacon.plainsleep.llvm.dll`
   (+map) + `ReflectiveLoader.x64.o` + `host_template_x64.exe`。
2. `SleeveEncode` DLL→`sleeve/beacon.x64.dll`、.o→`sleeve/BeaconLoader.VA.x64.o`，
   gradlew shadowJar，rig 重启 ~110s。
3. inbox: `listener_create franken-http 80` → `artifact_raw franken-http raw x64 …dll`。
4. 本地 host_template + patched_dll + 随机尾 → 落 VM `C:\lab`，wmic 脱离启动。
5. 判收：r1.log CHECKIN → 任务往返 → 执行副作用（对齐 MSVC 基线）。

### 排查基建增量
- VM 侧 PUT 回传用 `C:\Windows\System32\curl.exe`（WebClient.UploadFile 走代理失败）。
- cdb 寄存器相对转储（`db @r12 L2`）免 ASLR；r12=host flat 缓冲（identity 布局），
  **sc_base = r12+0x80000**（下一个 64K 分配）——现场测量务必先定基再算 RVA。
- 布局双关陷阱：flat 文件偏移 ↔ RVA 差 0xC00（.text），两次"映射内容不匹配"的
  误判皆源于此。

---

## 附录 H：全功能闭环达成 + A/B 双绿 + 插桩回滚（2026-10-27/28，HEAD a2402a0）

### 结论
**LLVM 线全功能测试闭环达成，与 MSVC 基线完全对齐。** 三项验收（CHECKIN → 任务往返 →
执行副作用）在同一 HEAD、同一 rig、同一条管线、同一测试序列下双轨全绿。
诊断插桩已全部回滚并复验通过，收尾完成。

### 闭环证据（全部来自 rig 活体 r1.log + VM 文件系统）
| 构建 | 提交 | session | CHECKIN | 任务输出 | 副作用文件 |
|------|------|---------|---------|----------|------------|
| LLVM (plainsleep) | 83111f9 | 375544582 | 13:44:35 INITIAL | whoami → desktop-p8ldlua\administrator | P2-EXECUTED-LLVM-20261027 |
| MSVC (Release) | 83111f9 | 193935888 | 15:13:05 INITIAL | whoami → desktop-p8ldlua\administrator | P2-EXECUTED-MSVC-20261027 |
| LLVM (插桩回滚后) | a2402a0 | 250605836 | 16:34:41 INITIAL | whoami → desktop-p8ldlua\administrator | P2-EXECUTED-LLVM-CLEAN-20261028 |

- LLVM beacon 首次 CHECKIN 后持续心跳 80+ 分钟无衰减（13:44 → 15:07+）。
- A/B 两侧任务往返均为 `CHECKIN sent: 109/118 bytes` → `OUTPUT received output`。
- 副作用文件经 WinRM 独立通道（不经 beacon）读取验证，内容逐字符匹配。

### 插桩回滚（commit a2402a0，-117 行）
- 删除：bw_diag2（DllMain 链 10 点）、bw_diag（主循环 8 点）、bw_st（settings 11 点）、
  bw_diag_ch（channel 2 点）——四个无条件 CreateFileA 落盘标记器。
- 顺带修复：beacon.cpp udc2_cycle 分支原为 dangling if（bw_diag 占位导致
  process_payload 绕过 length>0 守卫无条件执行），回滚后守卫自然恢复。
- 保留：hostexe bw_die 致命错误码报告（错误路径 API，仅 boot 一次）、
  BW_DIAG_RETADDR（编译期门控的 CI 诊断变体 beacon.rngdiag）、全部真实根修复
  （miniprintf NULL 守卫、BW_PLAIN_SLEEP 手工拷贝、layout 私有映射、exreg 跳过）。
- 回滚版部署复验：闭环三项全部通过（session 250605836）——插桩移除无回归。

### CI 双绿
- 83111f9：llvm-build ✅ + build ✅（墙 8192 定版）
- a2402a0：llvm-build ✅ + build ✅（回滚定版，最终状态）

### 迁移状态总结（Phase 0-4 全部完成）
1. 工具链：clang-cl + xwin + lld-link Linux 交叉编译，双主机 /Brepro 字节一致。
2. 定向重写四件套：私有映射 loader / 构建期 layout 自描述 / exreg 跳过 / crashdiag 关闭。
3. 拼接契约：volatile nop 墙 8192B（≥ TS 5120B 槽）；udrl loader 4129B 双 COMDAT。
4. 交付管线：sleeve 双资源（DLL+loader .o）加密 → artifact_raw raw → host_template
   包裹（artifact64big.exe 模板 311KB 槽不能承载 LLVM 488KB DLL）。
5. 全功能对齐 MSVC 基线。后续优化项（backed-mapping 隐蔽形态、检测面专项）见附录 G。

---

## 附录 I：Phase 2 广度项清零（2026-10-28，六通道 + 扫描对照 + 掩码取证）

### 1. 六通道活体矩阵（全部 on-LLVM，HEAD 99b0235 起同批次产物，host_template 交付）

| 通道 | 结果 | 关键证据 |
|---|---|---|
| x64 WinINet | **13 项全过** | INITIAL 61295236；pwd/getuid/ls/ps/shell/clipboard/data_store/steal/checkin/upload+download 语义/spawn/jobs/副作用文件（upload 落盘缺失为 harness 语义，MSVC 同现——双工具链等价证明） |
| x64 WinHTTP | **6/6** | INITIAL 1259881486（r2_winhttp profile 重启）；pwd/getuid/ls/shell whoami/副作用 MTX-WH |
| pivot SMB | **4/4** | spawn+link 子 INITIAL 879847424（rundll32）；pwd 经链路；shell 副作用 MTX-PIVOT-SMB |
| pivot TCP | **4/4** | 子 INITIAL 1069392972；同套全过；MTX-PIVOT-TCP |
| dnsb | **4/4** | INITIAL 496514490；pwd ALT；shell 副作用 MTX-DNSB（输出在判定窗外到达，文件实证） |
| extc2 | **INITIAL ✓ 任务下发 ✓ pwd 往返 ✓；shell 执行致死 = 遗留问题** | 会话 1140759560/1430542990（INITIAL+TASKED+ALT）；beacon 进程随 shell 任务执行整进程死亡（spawn/exec 路径 LLVM 侧缺陷，待单独立项） |
| x86 WinINet | **范围外** | LLVM CI 无 x86 轨 |

### 2. 本轮矩阵抓出并修复的真 bug
- **plain 变体 _snprintf 回归**（dab88f4 修复）：`#ifdef BW_PLAIN_SLEEP` 分叉让非 plainsleep
  构建重新编译进 _snprintf——进程健在（SleepEx 循环、WININET 已加载）但零查入。
  线缆抓包证实 GET 完好（元数据 344B Cookie），修复后同构建上线。三处 %s 手工拷贝改为无条件。
- **全部产品变体改 --layout**（3a5d26b）：winhttpb/dnsb/extc2/pivot 与主 beacon 共享
  gargle/crashdiag 源，plain 形态在 LLVM 下有 CRT-fprintf VEH + .pdata 注册风险。
- 教训（再次）：python 改 C++ 源必须 rb/wb（0e95354 整文件行尾改写，e2df4fa 恢复）。

### 3. 扫描矩阵（pe-sieve 0.4.1.1 + Moneta 1.0，同一 loader 公平对照）

| 项 | LLVM (llvm_scan 3312) | MSVC (msvc_scan 5200) |
|---|---|---|
| pe-sieve Implanted PE | 1 | 1 |
| pe-sieve Hooks/Replaced/Hdrs/IAT | 全 0 | 全 0 |
| Moneta 私有可执行区 | 1× RWX MEM_PRIVATE（0x3a7000） | 1× RWX MEM_PRIVATE（0x3b6000） |
| 宿主模块 | Unsigned | Unsigned |

**结论：暴露面逐项等价，扫描无回归。**（两者共用 BW_LOADER_PRIVATE 私有映射 loader，
对照变量只有工具链。检测面=unbacked RWX+无签名宿主，与附录 G 的设计权衡一致。）

### 4. sleep_mask 掩码窗口取证（r3_sm，gen3 路径，sleep 10s）

- 采样器：mask_probe.ps1（VirtualQueryEx 最大私有区域定位 sc_base → 100ms 采样
  .text vs 磁盘明文 text_ref.bin）。**x64 MBI 的 State/Protect/Type 是 4 字节字段**
  （+32/+36/+40）——8 字节 SIZE_T 假设导致首轮全错。
- **定性：gen3 = 调用栈感知的部分掩码。** 462/462 样本恒定 diffs=31633/65536：
  beacon 工作期（心跳正常、掩码态 pwd ALT 过、shell 副作用 MTX-MASKED 落盘 ✓）
  镜像仍保持 ~48% 密文——只解掩码活动调用链，头部常驻密文（hdrMZ=0 全程）。
  与 MSVC/官方"唤醒全量解掩码"语义不同，属 gen3 设计（规模化隐蔽更强），
  非 LLVM 缺陷。"还原 diffs=0"的旧判据在 gen3 语义下改写为：
  **掩码态多周期存活 + 掩码态任务功能保持**——两项均过。

### 5. Phase 2 验收门终判
- 六通道矩阵：5 通道全绿 + extc2 部分通过（shell 致死遗留，非工具链阻塞项——
  pwd/元数据/任务分发/输出回传全通）
- 扫描无回归：✅（逐项等价）
- 掩码窗口取证：✅（gen3 语义定性 + 掩码态功能保持）
- UDRL 链混编：✅（附录 B/H：MSVC 烘焙 loader + clang beacon 管线即日常路径）
- **Phase 2 宽度验收：达成。** 遗留：extc2 shell 致死排查、x86 LLVM 轨（范围外）。

---

## 附录 J：extc2 通道闭环 + "shell 致死"真因（2026-10-28 深夜，HEAD 5fe7932）

### 真因：link 家族 accept 循环的 sleep-0 退出（与工具链无关的存量 bug）
- `command_link_wait` / `command_tcp_bind_start` / dnsb 主循环全部
  `while (sleep_time > 0)`——操作员执行 `sleep 0`（交互语义）即在本周期末
  `safe_exit()`。矩阵取证时先 sleep 0 再 shell → shell 从未送达，"shell 致死"
  实为 pwd 周期结束后的循环退出。主循环同型 bug 早在 beacon.cpp 修过并有注释记录，
  链式家族三处漏修。MSVC 时代 extc2 测试用默认 60s sleep，从未触发。
- **修复**：三循环改 `while (TRUE) + check_kill_date()` 门（5fe7932），
  与 beacon.cpp 既有语义一致；顺带清除 smbx/lkmark 临时插桩。

### extc2 通道终局验证（LLVM 构建 + 修复版）
- **稳定模式**（默认 60s sleep）6/6：pwd/getuid/shell whoami/shell 副作用
  （MTX-STABLE2 落盘）/连续任务存活。
- **交互模式**（sleep 0）4/4：sleep 0 后信标存活、pwd ALT、shell 副作用
  （MTX-INTERACTIVE 落盘）。
- 至此六通道 **http/winhttp/SMB/TCP/dnsb/extc2 全部闭环**（x86 范围外）。

### 交互协议（sleep 0 = 每连接一个周期）——控制器契约
- beacon 每个任务周期末 `client_flush` +（sleep_time==0 时）`return` →
  FlushFileBuffers + DisconnectNamedPipe → ConnectNamedPipe 等新连接。
- 控制器必须在 EOF（PeekNamedPipe 失败）时重连并重读 metadata——TS 按
  agentid 重绑同一会话，未完成任务在新连接上继续派发。
- **round-18 协议教训再次生效**：任务帧写入后的清空窗口必须是非阻塞短窗
  （0.4s peek）——beacon 无心跳回复义务；阻塞式等心跳 = 中继死锁。

### 控制器（extc2_ctrl.ps1）终版形态
- 单线程 + PeekNamedPipe 非阻塞可用性检查 + NamedPipeClientStream 字节读
  （消息边界由 read 计数消化）；严格轮替 + 无条件帧前转 + 0.4s 清空窗 +
  EOF 重连重元数据。
- 历史教训：raw CreateFileW pinvoke 在 LoadLibrary 了 beacon 的进程内
  命名空间致盲（gle=2 恒定）；Task-per-read 超时弃读会在线程/队列堆积。
- VM 侧 PowerShell 均为 64 位；Add-Type 必须用 C#5 语法（无 out-var 内联、
  未用变量即错误）。

---

## 附录 K：Phase 3 完成 + Phase 4 决策（2026-10-29，HEAD e1e5566 双绿）

### Phase 3：pass 变形管线 MVP —— 全部验收达成

**管线**（tools/llvm/pass/，CMake+AddLLVM 构建 = 路线图的 Phase 3 CMake 引入点）：
- **obf-sub**：add x,C ↔ sub x,-C 无条件 opcode 互换（唯一等价形式）+
  icmp eq/ne x,C → xor-test 重写 + xor x,C 拆分（C1 种子化，C1^C2=C）。
- **obf-bogo**：不透明谓词块分裂——(x<<1)+x != x*3 对一切 i64 恒假，
  由 volatile 全局 bw_obf_seed 供数（ISel 不可折叠），每个合格函数
  1-2 次种子随机位置分裂；ReflectiveLoader（拼接墙契约）排除。
- 种子契约：OBF_SEED 环境变量（同种子 = /Brepro 字节复现；异种子 = 形状不同）。

**验收门实测（CI llvm-build 87e8043/e1e5566 全绿）**：
| 门 | 结果 |
|---|---|
| 确定性（同种子两次构建） | ✅ 字节一致 |
| 唯一性（异种子） | ✅ 哈希不同 |
| 基线发散 | ✅ obf ≠ baseline |
| YARA 自查（16 个站点居中窗口） | ✅ 基线 16/16 命中；变形丢 15（94% 覆盖） |
| 活体矩阵（变形产物） | ✅ CHECKIN + 11 项任务 battery + 副作用文件 + 扫描对照 |
| 扫描对照（变形产物） | ✅ pe-sieve/Moneta 暴露面与基线逐项等价 |

**管线开发中抓获/修复的真 bug**：
1. **pass 从未执行**：clang-cl 静默忽略未知 -f 旗标（warning only）——
   必须 /clang:-fpass-plugin= 前缀透传。
2. **pass-2 消费者过滤器**："/gargle." 永远匹配不到真正的 layout.h 消费者
   gargleint.cpp —— 修复前所有 DLL 烘焙的是零值占位表（verify_layout 是
   节级检查所以恒过）。修复后掩码表首次真实入库。
3. **种子化方向翻转 = 数值破坏**（活体矩阵抓获）：add x,C 被改写成
   add x,-C（保 opcode 换常数）破坏 50% 的加法 → 变形信标越界读崩溃。
   等价变换只有 opcode 翻转 + 常数取负，必须无条件。
4. /Brepro 哈希覆盖输入路径：out-dir 属于可复现契约的一部分
   （基线双构建判别器确证）。
5. gen_yara 站点居中采样：窗口必须落在可变换指令站点上
   （modrm reg 字段精确 = 0/5/7），任意窗口的覆盖是概率性的。

### Phase 4：主线切换决策（决策点完成）

**决策：llvm 分支内双轨并存——clang-cl/CMake 为 llvm 线权威构建，
MSVC CI（build.yml）保留为对照轨；build.py 继续承担变体矩阵驱动
（CMake 已按路线图接管 pass 管线，全变体移植列为后续项）。**

**合并裁定：按用户指令，llvm 分支成果不合入 feat/post-4.9.1，llvm 分支
作为长期分支存续。** 原 Phase 4 验收门（EVASION-ROADMAP Phase 0 双绿后
合入主分支）的合入动作由用户显式豁免；双绿前置条件已满足
（e1e5566: llvm-build ✅ + build ✅）。

### 遗留清单（Phase 3/4 之后）
- 全变体 CMake 移植（build.py 完全退役）——后续工程项
- x86 LLVM 轨（范围外）
- 变形覆盖扩展（and/or/sbb/relational-cmp 站点的等价变换）——
  与检测面专项合并推进

---

## 附录 L：Phase 3-4 终局收口（2026-10-29，HEAD dd47a55 双绿）

### 变形产物六通道矩阵（全部 on-obf，通道完整覆盖）

| 通道 | 变形 DLL | 结果 | 证据 |
|---|---|---|---|
| x64 WinINet | beacon.obf | ✅ | 1898698186：11 项 battery + 副作用（首发的 shell 任务丢失为任务队列竞态，重下发 try0 即执行）+ pe-sieve/Moneta 对照等价 |
| x64 WinHTTP | winhttpb.obf | ✅ 6/6 | 1844949532（r2_winhttp 轮换；首轮 4 分钟慢连）；pwd/getuid/whoami/副作用 MTX-OBF-WH2/存活 |
| pivot SMB | pivot.obf | ✅ | spawn+link 子 1368845096：pwd + MTX-OBF-SMB 落盘 |
| pivot TCP | pivot.obf | ✅ | spawn+link 子 1053356780：pwd + MTX-OBF-TCP 落盘 |
| dnsb | dnsb.obf | ✅ | 1499445234：INITIAL + pwd + MTX-OBF-DNS2（dns 慢循环，重下发即执行） |
| extc2 | extc2.obf | ✅ 7/7 | 967098602：sleep 0 交互 + pwd/getuid/whoami/副作用/存活全过 |
| x86 | — | 范围外 | LLVM CI 无 x86 轨 |

### Phase 4 build.py 退役（CMake 全变体移植）
- **架构**：`dump_manifest.py`（唯一 vcxproj/props 解析器，import build.py 的
  解析逻辑）→ manifest JSON；`layout_two_pass.py`（编译/链接/两遍布局循环/
  验证，接管 build.py 的 main()）；`tools/llvm/CMakeLists.txt`（变体驱动器，
  "+"记号变体旗标：layout/plainsleep/noexcreg/diagretaddr/bofwin/pause）。
- **CI（llvm-build.yml）**：9 个变体全部 CMake 产出（5 产品 obf + baseline +
  plainsleep/noexcreg/diagretaddr/bofwin）；build.py 的 CLI 不再被调用
  （解析器作为库存续——一个解析器，两个前端）。
- **收敛契约**：obj 依赖 gen/layout.h；每个产物取"第二次构建"（首次构建
  收敛 layout.h 表）——同秒 mtime 粒度使原地二次构建成为 no-op，必须
  rm+重 configure+重建。
- **跨运行复现实证**：/Brepro 在同 commit 上跨 CI 运行 sha 完全一致
  （4fa22012/bcfc8132 分别在两轮运行中重复出现）。

### CI 陷阱补录（CMake 移植轮）
1. dump_manifest 需 makedirs gen/（fresh checkout 无未跟踪目录）。
2. genex `$<$<BOOL:...>:...>` 空展开会成为空参数——用条件 list。
3. manifest 的 link 数组不含 lld-link 本体——驱动端前置。
4. 四个 beacon 变体共享 TargetName beacon.x64——artifact 分发必须按
   TNAME 子目录键控，否则 glob 字母序让 noexcreg 覆盖主产物
   （A_SHA 曾是 noexcreg 构建且每轮稳定——跨运行复现的副作用）。

### 终态
- **Phase 3 全验收达成**（管线 + 门 + 变形产物六通道）。
- **Phase 4 决策完成**：llvm 分支内双轨并存；CMake 为 llvm 线权威构建；
  合入主分支按操作员指令豁免；CI dd47a55 双绿（llvm-build + build）。
