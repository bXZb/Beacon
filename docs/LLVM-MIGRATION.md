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
