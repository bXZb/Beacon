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

## 2. 约束现状（哪些"铁律"已经消失、哪些还在）

| 约束 | 状态 | 说明 |
|---|---|---|
| 套筒容量上限 ×3 | **消失**（cs-gradle 线） | sleeve 文件化，上限即文件大小 |
| GraalVM 打槽 / CrackSleeve / svm_heap 解码缓存 | **消失** | TS 是普通 JVM fat jar |
| 5K INT3 墙（pe.process memcpy 5120B） | 名义还在 | 代码在自家 cs-gradle 源里可改；为保持官方工件形状兼容，默认 DLL 保留墙，rl0k（SIZE=0）路径本就无上限 |
| UDRL COFF 抽取契约（OBJParser.hasSection(".text")→首个可执行段裸字节） | 名义还在 | 同上可改；过渡期 UDRL `.o` 维持 cl 编译不动，见 §4 风险 1 |
| TS 下发表（sleepmask pair）按官方 PE 布局 | 在，但双端自控 | pair-5 打中 .pdata CRT unwind 条目的前科（SLEEP-MASK-FEEDBACK）；clang 的 .pdata/xdata 形状不同，Phase 2 必须重验 |

## 3. 技术选型（分相）

- **Phase A：clang-cl + lld-link 侧车**。不动 MSBuild 主线，新增独立脚本直接调 clang-cl
  镜像现有 flags（`build-llvm.ps1`，产物命名 `*.llvm.dll` 与 MSVC 产物并存）。保持 MSVC
  ABI/CRT/对象格式，风险最小，tomcrypt lib 直接链接。vcxproj 的 `PlatformToolset=LLVM`
  路线作为备选（一行改动但把主线耦合进实验，不采用）。
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
| 0 | CI 侧车编译：windows-2022（LLVM 预装，版本写进产物名）、`build-llvm.ps1` × 4 变体 + winhttp + rl0k | 编译过/不过清单 + 体积对照表（**纯信息收集，无门槛**） |
| 1 | 形状验证：`load_smoke`（blob 补丁→LoadLibrary→导出验证）×4 变体；导出表/MAP/.pdata 对照；tomcrypt 链接确认 | load_smoke 全绿 + 导出名逐字节一致 |
| 2 | 活体 A/B：cs-gradle sleeve 文件替换（非打槽）→ 六通道矩阵 + `evasion-lab` 扫描矩阵（PE-sieve/Moneta）与 MSVC 基线对照；UDRL 链（MSVC 烘焙 blob + clang beacon）混编验证；sleepmask 掩码表重派生 | MATRIX 全绿 + 扫描无回归 + 掩码窗口取证（等价性 diffs=0） |
| 3 | pass 管线 MVP：1-2 个自研 pass + 种子；对自家已知签名做 YARA 自查；变形产物过 Phase 2 同套矩阵 | 逐构建形状唯一（哈希散列）+ 矩阵全绿 |
| 4 | 主线切换决策点：clang-cl 默认或双轨并存 | 按 EVASION-ROADMAP Phase 0 矩阵双绿标准合入 `feat/post-4.9.1` |
| 5 | TS 侧重编架构（跨仓库，与 cs-gradle 协同） | 另立规格文档 |

## 6. 与其他线的关系

- `evasion-research`（Gen3 睡眠链/调用栈）：pass 变形与其**正交可叠加**；掩码表与堆形状的
  交互在 Phase 2 一并回归，不单独开口。
- cs-gradle `main`（4.11–4.13 parity）：官方 LLVM Beacon 的行为对照参考；其 BOF-PE /
  Payload Store 还原件是 Phase 5 架构的内部参照。
- `linux-4.5`：无关（Linux beacon 是另一条产品线）。

## 7. 立即行动项（Phase 0 细目）

1. `build-llvm.ps1`：参数镜像 `build.ps1`（-Project/-HttpLibrary/-Platform），内部定位
   clang-cl/lld-link（vswhere 之外的 LLVM 安装路径或 PATH），flags 逐项照抄（`/nologo /W3
   /O1 /GS- /MT /Zc:* /Gy /Gw /GR- /std:c++17 /Zl`——按 vcxproj Release|x64 实值核对），
   产物 `<name>.<plat>.llvm.dll` + `.llvm.map`（lld-link `/MAP:`）。
2. CI `llvm-x64` job：matrix × 4 变体 + winhttp + rl0k + x86；上传 `.llvm.*` 独立 artifact；
   记录 clang 版本到 step summary。
3. 体积对照表进本文件附录（Phase 0 产出回填）。

---

维护约定：本分支只做工具链迁移与 pass 管线；beacon 功能改动仍在 `feat/post-4.9.1`，
本分支定期 rebase 其上（像 evasion-research 对 4.9.1 的关系）。Phase 4 通过后本分支
使命终结，内容并回主线。
