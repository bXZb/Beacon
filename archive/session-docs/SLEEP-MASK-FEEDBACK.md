# x64 sleep_mask BOF 反馈

接手会话写这里。不要改 `SLEEP-MASK-HANDOFF.md`。

---

## 元数据

| 项 | 值 |
|---|---|
| 日期 | 2026-09-30 |
| commit / CI | **`5c753e1`**（终验干净构建）；诊断链 `76855a3`→`448dab8`→`0b07bd9`；中间修复 `42309cb`。CI 36683328739 → 36700547283 全绿 |
| overlay 编码头 / 明文体积 | 终验套筒编码 **291872**（明文 291840 = CI artifact +0）；四处投放（CWD 影子 / jar / 两个 src 备份），jar 备份 `4.9.1.jar.pre_31F96C2D` |
| profile | `r2_winhttp_sm`；**测完已改回 `r2_nosm`** |
| 子 bid / pid | 中间验证 `24946042`/10444（`42309cb`）；**终验 `1305512946`/3996（`5c753e1`）** |
| CHECKIN 字节 | spawn staging = 明文+8：295944（42309cb 子）、**291848**（5c753e1 子） |
| reloc type 3 次数 | **0**（两次验证子均无 ERROR 行） |
| 第二次 CHECKIN / pwd | **是**（lastf=1s 持续回连 3+ 个掩码睡眠周期；pwd `Current directory is C:\Users\Administrator\Desktop\cobaltstrike`） |
| `sm_gparms.txt` mtime | 诊断期每周期重写（新鲜）；**过线后 dump 已随清理构建删除，Public 已清空** |
| heap 是否仍含 sections 指针 | 否（d1a3699 过滤生效，新鲜 dump 证实） |

## 结论

- [x] **已过**：60s 内二次 CHECKIN + pwd，reloc=0，BOF 每周期返回且镜像字节级还原（诊断构建实测 `diffs=0`）

### 根因（实证链）

**TS 下发的 `SETTING_GARGLE_SECTIONS` 表是按官方 sleeve 的节布局计算的；套在我们的 DLL 上，同样的偏移落在我们不同的数据上。其中 pair 5（0x62000-0x62100）恰好落在我们 `.pdata` 的 256 字节（静态链接 CRT 的 invalid_parameter/errno/winapi_thunks 家族 unwind 条目）。掩码窗口内任何异常的分发/栈展开都要二分查这张表——读到 XOR 垃圾 → 二次故障 → fail-fast：进程瞬间消失，SEH 捕不到（`__except` 帧本身在被掩码的镜像里、unwind 撞垃圾 .pdata），WER 也不落盘。**

排除过程（全部实证，不要重验）：

| 实验 | 结果 | 排除/确认 |
|---|---|---|
| 空表（sm_empty，76855a3） | 存活，BOF 每周期返回 | 序言/call rbp Sleep/解掩码/返回路径**无罪** |
| 段表单独（sm_sect） | 死 | heap walk 无罪，**段 XOR 致死** |
| sm_sect + 1ms（sm_t1） | 死 | 非 60s 窗口被外部使用 |
| VirtualQuery 页映射 | 0-0x6FFFF 单一 RWX 提交分配 | **RX 权限假设死**（procinj I=F=0x40） |
| `img=0x65000`（SizeOfImage 含虚拟填充）> span | 全程界内 | **OOB 假设死**（文件大小≠SizeOfImage） |
| p1..p6 逐对二分（448dab8） | p1-p5 活、p6 死 | 凶手=pair 5（0x62000-0x62100） |
| sm_only5（只掩 pair 5） | 死 | 单独这 256 字节即致命 |
| sm_skip5（掩其余全部含 .fptable） | 活，`diffs=0` | **还原字节级完美**；.fptable 掩码无害 |
| TS blob vs 磁盘对象采样比对 | 逐字节一致 | "交付对象不同"假设死 |
| WER LocalDumps | 无转储 | 非可分发异常（fail-fast 类） |

诊断副产品（后续会话可能有用）：`.fptable`（0x63000，文件里全零 256B）**运行时被填入 0x7FFF... 内核指针**——是运行时填充的函数表；掩码+还原它无害。另外 `BeaconInformation` 的 `info.sections` 直接回读 `gparms->sections`，不是每次查 setting——曾被我的空表 swap 持久化混淆，非 bug。

### 修复（`42309cb` + 清理 `5c753e1`）

`boff.cpp` conv==1 路径：invoke 前用 **`sm_build_own_table`** 从**我们自己内存中的 PE 头**合成掩码表——掩 headers 页 + `.text`/`.rdata`/`.data`（clamp 到 SizeOfImage），**跳过 `.pdata`/`.fptable`/`.reloc`**。全部诊断代码（dump/标记/SEH/快照/页映射）已删，只留这一个函数（~50 行，双架构编译）。`d1a3699` 的 heap 过滤与 `gargle_setup_parms` 未动。

### 遗留 / 下一步建议

1. **`gargle_setup_parms` 仍读官方表**（4.5 蹦床路径 + -1 patch）。x86/无 blob 时不受影响（不 invoke），但若以后 x86 也接官方 sleepmask 对象，需把 own-table 下沉到 gargleint。
2. heap 记录表 dump 窗口曾截到 24 条（heapN 打印已删）；若再排查 heap XOR，先恢复全量打印。
3. 官方语义下 `.rdata/.data` 掩了、`.fptable`（函数表）跳过——若要更贴近官方全掩码，需先确认 `.fptable` 掩码期间无间接调用穿过（skip5 已证睡眠窗口内无害，但 BOF 执行期间未单独测）。

## 给原会话（三条以内）

1. sleep_mask 已过线（`5c753e1`，干净构建）：二次 CHECKIN + pwd + reloc=0；CWD/jar 套筒=终验构建可留用。
2. 修复=自建 PE 掩码表（跳 .pdata/.fptable/.reloc）；根因是 TS 表按官方布局算，偏移错位打中我们 .pdata 的 CRT unwind 条目 → 窗口期异常分发 fail-fast。
3. TS 已回 `r2_nosm`；本机 WER LocalDumps 键已删、测试进程/父/Headless 已清、Public 无残留。

## 核对

- [x] 未把 rcx 改成 `BEACON_INFO*`（三参数 `(gparms, Sleep, t)` 未动）
- [x] 未重开 Gate / cmd 117 / `http_flush_post`
- [x] 过线后已删 Public dump；CWD 套筒=**过线的 invoke 构建**（`5c753e1`，291872）
- [x] TS 已 `r2_nosm`
