# Phase 0 基线扫描记录（首轮，2026-10-03）

环境：TS=192.168.100.98 r2_nosm（**掩码关、无 process-inject 块**）；构建=805998c
（CI 37003242690）；Headless=grok-ev0；扫描器=PE-sieve 0.4.1.1（/data 2 /shellc 3
/imp 3）+ Moneta 1.0（-m ioc）。

## 基线数据

### 形态 A：stageless EXE（beacon_ev1.exe，pid 11976，bid 689310928）

| 扫描器 | 命中 |
|---|---|
| PE-sieve | **2 implanted PE**（Total suspicious: 2） |
| Moneta | 4 命中：<br>① `0x400000:0x57000` EXE Image **Unsigned module**（载体本身未签名）<br>② `0x7D0000:0x48000` Private **RX** "Abnormal private executable memory"（运行中 beacon 镜像，ER 权限）<br>③ `0xB20000:0x62000` Private **RWX**（EXE 载体 .data 腔的**原始 payload 副本**，永驻无掩码）<br>④ `0xB83000:0x1000` Private RWX 尾页 |

命中物鉴定：两块私有 PE 头部均为 `4D 5A 41 52 55 48 89 E5...`（MZ + ARU = 反射
loader stub）——②是自研 loader 映射的运行镜像，③是模板 .data 腔内原始 beacon blob。

### 形态 B：spawn 注入（rundll32 载体，pid 8784，bid 1443756358，父=ev1）

| 扫描器 | 命中 |
|---|---|
| PE-sieve | 2 implanted PE |
| Moneta | 3 命中：<br>① `0x...940000:0x48000` Private **RWX**（beacon 运行镜像——**RWX 而非 ER！**）<br>② `0x...C80000:0x62000` Private RWX（注入写入的 payload 副本，整块驻留）<br>③ `0x...E3000:0x1000` RWX 尾页 |

载体 rundll32 为签名系统二进制 → 无 Unsigned 命中（形态优势）。

## 首轮结论（六层可见性映射）

1. **L5 睡眠掩码关闭态基线已建立**：beacon 镜像（unbacked private executable）
   在两类扫描器下均全命中——这正是 Phase 1（Gen3 睡眠链）与 Phase 4（module
   stomping 消除 unbacked）的靶子。
2. **新发现①（配置级，零代码可整改）**：spawn 注入路径内存 **永 RWX**——
   r2_nosm 无 `process-inject` 块 → PERMS_I==PERMS 默认相等 → finalize 短路不翻
   权限（官方语义；§9.2 的 DEP 修复只救了 BOF 执行，未改注入默认）。整改：
   profile 显式配 `process-inject { set allocator ...; min_alloc; userwx "false"; }`
   或运营 profile 加 rx 目标权限 → 验证 Moneta 命中①②降为 RX。
   **C 批"RWX 收敛"只覆盖 beacon 内部分配（syscall 桩/BOF 映射），官方注入
   语义路径不在内——这是文档要修正的认知。**
3. **新发现②（模板级，Phase 4 靶子）**：stageless EXE 的 .data 腔原始 payload
   副本永驻且 RWX（官方 artifact 模板同款行为）——Phase 4 loader 链应"用后抹除"
   该副本。
4. **形态对照**：spawn（rundll32）比 EXE 少"未签名载体"命中——落地形态选择
   本身是规避决策（与六层模型 L1/L2 一致）。
5. **观察项**：beacon_ev0.exe（同构建同 profile）首 checkin 后 ~2 分钟死亡，无
   WER 记录；ev1 同链路存活跨多睡眠窗口——偶发未复现（与 §6.2 dnsb 一次性
   消失同类，挂观察）。EXE 载体执行后文件自删（无害，opsec 特性）。

## 待办（Phase 0 未完成项）

- [ ] **掩码开对照**（mini_sm 下同两形态重扫——预期命中①②内存内容变密文，
      但权限属性命中仍在）。
- [ ] **profile 整改验证**（process-inject 块 + spawn 复扫，验证 RWX→RX）。
- [ ] ETWti 采样（权限翻转/线程事件计数）。
- [ ] 掩码窗口内扫描（掩码生效时 Moneta/PE-sieve 对 beacon 镜像的读取行为）。

## 复现命令

```
# 生成与启动
#   Headless inbox: artifact http exe x64 C:\Users\Public\beacon_evX.exe
#   或 spawn http x64（经活着的父会话）
MSYS_NO_PATHCONV=1 ./tools/pe-sieve64.exe /pid <PID> /dir results/<dir> /data 2 /shellc 3 /imp 3
MSYS_NO_PATHCONV=1 ./tools/Moneta64.exe -m ioc -p <PID>
```

原始输出：`results/pe-sieve-out/`（EXE 形态）、`results/pe-sieve-spawn/`（spawn 形态）。


---

# 第二轮（2026-10-03 下午）：整改验证 + 掩码开对照

## 1. profile 整改验证（r2_evbase：process-inject startrwx/userwx false）

TS 侧语义（反编译 ProcessInject.apply 确认）：`setting43(PERMS_I) = startrwx ? 64 : 4`；
`setting44(PERMS) = userwx ? 64 : 32`。

| 轮次 | profile | Moneta（spawn 子进程） |
|---|---|---|
| 基线 | r2_nosm（无块） | 镜像 **RWX** + 副本 RWX + 尾页 RWX |
| evbase-1 | + startrwx false | **无变化（全 RWX）** —— 43=4 但 userwx 默认 true → 44=64，翻转照做但翻到 RWX（RW→RWX） |
| evbase-2 | + startrwx + **userwx "false"** | **镜像 RWX→RX ✓**；副本块仍 RWX |

结论：**零代码整改生效**——运营 profile 必须同时配 `startrwx "false"` 与 `userwx "false"`
（只配前者反而把 RW 起步翻成 RWX）。默认全 true = 注入内存永久 RWX。

## 2. 遗留工程项：注入副本块（0x64000，MZ+ARU 头）为何仍 RWX

消费链（inject_mirror）在写完副本后 `VirtualProtectEx(PERMS)`，44=32 应翻 RX。实测仍
RWX，且副本尾部（0x60000+）含运行时指针表（与 payload 同一区域）。候选假设：翻转时
序、loader 执行前窗口、区域合并显示。**归 Phase 2 工程分析**（Phase 0 只记录）。

## 3. 掩码开对照（mini_sm，ev4 EXE pid 8844）

- **三节全密文实证**（与磁盘明文逐字节比对）：.text/.rdata/.data mem≠disk 全部成立；
  3 分钟 18 采样点密文恒定（同 key 同位置的确定性 XOR）——**掩码全程有效，覆盖面
  包含 .text**（own-table 0f5490a 修复后的真实覆盖，此前从未对 .text 单独验证过）。
- 采样器教训：第一版分类器把稳定密文误判为 "plaintext"（字节和启发式），后改用
  与磁盘明文比对才闭环——**掩码态判定必须与磁盘原文比对，不能用启发式**。
- Moneta（掩码开）：镜像 RX（mir0x48000）+ 副本 RWX + 尾页 + **新增 0x390000:0x1000
  RX**（own-table 专用页，掩码基础设施自身的暴露点）。属性类命中（私有/RX/RWX）
  掩码无法消除——Phase 4 module stomping 的靶子。

## 4. Phase 0 剩余待办

- [ ] ETWti 采样（权限翻转/线程事件计数）
- [ ] 注入副本 RWX 时序分析（Phase 2 交接）
- [ ] 真机 EDR 实验室（独立预算项）

## 新增工具

- `evasion-lab/spawn_and_scan.py`（spawn+双扫描一体）、`dump_procinj_settings.py`
  （settings 表 dumper，TYPE_SHORT=1 注意）、`mask_window_scan.py`（掩码窗口采样，
  判定用磁盘比对法）、`watch_exe.py`。
- profile：`cs-agscript-mcp/scripts/r2_evbase.profile`（整改配方：startrwx+userwx
  双 false）。
