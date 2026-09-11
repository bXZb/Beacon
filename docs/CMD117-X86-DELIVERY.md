# x86 套筒交付核对（2026-09-11，原会话）

复现并钉死：cmd 117 崩在官方 Heaven’s Gate，是因为 **spawn 出来的 x86 进程跑的是官方 4.9.1 `beacon.dll`，不是 CI 槽里那份。**

## 对照样本

| 对象 | 判别 |
|---|---|
| CI `34571186915` / 磁盘槽 decode | `MZ\x90` `TimeDateStamp 0x6AA3A389` 有 `cmd117probe` / ReWolf |
| 官方明文 `official-x86-beacon.dll` | `MZ\x90` `0x64F88C5F` 旧 MSF stub |
| Headless `export_sleeved sleeve/beacon.dll`（`4.9.1.jar`） | **官方** 247808 B，`0x64F88C5F` |
| `artifact_payload http dll/exe x86` | Artifact 外壳 324096 B；内含官方 last512 |
| TS 文件槽 `0x054968E0` | **我方编码** `4a58e46e…` 长 245792 |
| 运行中 TS pid 16007 | 有我方编码头 ×2；**没有**官方编码头 `7fdd3cb9` |

生成后的 payload DOS 会被 MalleablePE 改成 **`MZRE`**。磁盘上的官方明文仍是 `MZ\x90`。`MZRE` 不能单独当「读错槽」的证据，**时间戳可以**。

## 活体 spawn（本机 EUEJDE2）

父 `890778478` pid 17600 `beacon_x64.exe`（pwd 正常）。

```
spawn http x86
CHECKIN sent: 247816 bytes   # 247808+8
INITIAL 362655368  rundll32 pid 15612
```

扫 pid 15612：

- 两处 PE：`MZRE` + **`ts=0x64F88C5F`**（`0x2520000`、`0x2760000`）
- `cmd117probe` / `0x6AA3A389` / ReWolf `66 8C D8 66 8E D0`：**无**
- dump `live_2520000.bin`：`0x200:0x400` 与官方明文相同；有旧 MSF `83 C0 25`

## TS 日志（listener 启动时 generate）

- **x86**：只有 `new string table not found (MalleablePE)`，**没有** `setExportName() failed`
- **x64**：两条都有（我方 x64 没有 strings table）

官方 x86 有 strings table，所以 x86 这条 generate **没有在用我们打进去的那份 PE**。

## 结论

接手会话「活体是官方套筒、磁盘槽是 CI」**成立**，本机新鲜 spawn 复核。

还没钉死的是 Graal **为什么**读到官方 PE：文件和进程里都只剩我方编码 blob。下一步应查 `SleevedResource` / 监听器 payload 缓存 / x86 专用模板，而不是改 Gate 字节。

不要把 `4.9.1.jar` 的 `sleeve/beacon.dll` 当成 TS 槽；Headless `export_sleeved` / `artifact_payload` 走的是 **client jar**，默认官方。

---

## 原会话 1–3（2026-09-11 17:30）

### 1. pid 4308 dump

`rundll32.exe.4308.dmp`：映像基址 `0x041E0000`（`MZRE` + `0x6AA3A389`）。异常 `eip=0x04201E30` = 基址 + **`0x21E30`**。

CI `beacon.map`：`_abort` `10021e07`（RVA `0x21e07`）。指令是 UCRT `abort` 里的 `push 7; int 29h`（`FAST_FAIL_FATAL_APP_EXIT`）。

栈（beacon RVA）：

- `0x5b53` `_fprintf`（`tomcrypt.x86:crypt_argchk.obj`）
- `0x5b24` `_crypt_argchk`
- `0x17edf` 在 `rsa_encrypt_once`
- `0x14119` 在 `agent_init`
- `0xe6a9` 在 `beacon()`
- `0x16772` 在 `DllMain`
- `0x1b89d` `__DllMainCRTStartup`

结论：CI 套筒在 **第一次 metadata RSA**（`agent_init` → `rsa_encrypt_once`）触发 **LTC_ARGCHK → abort**，所以回家前崩。不是 Gate、不是 `__chkstk`、不是 GS cookie（那会是 fastfail 2/6）。

### 2. 持久交付

- 客户端 overlay：`4.9.1/src/sleeve/beacon.dll`（同一份 245792 CI 编码）
- `build.ps1` 把 `src/sleeve` 打进 fat jar（覆盖 `cobaltstrike-client.jar`）
- 重建 `out/artifacts/4.9.1.jar`，条目头 `4a58e46e…`
- 重启 Headless `grok-hl117g`（先停了 `grok-hl117d`；未并行 AggressiveHeap）
- CWD 影子文件仍在，双保险

### 3. checkin 活测（未跑 cmd 117）

父 `890778478` pwd 过。`spawn http x86` CHECKIN **245768**（CI 体积）。**无 INITIAL**。与 4308 同一失败模式（LTC_ARGCHK abort）。父 17600 仍活。

### LTC_ARGCHK 根因

`rsa_import.c` **`in != NULL`**：`setting_ptr(SETTING_PUBKEY)` 为 NULL。运行时 `settings[]` 全 0。

注入 PE 里 `myargs` XOR 0x2E 后 TLV 是完整的（id=7 type=3 len=256，DER `30819f…`）。`settings_init` 把表清空了：

`BeaconGuardrails.applyPatch` 对整颗 DLL `indexOf(68 字节 GGGG 魔数)`。DLL 里有两份：`.rdata` 的 `GUARD_MAGIC` 和 `.data` 的 `guard_region`。Java 命中先出现的 **.rdata**，2048B guard blob 盖掉 LTC 字符串；`guard_region` 仍是 `GGGG…`。

`memcmp(guard_region, GUARD_MAGIC)` 一边明文、一边被盖掉的 .rdata → 误判已 patched → checksum fail-close → 公钥 NULL → `abort`。

dump：`.rdata+0x2D000` 乱码；`guard_region` 仍 `GGGGuuuu…`。

修复 commit **`1050045`**：比较串拆成两段，68 字节 needle 只留在 `guard_region`。CI https://github.com/bXZb/Beacon/actions/runs/34587054764 。

---

## 4. Overlay 进 client jar（2026-09-11）

CWD 影子能让 spawn 用上 CI，但不持久。`1ffbde2` 活测同时 overlay 了 jar：

| 位置 | 编码体积 | 头 16B |
|---|---|---|
| CWD `4.9.1\out\artifacts\sleeve\beacon.dll` | 245792 | `4ee3dde3a7053d73238e0ca0b346d6cf` |
| jar `4.9.1.jar` → `sleeve/beacon.dll` | 同上 | 同上（备份 `4.9.1.jar.pre_1ffbde2`） |
| 源树 `cobaltstrike\4.9.1\src\sleeve\beacon.dll` | 同上 | 同上 |

明文：CI `34590500649` `Win32/Release/beacon.dll` **245760**，ts **`0x6AA3DB62`**。`CommonUtils.resource()` 仍优先 CWD 文件；jar 是 Headless 换 CWD 或重建 artifacts 时的底。

Headless 必须在 **artifacts 目录** 启动。JVM 先试 `-XX:+UseParallelGC -Xms256m -Xmx1g`。

---

## 5. cmd 117 活测 PASS（18:56）

`1ffbde2`（参数拼接）+ 上述 overlay。Headless `grok-hl117k`。父 `890778478` spawn → 子 **463543496** pid **1216**。CHECKIN **245768**。store **Stored**；banner；OUTPUT **`grok-ea-117`**；pwd 仍过。

旧子 `402162100` 仍是 `1050045`，OUTPUT 曾是 `0x8007000b`，不能用来验 `1ffbde2`。

---

## 6. 收敛（`b243338`）

删除管道探针和 force-x86 开关。CI https://github.com/bXZb/Beacon/actions/runs/34592888623 全绿。日常步骤：`docs/LIVE-OPS.md` §3.1。矩阵：`docs/MATRIX.md` §4.1。

补测 overlay（CI `34593437113`）：明文 ts **`0x6AA3E415`**，无 `cmd117probe`，编码头 **`9b980d33…`**。子 `1026850514` store 117 + 非 store EA + hashdump 过。WinHTTP 须 `r2_winhttp`，子 `1204167688` CHECKIN **290312** cmd 117 过。
