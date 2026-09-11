# x86 套筒交付反馈

接手会话把结果写进**本文件**。不要改 `CMD117-X86-DELIVERY-HANDOFF.md`。

填完后告诉原来的会话：读 `docs/CMD117-X86-DELIVERY-FEEDBACK.md`。

---

## 元数据

| 项 | 值 |
|---|---|
| 日期 | 2026-09-11 16:44 |
| 代码 commit（若有） | `b066fe2`（implant 未改；交付只动 Headless CWD 影子文件） |
| TS 槽16 / 编码长度 | `0x054968E0` 头 `4a58e46e…` 长 **245792**（磁盘 + 运行中 TS 仍是这份） |
| Headless | `grok-hl117d` java pid **10384**，CWD `C:\Users\Administrator\Desktop\4.9.1\out\artifacts\`，jar 仍是官方 `4.9.1.jar` |
| 父 bid/pid | **890778478** / **17600**（仍活） |
| 新 x86 child bid/pid | **无 bid**（崩溃在 CHECKIN 前）；WER pid **4308**；dump `C:\Users\Public\cmd117_dumps\rundll32.exe.4308.dmp` |

---

## 真正读到的资源

两条路径，不要混：

### A. `bspawn http x86`（这次活测、也是 16:16 官方那次）

- 资源名：client 侧 `SleevedResource.readResource("resources/beacon.dll")` → `CommonUtils.readResource("sleeve/beacon.dll")`
- 代码：`TaskBeacon.Spawn` → `ScListener.exportLocal`（`BeaconTaskBridge` `&bspawn`），跑在 **Headless JVM**，不是 TeamServerImage
- 改影子之前：classpath `4.9.1.jar` 条目 `sleeve/beacon.dll`，编码 **247840**，头 **`7fdd3cb9b7663ec70e539f759792632f`**（官方）。`new File("sleeve/beacon.dll")` 当时不存在
- 改影子之后：Headless CWD 文件 `C:\Users\Administrator\Desktop\4.9.1\out\artifacts\sleeve\beacon.dll`，编码 **245792**，头 **`4a58e46e…`**（和 TS 槽同一份 CI）。`CommonUtils.resource()` 优先读磁盘文件
- 和 `0x054968E0` 的关系：**spawn 根本不读这个槽**。TS 槽只给 TeamServerImage 自己的 `export()` / 监听器启动 generate 用

### B. TS 监听器启动时 `Generating Payload ... Arch: x86`（ts.log）

- 资源名：Graal `sleeve/beacon.dll`（名字串 `0x03120e60`，Java `byte[]` 对象 `0x054968D0`，数据 **`0x054968E0`**）
- catalog / 对象长度：槽前 4 字节 = Java `byte[]` length = **245792**。镜像里 **已经没有** 对齐的 **247840**（备份 `TeamServerImage_patched.pre_beacon_x86` 里该对象曾是 247840 / `7fdd3cb9…`）
- svm_heap 里同体积的官方明文/第二份编码：**没有**。`0x64F88C5F` 不在镜像里。x64 槽 `0x04B40EE0` 仍是我方（len 290848），所以 TS 侧 x64 generate 的 `setExportName() failed` 是真的

x86 的 `setExportName` **不能**当「官方 vs 我方」判别：CI `beacon.dll` 的 `Export.Name` 已经是 `beacon.dll`（串在明文偏移 203372），`PEEditor.setExportName` 直接 no-op。官方同样 no-op。两边都会打 `new string table not found (MalleablePE)`。判别用 **TimeDateStamp**，不要用 MZRE。

---

## 为什么吐出官方 PE

HANDOFF **假设 5 成立（主因）**：`bspawn` 在 client 上 `exportLocal`，读 **`4.9.1.jar` 的官方 `sleeve/beacon.dll`**，再把生成好的 DLL 塞进 task 发给父会话。TS 槽是 CI 完全相容——spawn 不用它。

其余假设：

1. **Graal 名字指错槽**：证伪。svm_heap 里唯一一份 ~247840 的 `byte[]` 就是 `0x054968E0`；备份里它就是官方编码。TS 自己 generate 读的就是它。
2. **换成 rl0k / winhttpb**：证伪。16:16 CHECKIN **247816 = 247808+8**（官方明文体积）；影子之后 CHECKIN **245768 = 245760+8**（CI 明文体积）。rl0k cap 242208 对不上。
3. **svm_heap 另有官方明文缓存**：证伪。镜像无 `0x64F88C5F`，无第二份 247840 `byte[]`。进程里官方编码头本来就不会等于 jar 的 `7fdd3cb9` 以外的随机 IV；备份槽头恰好就是 `7fdd3cb9`，打槽时已被覆盖。
4. **监听器启动缓存**：spawn 每次 `exportLocal` 现生成，不复用 TS 监听器缓存。ts.log 这次 spawn **没有**新的 `Generating Payload ... x86`。

16:16 子进程官方 `0x64F88C5F`，是因为当时 Headless 还在用 jar。

---

## 活测过线

- [x] 子进程有 `cmd117probe` 或 `0x6AA3A389` 或 ReWolf
- [ ] ts.log x86 generate 出现 `setExportName() failed`（这次 spawn 不在 TS 上 generate；x86 即使是 CI 也不会 warn）
- [ ] 仍是 `0x64F88C5F` / `MZRE` 官方（MZRE 仍在，那是 MalleablePE；时间戳已是 CI）

证据：

- 父 CHECKIN **245768 B**（16:44:17）
- WER `C:\Users\Public\cmd117_dumps\rundll32.exe.4308.dmp`（16:44）：`cmd117probe`×2、`0x6AA3A389`×2、ReWolf `66 8C D8 66 8E D0`×2、**无** `0x64F88C5F`；PE@`0x112af9` DOS `MZRE` ts **`0x6AA3A389`**
- 无 INITIAL / 无新 bid：pid 4308 在回家前崩了（dump 已证明套筒是 CI）。**未跑 cmd 117**
- 影子文件：`C:\Users\Administrator\Desktop\4.9.1\out\artifacts\sleeve\beacon.dll`（245792，`4a58e46e…`）
- 父 17600、Headless 10384 未再拉起第二份 AggressiveHeap

---

## 下一步给原会话（三条以内）

1. 交付已通：新 rundll32 里是 CI（probe / `0x6AA3A389` / ReWolf）。先不要跑 cmd 117。崩在 pid 4308，dump 仍在 `C:\Users\Public\cmd117_dumps\rundll32.exe.4308.dmp`。
2. spawn 走 Headless `exportLocal` + jar。当前靠 CWD 影子；要持久就替换 `4.9.1.jar` 的 `sleeve/beacon.dll` 为同一份 245792 编码（需重启 Headless；**不要**并行再起 AggressiveHeap）。TS 槽不用再打一遍。
3. x86 `setExportName` 不能当套筒判别。Gate / force-x86 仍不要动，除非原会话在 CI 进程上继续查崩溃。

## 禁止项

- [x] 未改 Gate stub 当修复
- [x] 未把 force-x86 spawn 当最终方案
- [x] 未加回 `http_flush_post` / HKCU dump
- [x] 交付未通时未宣称 cmd 117 已过

---

## 后续：jar overlay + cmd 117 PASS（2026-09-11）

持久交付：同一份 245792 编码写进 **CWD 影子 + `4.9.1.jar` `sleeve/beacon.dll` + `4.9.1/src/sleeve/beacon.dll`**。活测用的是 **`1ffbde2`**（头 `4ee3dde3…`，ts `0x6AA3DB62`），不是最早那份 `4a58e46e` / `0x6AA3A389`。

Headless `grok-hl117k`，`-XX:+UseParallelGC -Xms256m -Xmx1g`，CWD artifacts。父 `890778478` spawn → 子 **463543496** pid **1216**。CHECKIN **245768**。进程里 CI ts + ReWolf。`data_store_load` Stored；cmd 117 OUTPUT **`grok-ea-117`**。

探针 / force-x86 已在 **`b243338`** 删除。CI https://github.com/bXZb/Beacon/actions/runs/34592888623 全绿。TS 槽仍不必为 spawn 再打。
