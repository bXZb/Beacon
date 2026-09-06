# Live 结论：CS 4.9.1 协议兼容 HTTP WinINet x64

- 窗口：2026-09-02–03
- 目标：`CobaltStrikeBeaconCppSource-main` 4.9.1 分支，HTTP WinINet x64
- 客户端：`4.9.1.jar` + JDK 21 + Headless Aggressor（`grok-hl*`）
- TeamServer：`192.168.100.98:50050`，密码 `123456`
- 主会话：`988387210` `beacon_x64.exe` pid 10560 `Administrator *` @ `DESKTOP-4CPCB7A` / `192.168.100.198`
- Listener：`http` `192.168.100.98:8080`（后续另开 8081/8084–8089 做生成期对照）
- 原始日志：`cs-agscript-mcp/scripts/r1.log`；分轮备忘 `r1_report.md` / `r2_report.md` / `r3_report.md`

**范围**：只声称 HTTP WinINet x64。WinHTTP 套筒、x86、dnsb、SMB/TCP pivot、ExtC2、UDRL、Post-Ex prepend、cmd 117 assembly-from-store **未测，不在本结论内**。

---

## 1. 总表

图例：**过** = 活体对官方 4.9.1 TS 行为符合；**官方语义** = 不是 implant 协议洞；**未测** = 范围外。

| 能力 | 结论 | 证据 |
|---|---|---|
| checkin / 不掉线 | **过** | `host called home`；全程 lastf 毫秒～数秒 |
| Cookie RSA-1024 | **过** | `GET /match` Cookie base64 **172** 字符（末尾 `=`）→ 密文 **128B** |
| spawn + exit | **过** | 子 `424533428` INITIAL 后 `beacon exit.`，父仍在 |
| ps / pwd / cd / ls | **过** | pwd 走 `beacon_output_alt`（4.x 原样）；ps 字段 `name,ppid,pid,…` |
| steal 同会话 | **过** | explorer 5304 → Impersonated；HEART `impersonated=` |
| rev2self | **过** | impersonated 清空；无 callback 37 |
| token-store | **过** | steal 不立刻 use、list、use、rev2self 后 store 仍在、remove |
| steal 跨会话 11724 | **官方语义** | `OpenProcess(PROCESS_QUERY_INFORMATION)` → ERROR 5。见 §3 |
| syscall 运行时 None/Direct/Indirect | **过** | 每次改完 ps 完整、不掉线 |
| syscall 生成期 Direct | **过** | 新 `957216250` / `885590660` 查询 Direct；旧主会话仍 None |
| clipboard BOF（cmd 100） | **过** | 两次 `Clipboard Data`；allocator reuse 未崩 |
| data-store add/list/remove | **过** | index 0 存/列/删 |
| data-store 从 store 执行 BOF（cmd 116） | **过** | `Executing the BOF from Data Store` + clipboard 回显 |
| bof_res setting 74 默认空 | **过** | live `BeaconGetValue("bof_res")=NULL`。非空无用户语法，见 §2 |
| upload / download | **过** | 29B 往返大小一致 |
| screenshot | **过**（打包瑕疵） | 55kb 成功；缺 sleeved `postex-loader.x64.bin`，回落 jar `resources/` |
| keylogger + jobkill | **过** | job 3 出现后杀掉，jobs 空 |
| SOCKS5 TCP | **过** | TS `:2108x` CONNECT example.com → `HTTP/1.1 200`。绑在 TS 不是 Windows 客户端 |
| SOCKS5 UDP（正确 ASSOCIATE） | **过** | 见 §4。`0.0.0.0:0` 被官方过滤器 drop，不是 implant |
| Host Profiles | **过** | `GET /hp1.js?h=1` + `X-HP: one` 与 `/hp2.js` 轮换；旧 beacon 仍 `/match` |
| Guardrails | **过** | 匹配 `http_gok3` 上线；不匹配 `http_gbad3` 发 307208B **无 INITIAL**（CNA 必须用真正 tab，禁止 Sleep `replace("|")`） |
| sleep_mask ON | **过** | `957216250` `sleep 5` 后 lastf~1s，继续跳 |
| sleep_mask OFF | **过** | `885590660` Direct + `sleep 5` 后 lastf 2s/4s，trampoline 未崩 |
| WinHTTP / x86 / dnsb / pivot / UDRL / cmd 117 | **未测** | 约定范围外 |

---

## 2. A2：`bof_res`（setting 74）

### 活体

对当前 payload inline-execute `cs-agscript-mcp/scripts/bof/bof_res_read.x64.o`：

```
OUTPUT  bof_res=NULL
```

implant：

```c
char * res = setting_ptr(SETTING_BOF_RESOURCE);
if (res != NULL && res[0] != '\0')
    BeaconAddValue("bof_res", res);
else
    BeaconRemoveValue("bof_res");
```

空或缺失 → KV 为 NULL。与现网一致。

非空路径：`tests/test_s4.cpp` `bof_res_setting_74_kv` 写入 type=3 的 index 74 后 `BeaconGetValue != NULL`，再清掉变回 NULL。

### 有没有用户可写的 Malleable 语法？

**没有。** 官方 Process Injection 手册（Fortra CS current / 4.13 文档页，2026-06-22）`process-inject` 用户选项是：

`allocator` · `bof_allocator` · `bof_reuse_memory` · `min_alloc` · `startrwx` · `userwx` · `transform-x86/x64` · `execute` ·（后续版本）`use_driploading` / `dripload_delay`

**没有 `set bof_res`。** ThreatExpress `jquery-c2.4.9.profile` 同样只有 `bof_allocator` / `bof_reuse_memory`。`resources/default.profile` 全文无 `bof_res`。

生成器内部：`ProcessInject.parse` 读 `c2profile.getByteArray(".process-inject.bof_res")`，`apply` 无条件 `addData(74, this.bof_res, this.bof_res.length)`。这是 **byte[] 内部键**，和 `.self` 一类，不是 `set "..."` 字符串。

Malleable `set foo "bar"` 进的是 String。若手写 `set bof_res "file.bin"`，`getByteArray` 会 ClassCast 或得到 null；`this.bof_res.length` 在 null 上 NPE。现网能生成，说明缺键时解析器给了空 `byte[0]`（或 native 侧有保护），setting 74 长度为 0 → `setting_ptr` 空串 → live NULL。

**结论：4.9 用户可见行为就是 `bof_res=NULL`。不在 profile 里加 `bof_res`，不做非空 live 正例。** 非空只保留单元测试。

---

## 3. steal 跨会话（不列入协议失败）

`tokens.cpp` `steal_token_from_pid`：`OpenProcess(PROCESS_QUERY_INFORMATION)` 失败则 `post_error_dd(0x21, pid, GetLastError())`。

notepad 11724 在另一桌面会话（用户 `test`）→ ERROR 5。`.steal_token_access_mask` 只作用于随后的 `OpenProcessToken`，到不了这一步。同会话 5304 已过。

可选后续（A3）：改 `PROCESS_QUERY_LIMITED_INFORMATION`。不改不影响本结论。

---

## 4. SOCKS UDP 测法（写死，避免再假失败）

绑在 **TeamServer** `192.168.100.98`，不是 Headless 所在 Windows。`/etc/hosts` 里 hostname 必须是 `192.168.100.98`，否则 `InetAddress.getLocalHost()` 会把 BND.ADDR 写成 `127.0.1.1`。

官方 `Socks5UDPRelayServer.isFromClient` 要求 UDP 源端口 == ASSOCIATE 的 **DST.PORT**。ASSOCIATE `0.0.0.0:0` 时构造日志是 `Port:0`，随后：

```
Dropping Packet from unknown client. PacketAddress: /192.168.100.194 PacketPort:52149
```

包已到 TS，**不会**下发 cmd 103/104。这是官方 4.9.1 过滤器，不是 RFC「首包登记端口」。

正确测法：

1. 先 `bind` UDP，记下端口 P
2. ASSOCIATE ATYP=IPv4 DST=`0.0.0.0` DST.PORT=**P**
3. 从同一 UDP socket `sendto` 中继

对照（2026-09-03，DNS=`223.5.5.5`；本机/TS 直连 223.5.5.5 与 8.8.8.8 均通）：

```
constructor: Client Address:/192.168.100.194 Port:56634
Granted bndPort:55872
Client-Packet (Decapsulated)  223.5.5.5:53
writeToClient DataLen: 61
```

客户端收到 71B，DNS flags `0x8180`。cmd **103/104 通**。

回包 SOCKS 头地址是客户端 IP:P 而不是 `223.5.5.5:53`（官方 `writeToClient` 用 G:F 封装）；DNS 载荷正确。

---

## 5. 测试环境备忘

- Guardrails 的 CNA 字段必须是真正的 tab（`URLDecoder.decode("%09")`）。Sleep `replace("|")` 是正则空交替，会拆成 17/33 字段，TS `Length error parsing guardrail callback`，GGGG 打不进去。
- Headless 驱动 `wait()` 曾在日志已成功时显示失败（pos 竞态）；以 `r1.log` 为准。
- screenshot 缺 sleeved loader 是资源打包，功能已过（可选 A4）。

---

## 6. 明确不在本结论内

WinHTTP 套筒、x86、dnsb、SMB/TCP pivot、ExtC2、UDRL、Post-Ex prepend、data-store **cmd 117** execute-assembly。
