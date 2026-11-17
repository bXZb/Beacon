# -*- coding: utf-8 -*-
"""update_memory_c43.py - append C-42/C-43 results to c41 memory file."""
import io

P = (r"C:\Users\Administrator\.zcode\cli\memories\projects"
     r"\cobaltstrike-646a8c99d4ff867a\memory\c41-ecosystem-compat-tests.md")
s = io.open(P, encoding="utf-8").read()

s += '''

**C-43（同日）测 5 完整闭环 + 测 1 直连 GET 通路打通**：
- **测 5 构建链定稿**（bash-native 弃 cargo-make）：rust nightly gnu +
  sysroot rlib harvest（core/alloc/compiler_builtins/panic_abort，注意
  rustc --print=sysroot 需 +nightly）+ CRT shim 四件 + __rust_no_alloc_
  shim defsym=0（crate-hash mangled 动态构造）。纯 core BOF 完全可行，
  shim 链文档化=社区 BOF 适配路线图。
- **测 1 决定性突破**：三层 OBTRACE 探针（beacon.c/network.c/transform.c）
  逐级定位——preflight gle 链全 ✓（12029=fake TS one-shot accept 假象，
  改 persistent accept loop）；**直连 GET sent=1 gle=0，Cookie 182B
  base64(RSA metadata) 成功送达真实 TS**；TS 收到但解密失败静默 404。
- **精确缺口**：TS 端 Cookie 解密后 AES key/字段校验失败。已备工具：
  fake_ts_capture persistent 版抓 cookie 到 ob_cookie_b64.txt，TS java
  AsymmetricCrypto 可复用解密。半轮工作量闭环。
- **vendor patch 新增**：blob 1024B 填充（MAX_REQUEST_PROFILE 越界读）、
  direct GET 直连通路（硬编码 Cookie 头）、fresh wininet handles
- **环境坑新增**：python one-shot fake TS 假象（curl 200 但 beacon 时已
  退出——persistent accept loop 修复）、PDB 未收 artifact、heredoc
  chr(34) 字符串拼接炸（script via Write 工具）
- ts e582e6f / beacon 0f2eb72+。

**下轮最后半轮**：TS 私钥解密 ob_cookie_b64 → 逐字节对撞 → 修
OpenBeacon metadata → INITIAL → 测 1 全绿。
'''
io.open(P, "w", encoding="utf-8", newline="").write(s)
print("memory updated")
