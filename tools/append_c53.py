# -*- coding: utf-8 -*-
"""append_c53.py - append C-53 (dev-era console output silencing) to c41 memory."""
import io

P = (r"C:\Users\Administrator\.zcode\cli\memories\projects"
     r"\cobaltstrike-646a8c99d4ff867a\memory\c41-ecosystem-compat-tests.md")
s = io.open(P, encoding="utf-8").read()

s += '''

**C-53（2026-11-20）两条开发期 console 输出静音（用户观察 web-client 后提出）**：
- 三条消息全查清=我们自己 beacon 代码的"特性级诊断"非失控 debug：
  ①`udc2 probe: len=0 entry=0`=beacon_udc2.cpp 启动探针（非 UDC2 beacon
  报 error-96 确认，每生命周期一次）②pwd=部署脚本验证任务（时间撞车）
  ③`bofwin skipped (api/nook/threads`=BOF 掩码窗门诊断（条件不满足走
  fallback 的正常路径提示，每 BOF 一次）
- **静音 2 处**（逻辑/fallback 全保留）：beacon_udc2.cpp 删
  post_error_na(96)；boff.cpp 删 "bofwin skipped" callback（window
  served/declined 保留——默认配置不触发）。commit 6d4fb7f 已推
  bXZb/Beacon，CI 44569596039 构建成功。
- **sleeve 换槽全流程**：encrypt_sleeve.py 是硬编码路径模式（读
  src resources 明文 → 加密回写）→ 明文 DLL 放 src/resources/sleeve →
  跑加密 → shadowJar → 部署。新 beacon 1601234390 验证：**DEV-MSGS
  REMAINING: 0** + pwd/BOF 回归全绿。ts 63d2256。
- 注意：encrypt_sleeve.py 跑完会把 src resources 的 sleeve 变成加密态
  （再跑会 skip）——这是预期状态，构建管线直接吃加密资源。
'''
io.open(P, "w", encoding="utf-8", newline="").write(s)
print("C-53 appended")
