# -*- coding: utf-8 -*-
"""append_c54.py - append C-54 (KDEBUG gate + probes) to c41 memory."""
import io

P = (r"C:\Users\Administrator\.zcode\cli\memories\projects"
     r"\cobaltstrike-646a8c99d4ff867a\memory\c41-ecosystem-compat-tests.md")
s = io.open(P, encoding="utf-8").read()

s += '''

**C-54（2026-11-20）KDEBUG 编译期门控 + 开发噪音审计收官**：
- **审计**：beacon 201 console 点+250 spawn_log+**4 个目标机 trace 文件**
  （spawn_trace/bof-loadtrace/beacon-crashdiag/gen3_trace，行为级 IOC）
  +错误码 96/97/98 族；TS 104 System.out（运维面无 beacon 直出）；Python
  良好。三分类=删（always-fire 探针）/门控（战斗调试 sink）/保留（真错误）。
- **KDEBUG 方案落地**（beacon.vcxproj BeaconKDebug=true→KDEBUG 宏，同
  BeaconBofWin 管道）：4 sink 全 #if KDEBUG 门控（release 零文件 IO）；
  release 保符号 stub（外部 caller 链接）或 no-op 宏（boftrace/g3_log）；
  beacon.h KD/KDF/KDGEN3 宏桩。**CI 六轮修**（boftrace 标识符/杂散
  #endif/extern C 链接三连：spawn_trace.h extern "C" × beacon.h 声明块
  也要 extern "C" 包裹——channel_doh.c 是 C TU 用 _spawn_log 符号）。
- **删探针**：post_error_dd(96 loaded-OK)+post_error_dd(98 UDC2STORE)
  ——与 C-53 同族 always-fire。
- **二进制级+活体验证**：release DLL grep 零 trace 字符串/kdebug DLL
  全带；release beacon 1777556348 部署后 4 文件零存在+pwd/BOF 绿；
  CI 新产物 beacon-kdebug-x64（排查战斗用）。
- beacon 26df59a（6 轮）/ts b1ad741。sleeve 560160/565792。
'''
io.open(P, "w", encoding="utf-8", newline="").write(s)
print("C-54 appended")
