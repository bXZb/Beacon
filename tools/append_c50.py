# -*- coding: utf-8 -*-
"""append_c50.py - append C-50 to c41 memory file."""
import io

P = (r"C:\Users\Administrator\.zcode\cli\memories\projects"
     r"\cobaltstrike-646a8c99d4ff867a\memory\c41-ecosystem-compat-tests.md")
s = io.open(P, encoding="utf-8").read()

s += '''

**C-50（2026-11-18 上午）IEA 全链贯通（官方+我方 beacon 双 FULL PASS）**：
- **官方 beacon 上线（C-49 crash 解）**：rundll32 crash = RL export 错误
  入口；官方真契约 = flat copy + 执行 blob[0]（MZAR DOS 桩=引导码）。
  probe_runner 喂 stock 处理官方 DLL → INITIAL 790400446 + pwd PASS。
- **判别**：官方 beacon iea 也哑 → TS 侧实锤。
- **TS 真 bug ×2 全修**：① cna 用错函数——`binline_execute`（file 桥）
  只读 file+entry 丢第 4 参 bofArgs（args="go\0"）→ 改
  `beacon_inline_execute`（UserSpecifiedFull 全传）；②
  **OBJExecutable 不支持 MSVC COMDAT**——OBJParser 重复段名改名
  ".rdata$44" 撞 MSVC 真分节语法 → ??_C@ 字面量 Unknown symbol；且
  单段 carve/段内偏移在多段全错。修复 6 处：familyRoot 归一+
  buildFamilies 六族合并（.text/.rdata/.data/.xdata/.pdata/.bss，
  文件序+famBase 基表）+五访问器读合并流+getRelocSection root 比较+
  reloc 循环 root 归类（r_vaddr=宿主族基+段内，e_value=符号段族基+
  段内）+entry 加符号段族基。单段 mingw 全基=0 零回归（实测）。
- **验证矩阵全绿**：官方 beacon IEA=CLR 执行（文件标记+管道输出回传
  IEA-TEST-OK/Finished+17805B 下行+存活）；我方 beacon 294650156 同
  FULL PASS；ajpc mingw 回归 7 输出零回归。
- **战线总结账**：C-48"杀 beacon"=非确定性竞态（维持）；"无输出"=
  args 丢弃+MSVC COMDAT 双 bug（全修）。obpipe 输出环实证（C-49 撤销
  结论正确）。**我方 TS 对官方 beacon+MSVC/mingw 双系 BOF 完整兼容**。
- 工具：coff_anatomy2.py（COFF 解剖，节头 IIIIIIHH）、patch_objexec.py、
  外科 jar ×2（官方/我方 sleeve 版各带双修复类）。
- ts b7e429a。
'''
io.open(P, "w", encoding="utf-8", newline="").write(s)
print("C-50 appended")
