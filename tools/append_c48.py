# -*- coding: utf-8 -*-
"""append_c48.py - append C-48 to c41 memory file."""
import io

P = (r"C:\Users\Administrator\.zcode\cli\memories\projects"
     r"\cobaltstrike-646a8c99d4ff867a\memory\c41-ecosystem-compat-tests.md")
s = io.open(P, encoding="utf-8").read()

s += '''

**C-48（2026-11-18 凌晨）IEA 杀 beacon 根因收敛**：
- **kill 4 次不复现**（df2e806 同构建：2 beacon × 各 2 派发，cdb 上下都
  存活）→ test-3 的 kill=非确定性（时序/状态竞态），"CLR 宿主冲突"归因
  需新复现才能续挖；换 beacon 重部署后 cdb 附着污染进程 debug 端口
  （Stop-Process 杀 cdb 不干净 → 再附着 Win32 0x87）。
- **静默退出行级铁证**：TestAssembly 文件标记版（csc 写 iea_ran.txt）×3
  无标记 + IEA 零输出 → StartCLR 失败路径（`if (success != 1) return;`
  无任何输出）——CLR 从未执行。参数契约核对（z+5i+3z+i+b，mailSlot=0，
  无 EXITFUNC 参数——排除 ExitFunc 致死）；动态导入 26 个 < 32 槽池。
- **输出契约缺口（代码证实）**：我方 beacon 零 obpipe/obslot 引用
  （唯一 CreateNamedPipeA=identity.c pivot 用），InlineExecuteObject 同步
  直调无管道读端 → IEA 输出腿永断（test-3 DNS beacon "无输出"同因）。
  新工作项=beacon 侧管道读端契约。
- **工具坑**：CLRCreateInstance 导出在 mscoree 非 ole32（bp 写 ole32 永远
  deferred）；python Popen 启 cdb=initial break 时 stdin EOF 退出（须 bash
  nohup </dev/null）；TestAssembly 文件标记法=旁路输出腿的 CLR 执行
  判定器。
- 下轮：fresh beacon 单 cdb 全程 + bp mscoree!CLRCreateInstance 拿
  HRESULT；官方 beacon + iea 对照判别。ts 85d04f5。
'''
io.open(P, "w", encoding="utf-8", newline="").write(s)
print("C-48 appended")
