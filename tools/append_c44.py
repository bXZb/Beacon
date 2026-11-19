# -*- coding: utf-8 -*-
"""append_c44.py - append C-42/43/44 to c41 memory file."""
import io

P = (r"C:\Users\Administrator\.zcode\cli\memories\projects"
     r"\cobaltstrike-646a8c99d4ff867a\memory\c41-ecosystem-compat-tests.md")
s = io.open(P, encoding="utf-8").read()

s += '''

**C-44（同日晚）R2 测试轮启动 + 官方基准切换（用户指示）**：
- **R2-1 Cobaltstrike_BOFLoader 交叉验证 PASS**：CodeXTF2 ⭐74 声称 1:1
  复刻官方 loader——MSVC CI 构建 + bof_pack.py 打包 8 个我方 CI BOF 喂
  它执行，结果与我方 beacon 逐项一致（FindModule/FindProcHandle/KerbHash
  成功、Klist/Domaininfo/Smbinfo 走完、AD error 53/参数 underflow 一致）
  → **我方 BOF loader 语义与 1:1 复刻无分歧**。
- **R2-2 AceLdr CI 构建绿**：上游 mingw/GCC 项目（__typeof__/packed/
  .text$ SECTION），MSVC 适配 3 轮放弃→ubuntu mingw+nasm 构建成功
  （AceLdr.x64.bin 16893B）。注意：-i 重定位链接不支持 --gc-sections
  根符号（-u/-e 无效），直接 drop。部署验证（cna aceldr 命令已入：
  payload 桥接 DLL + loader 拼接 + bdll_spawn）下轮跑。
- **官方 4.9.1 DLL 对照 PASS（用户指定基准）**：官方 src/sleeve
  beacon.x64.dll（解码版 305696B）→ probe_baked 替换 → own-exe →
  INITIAL 1047984458 + pwd True。**我方 TS ↔ 官方 beacon 双向兼容闭环**。
  注意：官方 jar 的编码 sleeve key≠CrackSleeve key，须 decode→re-encode。
- **勘误（用户质疑成立）**：测 1 的 3 个"深层 bug"全是我方 glue 自身
  缺陷/失误（transform->parser 是我方没抄全、loader-lock 是我方
  ObStart 写法、pubkey 是手抄错），非 OpenBeacon 上游问题。OpenBeacon
  作为基准退役（保留 vendor 供参考）。
- ts bfc5fce / beacon 0f2eb72。
'''
io.open(P, "w", encoding="utf-8", newline="").write(s)
print("C-44 appended")
