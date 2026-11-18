# -*- coding: utf-8 -*-
"""append_c49.py - append C-49 to c41 memory file."""
import io

P = (r"C:\Users\Administrator\.zcode\cli\memories\projects"
     r"\cobaltstrike-646a8c99d4ff867a\memory\c41-ecosystem-compat-tests.md")
s = io.open(P, encoding="utf-8").read()

s += '''

**C-49（2026-11-18 上午）IEA 上游收敛 + TS 真 bug + C-44 假阳性揭露**：
- **mscoree!CLRCreateInstance bp 判决**：bp 正常挂上但 iea 派发后从未
  触发 + beacon 进程无 mscoree/clr 模块 → **BOF 根本没跑到 CLR**，
  问题上移到 TS 任务管线。
- **TS 真 bug（已修）**：`BeaconPayload.patchSleepMaskString` 占位串
  （SSSSLLLLEEEEPPPPMMMMAAAASSSSKKKK）在官方 DLL 缺失 → indexOf=-1 →
  replaceAt(-1) OOB → **官方 DLL 走 exportBeaconStage 全链崩**。修复 =
  n<0 guard。注意：全量 gradlew 重建的 jar 官方 sleeve 解码行为漂移
  （e_magic 64310），改用**外科 jar 法**（bak_our 已知好 jar + 单类
  BeaconPayload.class 替换）→ 稳定。
- **C-44 假阳性揭露（重要勘误）**：python 复刻 SleeveSecurity
  （AES-CBC/NoPadding IV=abcdefghijklmnop，key=SHA256(key16)[:16]，
  明文=[4B rand][4B len][data]['A' 填充]+HMAC-SHA256 tag 前 16B）解码
  C-44 的 .enc → 解出 = src/sleeve = **官方编码形态非 MZ** → C-44 的
  EncodeOne 没先解码 = 双重编码 → C-44 exe 实际含我方 DLL →
  **"官方 DLL 对照 PASS（1047984458）"是假阳性，双向兼容结论撤销**。
  真解码版 = CrackSleeve4.9/Resource/Decode/sleeve/（571392B MZ）。
- **正确 .enc 产出（encode_official.py）+ 管线首通**：正确官方 .enc →
  外科 jar → **TS boot 监听器 0 失败（官方 sleeve 首次在我方 TS 完整
  解码）** → nohook 模式（SIZE=5 + GENERATE passthrough）→ probe_baked
  = 571392B stock 处理官方 DLL（MZAR+桩+settings，官方 DLL 首次走通
  我方生成管线）。
- **官方 stock RL crash（下轮主攻）**：交付即死，rundll32+cdb 抓到
  `official_beacon!ReflectiveLoader+0x1006 rep movs [rdi],[rsi]` 节拷贝
  AV——stock RL 自定位假设与我方交付形态（LoadLibrary 映射/flat copy）
  不匹配。下轮：cdb 比 own-exe+官方 DLL 寄存器，或按官方 artifact64.exe
  stub 契约交付（flat copy + MZAR 桩入口）。
- **obpipe 契约撤销（C-48 前提勘误）**：IEA 源码行级确认自含输出环
  （server+client+SetStdHandle+自读+回传）——beacon 侧无需管道读端。
- 工具：decode_enc.py/encode_official.py（SleeveSecurity python 复刻）、
  surgical_jar.py（已知好 jar+单类替换）、nohook 管道模式。
- ts 0b74119 / beacon 推进中。
'''
io.open(P, "w", encoding="utf-8", newline="").write(s)
print("C-49 appended")
