# -*- coding: utf-8 -*-
"""append_c46.py - append C-46/C-47 to c41 memory file."""
import io

P = (r"C:\Users\Administrator\.zcode\cli\memories\projects"
     r"\cobaltstrike-646a8c99d4ff867a\memory\c41-ecosystem-compat-tests.md")
s = io.open(P, encoding="utf-8").read()

s += '''

**C-46/C-47（2026-11-18 凌晨）R2-2/R2-4 部署活测双 FULL PASS**：
- **R2-2 AceLdr PASS**：三连根因（bdll_spawn 函数名不存在；官方 Makefile
  有 extract.py 从 exe 按 ACELDR 标记提取裸 bin——上轮直接拿 PE 当 bin
  形状全错；probe_runner 宿主须 Sleep(INFINITE) 驻留——AceLdr Start 返回
  设计如此，"首检后消失"是宿主退出假象非崩溃）。官方 mingw gcc 旗标
  全套复刻 → AceLdr.x64.bin 7323B 裸引导码。GENERATE 钩子加 prepend
  分支（$g_aceldr 旗标，blob=$ldr.setup_strings($2)）→ probe_runner
  （flat RWX+thread(blob[0])）→ 子 beacon INITIAL+pwd+多 sleep 周期
  HEART 稳定。
- **R2-4 Titan PASS**：上轮 CI 假绿=任务名错（真实任务 x64 非
  build-x64）+||true 吞错+缺 OBJCOPY_X64/nasm。真 bug（vendor patch）：
  Titan 硬编码 stomp d3d10.dll，.text 0.9MB < 我方 beacon SizeOfImage
  3.9MB（rl0k sleeve 真实值）→ 补丁=stomp 候选列表（d3d10warp 5.8MB/
  windows.storage/shell32/d3d10 兜底）。debug 变体 dbg_print 轨迹拿铁证
  （18 步装载链全绿）→ 子 beacon INITIAL 1142886620+pwd+多周期稳定。
- **通用方法论沉淀**：prepend 式 UDRL（AceLdr/Titan 同范式）= hook 里
  $ldr.setup_strings($2)（Titan 多一层 pack('I+',BE)+RC4(DLL) 20B 头），
  probe_runner=CreateFileA→VirtualAlloc RWX→copy→CreateThread(blob[0])→
  Sleep(INFINITE)；debug 变体（dbg_print）先跑拿轨迹再查 release；
  G_END=GetIp+11 语义两 loader 同源；.cna 无 BOM（utf-8-sig 写回会炸，
  memory 旧坑重踩一次）。
- **坑账**：SizeOfImage 解析偏移=NT+24+56（e_lfanew+0x50）；CI yaml 里
  cl 的 /Fo 附着空格吞字（chr 拼接heredoc 三炸）；Sleep 'I+' pack=大端。
- ts 0c08eb4 / beacon 推进中。
'''
io.open(P, "w", encoding="utf-8", newline="").write(s)
print("C-46/C-47 appended")
