# x64 sleep_mask BOF 反馈（模板）

接手会话写这里。不要改 `SLEEP-MASK-HANDOFF.md`。

---

## 元数据

| 项 | 值 |
|---|---|
| 日期 | |
| commit / CI | |
| overlay 编码头 / 明文体积 | |
| profile | `r2_winhttp_sm` / 测完是否 `r2_nosm` |
| 子 bid / pid | |
| CHECKIN 字节 | |
| reloc type 3 次数 | |
| 第二次 CHECKIN / pwd | 是 / 否 |
| `sm_gparms.txt` mtime | |
| heap 是否仍含 sections 指针 | |

## 结论

- [ ] **已过**：60s 内二次 CHECKIN + pwd，reloc=0 或仅 pdata 相关且 BOF 返回
- [ ] **仍挂**：卡点现在认为是（XOR 段 / XOR 堆 / Sleep ecx / 其它）
- [ ] 空表对照结果：

dump 或对照摘录：

```
```

## 给原会话（三条以内）

1.
2.

## 核对

- [ ] 未把 rcx 改成 `BEACON_INFO*`
- [ ] 未重开 Gate / cmd 117 / `http_flush_post`
- [ ] 过线后已删 Public dump；未过线则套筒已改回 `44161e2` 或等价不 invoke 构建
- [ ] TS 已 `r2_nosm`
