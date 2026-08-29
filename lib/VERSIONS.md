# vendored 预编译依赖库

| 文件 | 来源 | 配对头文件 |
|---|---|---|
| `tomcrypt.x64.lib` | **本仓库自研精简重编**（LTC 1.18.2 + `thirdparty/tomcrypt_custom_min_1182.h`，clang-cl /O1，CI trimlib 流水线产物；2026-08-29 由 vendored 库替换而来） | `tomcrypt-headers/`（**上游原版 1.18.2 头文件**） |
| `tommath.x64.lib` | **本仓库自研重编**（LTM 1.3.0 原样，clang-cl /O1） | 内建于 lib |

## 重编库验收结论（2026-08-29，trimlib run 33232506933）

- 28/28 测试通过，**含 keygen 探针**：干净重编的 1.18.2 keygen 路径健康，
  坐实此前 keygen 缺陷为 vendored 库构建产物问题；
- 精简配置下 ECC/DH/DSA/其余密码哈希/内置 PRNG 不参与编译，
  beacon 链接面显著缩小（配合 src/ 下的 CRT 瘦身组件）；
- PRNG 全禁用：运行时由 `src/crypto.cpp` 注册 `processprng`（ProcessPrng →
  CryptGenRandom 回退）。

## 历史取证存档

**原 vendored `tomcrypt.x64.lib` 实为 LTC 1.18.2 构建**——二进制内嵌版本串
`"1.18.2"` + 1.18 独有符号 `rsa_get_size`；而仓库原有头文件是 1.17，错配导致
`rsa_key` 布局差 8 字节（`size_t qS`）、栈上声明被写穿（/GS 下 0xC0000409）。
该库已被上述自研重编库替换；`tomcrypt-headers/` 为上游 v1.18.2 原版。

## 重要约束

1. **头/库必须成对替换**：换 lib 必须同步审查头文件版本，反之亦然。
2. **链接方式**：`common.props` 已把 `$(ProjectDir)lib` 加入 `LibraryPath`，
   工程经 `#pragma comment(lib, ...)` 或链接器输入解析；x64 构建只链这两个 .lib。
3. **x86/ARM 构建无库**：本仓库的 `lib/` 只有 x64 版本。Release|Win32/ARM 配置
   属于历史遗留（原始仓库布局），当前仅维护 Release|x64（见 BUILD.md）。
4. **替换 lib 的验收**：任何重新分发/重编的 lib 必须通过 `tests/` 下的协议
   golden 测试（含 keygen 探针），并核对 MAP 文件中 RSA 路径函数存在。

## 已知缺陷（CI 实证 2026-08-29）

**大指数模幂路径触发 0xC0000409 fastfail**：`rsa_exptmod(PK_PRIVATE)`（CRT 分支）
乃至普通 `mp_exptmod(c, d, N)`（1024 位私钥指数）在本库上必崩；公钥运算
（e=65537）与密钥生成正常。beacon 生产路径只导入公钥加密，**不受影响**；
tests 中私钥侧验证因此改为分段验证（编码器结构 + 公钥模幂）。
该缺陷也是 `thirdparty/` 精简重编的直接动机之一：重编库落地后应恢复
完整私钥解密回路测试。

## 重编精简版（P4.16，待源码）

`thirdparty/` 下备有精简重编配置与获取脚本（`thirdparty/README.md`）。
目标：`LTC_NO_ECC` 等宏直接编掉死代码，使链接期符号桩方案成为不必要。
