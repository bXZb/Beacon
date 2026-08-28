# vendored 预编译依赖库

| 文件 | 来源 | 配对头文件 |
|---|---|---|
| `tomcrypt.x64.lib` | 预编译 LibTomCrypt（x64 Release /MT），经 vcpkg 获取构建，随本仓库直接分发 | `tomcrypt-headers/`（**LTC 1.17**，CRYPT=0x0117） |
| `tommath.x64.lib` | 预编译 LibTomMath（x64 Release /MT），1.2.x/1.3.x 结构（`bn_cutoffs.c` 全局 cutoff 变量） | 内建于 lib |

## 重要约束

1. **头文件是 LTC 1.17**：`tomcrypt-headers/tomcrypt_custom.h` 等为 1.17 结构。
   1.18+ 的 ABI 有差异（`ltc_asn1_type` typedef、`LTC_ASN1_RAW_BIT_STRING`、
   `CRYPT_INPUT_TOO_LONG` 等），替换头文件必须同步替换 lib，反之亦然。
2. **链接方式**：`common.props` 已把 `$(ProjectDir)lib` 加入 `LibraryPath`，
   工程经 `#pragma comment(lib, ...)` 或链接器输入解析；x64 构建只链这两个 .lib。
3. **x86/ARM 构建无库**：本仓库的 `lib/` 只有 x64 版本。Release|Win32/ARM 配置
   属于历史遗留（原始仓库布局），当前仅维护 Release|x64（见 BUILD.md）。
4. **替换 lib 的验收**：任何重新分发/重编的 lib 必须通过 `tests/` 下的协议
   golden 测试（P3.12），并核对 MAP 文件中 RSA 路径函数
   （`rsa_import`/`rsa_exptmod` 或 `rsa_encrypt_key_ex`/`pkcs_1_oaep_encode`）存在。

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
