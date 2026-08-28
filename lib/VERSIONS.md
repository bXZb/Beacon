# vendored 预编译依赖库

| 文件 | 来源 | 配对头文件 |
|---|---|---|
| `tomcrypt.x64.lib` | 预编译 LibTomCrypt（x64 Release /MT），经 vcpkg 获取构建，随本仓库直接分发 | `tomcrypt-headers/`（1.17 原版 + **ABI 修正**，见下） |
| `tommath.x64.lib` | 预编译 LibTomMath（x64 Release /MT），1.2.x/1.3.x 结构（`bn_cutoffs.c` 全局 cutoff 变量） | 内建于 lib |

## 版本实证（CI 调试 2026-08-29 修正）

**`tomcrypt.x64.lib` 实为 LTC 1.18.2 构建**——二进制内嵌版本串 `"1.18.2"`，
且含 1.18 独有符号 `rsa_get_size`；而仓库原有头文件是 1.17。两者错配的
后果：1.18 的 `rsa_key` 末尾多一个 `size_t qS`（72→80 字节），库函数按大
结构体写入调用方栈上按 1.17 布局声明的 `rsa_key` 时会踩掉 8 字节——
/GS 环境下函数返回即 `0xC0000409`。

处置：`tomcrypt-headers/` 保留 1.17 原版内容并做**布局级 ABI 修正**
（`rsa_key` 补 `qS` 字段；`CRYPT`/`SCRYPT` 版本宏更正为 0x0118/"1.18.2"）。
1.17→1.18 其余被 beacon 用到的结构（`ltc_asn1_list`、`ltc_prng_descriptor` 等）
布局兼容。完整换用正版 1.18.2 头文件/重编库见 `thirdparty/README.md`。

## 重要约束

1. **头/库必须成对替换**：布局级修正只覆盖已实证的差异；换 lib 必须同步
   审查头文件，反之亦然。
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
