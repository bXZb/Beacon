# thirdparty：LibTomCrypt / LibTomMath 精简重编（P4.16）

> 状态：**配方就绪，等待在有网环境执行**（本仓库工作机无网络，无法拉取源码）。
> 完成后，`lib/` 下的预编译库替换为本目录构建的精简库，"链接期符号桩"方案
> （往符号表塞空实现骗 /OPT:REF 拔死代码）即不再必要。

## 为什么值得做

当前 vendored 库按默认配置构建，链接进 beacon 的 crypto .text 约 70-90KB，
其中 beacon（RSA-1024 only）**永远不会执行**的部分：

| 死代码 | 规模 | 为什么死 |
|---|---|---|
| `ltc_ecc_*`（5 个点运算函数 + 依赖） | ~7KB | beacon 不做 ECC；唯一引用是 ltm_desc 描述符里 5 个从不调用的函数指针 |
| `rsa_make_key` + `rand_prime` + 素数测试链（lucas/miller_rabin/is_square/kronecker/is_divisible） | ~6.5KB | beacon 只导入硬编码公钥加密，无 keygen；唯一引用同样是描述符死指针 |
| toom 大数快路径（`s_mp_toom_mul/sqr`） | ~2.5KB | dispatch 的静态分支，RSA-1024 limb 数（≤128）远低于 cutoff（350），结构不可达 |
| 证书类 DER 解码器（utctime/generalizedtime/各 string 类型，经 sequence_ex switch） | ~8KB | SPKI 解析只需 SEQUENCE/INTEGER/OID/NULL/BIT_STRING |

在**库源码层**禁用它们（宏 + 少量源码补丁），比链接期桩干净得多：
死代码根本不参与编译，无 LNK2005 "co-contained symbol" 风险，无 lib 版本漂移风险。

## 步骤

1. **拉源码**（版本必须与 `tomcrypt-headers/` 一致——**LTC 1.17**，头文件 CRYPT=0x0117；
   LTM 用 1.3.0，与 vendored lib 的 `bn_cutoffs.c` 结构一致）：

   ```
   git clone --branch v1.17 https://github.com/libtom/libtomcrypt
   git clone --branch v1.3.0 https://github.com/libtom/libtommath
   ```
   或直接运行 `fetch_and_build.ps1`。

2. **套精简配置**：用 `tomcrypt_custom_min.h` 覆盖 libtomcrypt 源码树的
   `src/headers/tomcrypt_custom.h`。关键差异：
   - 去掉 `LTC_MECC`（ECC 整体不编译）
   - 去掉 `LTC_NO_PRNG` 相关默认，保留我们自己的注入（beacon 经 crypto.cpp
     注册 ProcessPrng 描述符，**不再需要 sprng** → 去掉 `LTC_SPRNG`）
   - `LTC_NO_TEST`、`LTC_NO_FILE`（beacon 无文件系统熵/自测需求）
   - 保留：`LTC_MRSA`（RSA 加密路径必须）、AES/SHA256/HMAC/base64

3. **源码补丁**（宏管不到的三处，见 `patches/`）：
   - `ltm_desc.c`：描述符里 `isprime`、5 个 ECC 函数指针、`rsa_make_key` 字段
     指向库内新增的空实现（或直接置 NULL，需同步改 ltc_math_descriptor 的
     调用方判空——beacon 路径从不调用，置 NULL 即可）
   - `tommath`：`mp_mul/mp_sqr` 的 toom 分支由 cutoff 常量守卫，源码层把
     `TOOM_MUL_CUTOFF/TOOM_SQR_CUTOFF` 提到不可能值（如 INT_MAX）即可让
     编译器/链接器保留 Comba 路径、丢弃 toom 对象

4. **构建**（MSVC，x64）：

   ```
   libtommath:     nmake -f makefile.msvc
   libtomcrypt:    nmake -f makefile.msvc   （需先应用第 2/3 步）
   ```
   注意 64 位 cl（HostX64）——32 位 cl 编 tomcrypt 模板会 C1060。

5. **替换与验收**（缺一不可）：
   - `lib/tomcrypt.x64.lib`、`lib/tommath.x64.lib` 换成新产物，更新 `lib/VERSIONS.md`
   - `tests/run_tests.ps1` 全绿（重点：RSA 元数据回路、SHA256/HMAC golden——
     精简版 lib 不得破坏任何 golden）
   - 构建 beacon 后检查 MAP：`ltc_ecc_*`、`bn_mp_prime_*`、`s_mp_toom_*`、
     `der_decode_utctime` 等 .obj **不存在**；`rsa_import/rsa_exptmod/
     s_mp_montgomery_reduce_fast` **存在**
