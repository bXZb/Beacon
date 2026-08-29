# thirdparty：LibTomCrypt / LibTomMath 精简重编（P4.16）

> 状态：**配方与 CI 流水线就绪**。手动触发 GitHub Actions 的 `trimlib`
> workflow（Actions 页 → trimlib → Run workflow）即可在 CI 完成拉源码、
> 精简构建、测试验收、产物上传的完整闭环——不依赖本机工具链。

## 为什么重编

vendored 库（实为 **LTC 1.18.2**，见 `lib/VERSIONS.md` 的取证结论）按默认
配置构建，链接进 beacon 的 crypto .text 中有大量 beacon（RSA-1024 only）
**永不执行**的代码：

| 死代码 | 规模 | 为什么死 |
|---|---|---|
| `ltc_ecc_*`（点运算 + 曲线表） | ~7KB | beacon 不做 ECC；唯一引用是描述符死指针 |
| keygen + 素数测试链（`rsa_make_key`/`rand_prime`/lucas/miller_rabin 等） | ~6.5KB | beacon 只导入公钥加密；且该路径在 vendored lib 中疑似内存破坏（CI 实证，见 VERSIONS.md） |
| DH/DSA/ECC 等 PK 分支 | 数 KB | 精简配置下根本不参与编译 |
| 其余密码/哈希/模式/MAC | 数十 KB | 同上 |

库源码层禁用（宏）比链接期符号桩干净：死代码不参与编译，无 LNK2005
"co-contained symbol" 风险。

## 使用

1. **触发**：GitHub → Actions → **trimlib** → Run workflow。
2. **构建内容**：
   - LTC `v1.18.2` + `thirdparty/tomcrypt_custom_min_1182.h`
     （仅 AES/CBC/ECB/SHA256/HMAC/BASE64/MRSA/DER；PRNG 全禁用——运行时由
     `src/crypto.cpp` 注册 `processprng`）；
   - LTM `v1.3.0` 原样。
3. **验收**（workflow 内自动执行）：用重编库编译并运行 `tests/` 全套 +
   **keygen 探针**（`BEACON_TEST_ENABLE_KEYGEN`，同时复核 vendored lib 的
   keygen 缺陷是否为构建产物问题）。
4. **产物**：artifact `trimmed-libs`（两个 .lib）+ 体积汇总。验收通过后
   人工决定替换 `lib/` 下 vendored 库（同时更新 `lib/VERSIONS.md`）。

本机想复现：VS Developer Command Prompt 下运行
`thirdparty/build_trimmed.ps1 -Proxy http://127.0.0.1:10808`（代理可选）。

## 版本纪律

- **头/库必须同版本**：本次排障的直接教训（1.17 头 + 1.18.2 lib 的
  `rsa_key` 布局错配导致栈破坏）。重编库与上游 v1.18.2 头文件配对，
  仓库 `tomcrypt-headers/` 已是 1.18.2 ✓。
- 替换 `lib/` 后必须跑全套测试（27 项 + keygen 探针）并核对 MAP 中
  RSA 路径函数存在、ECC/素数链不存在。
