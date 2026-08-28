# C2 线缆协议（加密层）规格

> 本文描述的字节级约束在 `tests\test_crypto.cpp` 中有对应测试——
> **本文与该测试文件共同构成协议的权威定义**，两者不一致以测试为准。
> golden 向量由独立实现（Python hashlib/hmac）离线计算，防止依赖库静默回归。

## 1. 配置 blob（settings）

TeamServer patch 进 beacon 二进制的 `myargs[4096]` 数组（`settings.cpp`），
整包经 **XOR 0x2E** 掩码存储：

```
settings := entry* zero-terminator
entry    := u16 index | u16 type | u16 length | payload
type     := 1 = u16 (网络序)   2 = u32 (网络序)   3 = 定长字节串(length)
index    := 1..127；0 表示列表结束
```

读取接口：`setting_short/setting_int/setting_ptr`（类型不符返回零值）。
可执行规格：`tests\test_settings.cpp`。

## 2. 会话密钥派生

```
key_bucket = SHA-256(session_key[0..16])     # 32B
aes_key    = key_bucket[0..16]
hmac_key   = key_bucket[16..32]
```

golden：`SHA-256("0123456789abcdef")`
= `9f9f5111 f7b27a78 1f1f1ddde5ebc2dd 2b796bfc 7365c9c2 8b548e56 4176929f`。

## 3. 回传帧（beacon → TS）

```
frame := AES-128-CBC(aes_key, iv="abcdefghijklmnop", pad(frame_body)) || mac
mac   := HMAC-SHA256(hmac_key, pad(frame_body))[0..16]      # 截断 16B
frame_body := 应用层数据（含 4B 任务相关头，由调用层定义）
pad    := 长度补齐到 16 的倍数（注意：security_encrypt 仅扩展长度，
          填充字节内容未定义——加密前缓冲区必须预留足够容量）
```

## 4. 下发帧（TS → beacon）

```
plaintext := u32 counter | u32 len | payload[len]
wire      := AES-128-CBC(...) || mac            # 同上，iv 固定 "abcdefghijklmnop"
```

- `counter` 为单调值，防重放容差 **3600**：`counter + 3600 <= lastcounter`
  视为重放，`security_decrypt` 返回 0（软失败，beacon 继续运行）；
- HMAC 不匹配同样返回 0（软失败）；
- 解出的 payload 就地拷贝回调用缓冲区，返回 payload 长度。

可执行规格：`tests\test_crypto.cpp`（roundtrip / 篡改拒绝 / 重放拒绝）。

## 5. 元数据加密（首个 checkin 的会话材料上送）

```
metadata_ct := RSA-1024-PKCS#1-v1.5(pubkey_spki162, session_material, lparam="Zz")
```

- 公钥：**162 字节** SPKI DER（X.509 包壳，RSA-1024 的标准形状），
  取自 settings 的 `SETTING_PUBKEY`(7)；
- 明文 ≤117B（128 - 11 PKCS#1 v1.5 最小填充），CS 实际放 32B 会话密钥材料；
- 密文恒 128B；
- 162B SPKI 的 DER 形状（`tests\test_crypto.cpp::build_spki_162` 逐字节构造）：

```
30 81 9F                         SEQUENCE (159B)
  30 0D                          SEQUENCE (AlgorithmIdentifier)
    06 09 2A 86 48 86 F7 0D 01 01 01     OID rsaEncryption
    05 00                        NULL
  03 81 8D 00                    BIT STRING (141B, 0 unused bits)
    30 81 89                     SEQUENCE (RSAPublicKey)
      02 81 81 00 || mod[128]    INTEGER (前导 0x00 + 128B 模数)
      02 03 01 00 01             INTEGER (e = 65537)
```

实现入口：`security.cpp::rsa_encrypt_once`（运行时只导入公钥，无 keygen）。

## 6. 编码辅助

标准 base64 由 `crypto_base64_encode/decode` 提供（RFC 4648 参考向量已测）；
URL 安全变体（`-`/`_` 字母表）由 `encoders.cpp::base64url_*` 在其上转换实现。

## 7. 随机数源

`crypto.cpp` 注册 `processprng` 描述符：优先 `ProcessPrng`（Win10 1809+），
回退 `CryptGenRandom`。原 LTC `sprng` 不再使用。
