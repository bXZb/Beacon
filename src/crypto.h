#pragma once
/* 加密/编码薄抽象层（P4.15）
 *
 * 边界约定：tomcrypt.h 只允许被两个实现单元包含——
 *   - crypto.cpp     （base64 编解码、随机数源注册）
 *   - security.cpp   （会话 AES/HMAC、元数据 RSA；协议语义见 docs/WIRE-PROTOCOL.md）
 * 其余代码一律经由本头文件，底层库替换时不再牵动调用方。 */

/* 状态码：与底层库解耦。数值沿用 LibTomCrypt，便于实现层直通。 */
#define CRYPTO_OK                0
#define CRYPTO_ERROR            -1
#define CRYPTO_BUFFER_OVERFLOW  -3   /* 输入超长/输出缓冲不足 */

/* base64（标准字母表）。outlen 为入出参数：入=输出缓冲容量，出=实际长度。
   返回 CRYPTO_OK 或负错误码。URL 安全变体由 encoders.cpp 在其上实现。 */
int crypto_base64_encode(const unsigned char * in,  unsigned long inlen,
                         unsigned char * out,       unsigned long * outlen);
int crypto_base64_decode(const unsigned char * in,  unsigned long inlen,
                         unsigned char * out,       unsigned long * outlen);

/* 初始化加密层：注册 OS 随机数源（ProcessPrng，Win10 1809+；
   不可用时回退 CryptGenRandom）。返回可用于加密原语的 prng 索引。
   幂等，可重复调用。 */
int crypto_init(void);

/* 取 OS 随机字节（无状态）。返回实际写入字节数，失败返回 0。
   替代原 LTC rng_get_bytes（后者要求已注册的 PRNG 描述符）。 */
unsigned long crypto_rng_get_bytes(unsigned char * out, unsigned long outlen);
