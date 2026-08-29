#ifndef TOMCRYPT_CUSTOM_H_
#define TOMCRYPT_CUSTOM_H_

/* 精简版 tomcrypt_custom.h —— 基于 LibTomCrypt **v1.18.2** 原版派生（P4.16）。
 *
 * 与旧版 1.17 精简头的差异：1.18 的 base64 归入 LTC_NO_MISC 段、PRNG 新增
 * CHACHA20/TRY_URANDOM_FIRST/LTC_RNG_GET_BYTES 等宏、PK 段新增 MDH/DH* 宏。
 *
 * 保留：AES(RIJNDAEL) + ECB/CBC + SHA256 + HMAC + BASE64 + MRSA(+blinding/
 * CRT hardening) + DER。其余全不编译：ECC/DSA/DH、其余密码与模式、其余哈希、
 * 全部内置 PRNG（运行时由项目侧 src/crypto.cpp 注册 "processprng" 描述符）。 */

/* libc 替换宏：与原版一致 */
#ifndef XMALLOC
   #ifdef malloc
   #define LTC_NO_PROTOTYPES
   #endif
#define XMALLOC  malloc
#endif
#ifndef XREALLOC
   #ifdef realloc
   #define LTC_NO_PROTOTYPES
   #endif
#define XREALLOC realloc
#endif
#ifndef XCALLOC
   #ifdef calloc
   #define LTC_NO_PROTOTYPES
   #endif
#define XCALLOC  calloc
#endif
#ifndef XFREE
   #ifdef free
   #define LTC_NO_PROTOTYPES
   #endif
#define XFREE    free
#endif

#ifndef XMEMSET
   #ifdef memset
   #define LTC_NO_PROTOTYPES
   #endif
#define XMEMSET  memset
#endif
#ifndef XMEMCPY
   #ifdef memcpy
   #define LTC_NO_PROTOTYPES
   #endif
#define XMEMCPY  memcpy
#endif
#ifndef XMEMCMP
   #ifdef memcmp
   #define LTC_NO_PROTOTYPES
   #endif
#define XMEMCMP  memcmp
#endif
#ifndef XSTRCMP
   #ifdef strcmp
   #define LTC_NO_PROTOTYPES
   #endif
#define XSTRCMP strcmp
#endif

/* 1.18 新增：常时比较宏（缺失会在 pkcs_1_oaep_decode.c 等处编译失败） */
#ifndef XMEM_NEQ
#define XMEM_NEQ mem_neq
#endif

#ifndef XCLOCK
#define XCLOCK   clock
#endif
#ifndef XCLOCKS_PER_SEC
#define XCLOCKS_PER_SEC CLOCKS_PER_SEC
#endif

#ifndef XQSORT
   #ifdef qsort
   #define LTC_NO_PROTOTYPES
   #endif
#define XQSORT qsort
#endif

/* 自测向量表不参与编译（省 .rdata；行为由 tests/ 侧 golden 保障） */
#define LTC_NO_TEST

/* 无文件访问（无 /dev/random 熵、无文件读入接口） */
#define LTC_NO_FILE

/* ---> Symmetric Block Ciphers：仅 AES（Rijndael） <--- */
#ifndef LTC_NO_CIPHERS

#define LTC_RIJNDAEL

#endif /* LTC_NO_CIPHERS */

/* ---> Modes：仅 ECB/CBC <--- */
#ifndef LTC_NO_MODES

#define LTC_ECB_MODE
#define LTC_CBC_MODE

#endif /* LTC_NO_MODES */

/* ---> Hashes：仅 SHA256 <--- */
#ifndef LTC_NO_HASHES

#define LTC_SHA256
/* hash_memory/hash_file 等 helper（security_init 依赖 hash_memory） */
#define LTC_HASH_HELPERS

#endif /* LTC_NO_HASHES */

/* ---> MACs：仅 HMAC <--- */
#ifndef LTC_NO_MACS

#define LTC_HMAC

#endif /* LTC_NO_MACS */

/* ---> PRNG：全部禁用。
 * beacon 经 src/crypto.cpp 注册 "processprng" 描述符（ProcessPrng，
 * 回退 CryptGenRandom），运行时 find_prng 即可命中。 <--- */
#define LTC_NO_PRNGS

/* ---> Public Key：仅 RSA（含 blinding / CRT hardening 默认开启） <--- */
#ifndef LTC_NO_PK

#define LTC_MRSA

#endif /* LTC_NO_PK */

#if defined(LTC_MRSA) && !defined(LTC_NO_RSA_BLINDING)
#define LTC_RSA_BLINDING
#endif
#if defined(LTC_MRSA) && !defined(LTC_NO_RSA_CRT_HARDENING)
#define LTC_RSA_CRT_HARDENING
#endif

/* ---> PKCS：仅 #1（RSA 加密封必需）；#5 口令派生不用 <--- */
#ifndef LTC_NO_PKCS

#define LTC_PKCS_1

/* ASN.1 DER（MRSA 硬性要求） */
#define LTC_DER

#endif /* LTC_NO_PKCS */

/* ---> misc：仅 base64（1.18 起归入本段；URL 变体由 encoders.cpp 本地实现） <--- */
#ifndef LTC_NO_MISC

#define LTC_BASE64

#endif /* LTC_NO_MISC */

/* cleanup（与原版一致的派生约束） */

#if defined(LTC_DER)
   #ifndef LTC_DER_MAX_RECURSION
      #define LTC_DER_MAX_RECURSION 30
   #endif
#endif

#if defined(LTC_MRSA)
   #define LTC_MPI
   #ifndef LTC_PK_MAX_RETRIES
      #define LTC_PK_MAX_RETRIES  20
   #endif
#endif

#ifdef LTC_MRSA
   #define LTC_PKCS_1
#endif

#if defined(LTC_DER) && !defined(LTC_MPI)
   #error ASN.1 DER requires MPI functionality
#endif

#if defined(LTC_MRSA) && !defined(LTC_DER)
   #error PK requires ASN.1 DER functionality, make sure LTC_DER is enabled
#endif

#if defined(LTC_NO_MATH) && (defined(LTM_DESC) || defined(TFM_DESC) || defined(GMP_DESC))
   #error LTC_NO_MATH defined, but also a math descriptor
#endif

/* THREAD management：与原版一致（无 pthread） */
#define LTC_MUTEX_GLOBAL(x)
#define LTC_MUTEX_PROTO(x)
#define LTC_MUTEX_TYPE(x)
#define LTC_MUTEX_INIT(x)
#define LTC_MUTEX_LOCK(x)
#define LTC_MUTEX_UNLOCK(x)
#define LTC_MUTEX_DESTROY(x)

#endif

#ifndef LTC_NO_FILE
   #ifndef LTC_FILE_READ_BUFSIZE
   #define LTC_FILE_READ_BUFSIZE 8192
   #endif
#endif
