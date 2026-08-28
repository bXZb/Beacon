#ifndef TOMCRYPT_CUSTOM_H_
#define TOMCRYPT_CUSTOM_H_

/* 精简版 tomcrypt_custom.h（P4.16，基于 tomcrypt-headers/ 的 1.17 原版派生）。
 *
 * 目标：只编译 beacon（RSA-1024 only）实际使用的路径——
 *   AES(RIJNDAEL) + CBC + SHA256 + HMAC + base64 + RSA(MRSA) + DER(为 MRSA 所需)
 * 其余全部不编译：ECC/DSA、其余分组密码与模式、其余哈希、GCM/OCB/EAX 等组合模式、
 * 全部内置 PRNG（随机数由项目侧 crypto.cpp 注册的 ProcessPrng 描述符提供）。
 * 与链接期"符号桩"方案互补：此文件管"不编进来"，项目源码侧管"残余死引用"。 */

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
#ifndef LTC_NO_TABLES
   #define LTC_TWOFISH_TABLES
#endif

#endif /* LTC_NO_CIPHERS */

/* ---> Modes：仅 CBC <--- */
#ifndef LTC_NO_MODES

#define LTC_ECB_MODE
#define LTC_CBC_MODE

#endif /* LTC_NO_MODES */

/* ---> Hashes：仅 SHA256 <--- */
#ifndef LTC_NO_HASHES

#define LTC_SHA256

#endif /* LTC_NO_HASHES */

/* ---> MACs：仅 HMAC <--- */
#ifndef LTC_NO_MACS

#define LTC_HMAC

#endif /* LTC_NO_MACS */

/* base64（crypto 层与 profile/编码路径使用） */
#define LTC_BASE64

/* ---> PRNG：全部禁用。
 * beacon 经 src/crypto.cpp 注册 "processprng" 描述符（ProcessPrng，
 * 回退 CryptGenRandom），运行时 find_prng 即可命中。 <--- */
#define LTC_NO_PRNGS

/* ---> math provider：由工程预定义 LTM_DESC / USE_LTM 提供，此处不重复 <--- */

/* ---> Public Key：仅 RSA <--- */
#ifndef LTC_NO_PK

#define LTC_MRSA

#endif /* LTC_NO_PK */

/* LTC_PKCS #1（RSA 加密封必需）；#5 口令派生不用 */
#ifndef LTC_NO_PKCS

#define LTC_PKCS_1

/* ASN.1 DER（MRSA 硬性要求；证书类解码器的死分支由链接期处理，见 thirdparty/README.md） */
#define LTC_DER

#endif /* LTC_NO_PKCS */

/* cleanup（与原版一致的派生约束） */

#if defined(LTC_MRSA)
   #define MPI
#endif

#if defined(LTC_DER) && !defined(MPI)
   #error ASN.1 DER requires MPI functionality
#endif

#if defined(LTC_MRSA) && !defined(LTC_DER)
   #error PK requires ASN.1 DER functionality, make sure LTC_DER is enabled
#endif

/* THREAD management：与原版一致（无 pthread） */
#define LTC_MUTEX_GLOBAL(x)
#define LTC_MUTEX_PROTO(x)
#define LTC_MUTEX_TYPE(x)
#define LTC_MUTEX_INIT(x)
#define LTC_MUTEX_LOCK(x)
#define LTC_MUTEX_UNLOCK(x)

#endif
