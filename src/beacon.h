void beacon(void * lpReserved);
void process_payload(char * buffer, unsigned int length);
void command_shell_callback(char * buffer, int length, int type);
void post_crypt_replay_error(unsigned int diff);
void process_payload(char * buffer, unsigned int length);

/* prototype for our error function */
void post_error(int error, char * fmt, ...); /* error with formatted args, I guess */
void post_error_na(int error);			/* error with no args */
void post_error_d(int error, int arg);  /* error with a single arg */
void post_error_dd(int error, int arg1, int arg2); /* error with two # args */
void post_error_s(int error, char * text); /* error with a single string arg */
void post_error_sd(int error, char * arg1, int arg2); /* error with a string and a # arg */

#define BEACON_PROTO_HTTP         0x00
#define BEACON_PROTO_DNS          0x01
#define BEACON_PROTO_SMB          0x02
#define BEACON_PROTO_TCP_REVERSE  0x04
#define BEACON_PROTO_HTTPS        0x08
#define BEACON_PROTO_TCP_BIND     0x10

#define IS_HTTPS ( (setting_short(SETTING_PROTOCOL) & BEACON_PROTO_HTTPS) == BEACON_PROTO_HTTPS )

extern char myargs[];

typedef struct {
	int  myid;         /* agent id */
	int  length;       /* length of metadata */
	char data[1024];   /* session metadata */
} sessdata;

/* setting constants */
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
#define DEPRECATED_SETTING_SPAWNTO 14
#define SETTING_PIPENAME   15
#define DEPRECATED_SETTING_KILLDATE_YEAR  16
#define DEPRECATED_SETTING_KILLDATE_MONTH 17
#define DEPRECATED_SETTING_KILLDATE_DAY   18
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
// #define DEPRECATED_SETTING_INJECT_OPTIONS 36  (...RE-PURPOSED in 4.5)
#define SETTING_WATERMARK_HASH 36
#define SETTING_WATERMARK      37
#define SETTING_CLEANUP        38
#define SETTING_CFG_CAUTION    39
#define SETTING_KILLDATE       40
#define SETTING_GARGLE_NOOK     41
#define SETTING_GARGLE_SECTIONS 42
#define SETTING_PROCINJ_PERMS_I     43
#define SETTING_PROCINJ_PERMS       44
#define SETTING_PROCINJ_MINALLOC    45
#define SETTING_PROCINJ_TRANSFORM_X86 46
#define SETTING_PROCINJ_TRANSFORM_X64 47
#define DEPRECATED_SETTING_PROCINJ_ALLOWED     48
#define SETTING_BINDHOST            49
#define SETTING_HTTP_NO_COOKIES     50
#define SETTING_PROCINJ_EXECUTE     51
#define SETTING_PROCINJ_ALLOCATOR   52
#define SETTING_PROCINJ_STUB        53 /* NOTE: this is a fake constant. It's the MD5 sum of cobaltstrike.jar. This constant is used
										* because it will show in the decompiled Java source code for Cobalt Strike */
#define SETTING_HOST_HEADER         54
#define SETTING_EXIT_FUNK           55
#define SETTING_SSH_BANNER          56
#define SETTING_SMB_FRAME_HEADER    57
#define SETTING_TCP_FRAME_HEADER    58
#define SETTING_HEADERS_REMOVE      59

#define SETTING_DNS_BEACON_BEACON             60
#define SETTING_DNS_BEACON_GET_A              61
#define SETTING_DNS_BEACON_GET_AAAA           62
#define SETTING_DNS_BEACON_GET_TXT            63
#define SETTING_DNS_BEACON_PUT_METADATA       64
#define SETTING_DNS_BEACON_PUT_OUTPUT         65

#define SETTING_DNSRESOLVER                   66
#define SETTING_DOMAIN_STRATEGY               67
#define SETTING_DOMAIN_STRATEGY_SECONDS       68
#define SETTING_DOMAIN_STRATEGY_FAIL_X        69
#define SETTING_DOMAIN_STRATEGY_FAIL_SECONDS  70

#define SETTING_MAX_RETRY_STRATEGY_ATTEMPTS   71
#define SETTING_MAX_RETRY_STRATEGY_INCREASE   72
#define SETTING_MAX_RETRY_STRATEGY_DURATION   73

/* our various funks */
#define EXIT_FUNK_PROCESS 0
#define EXIT_FUNK_THREAD  1

#define HOST_STRATEGY_ROUND_ROBIN 0
#define HOST_STRATEGY_RANDOM      1
#define HOST_STRATEGY_EVENT       2

/* settings related code */
unsigned short setting_short(int field);
unsigned int   setting_int(int field);
char *         setting_ptr(int field);
unsigned int   setting_len(int field);
unsigned int   setting_option(int field, unsigned short value);

/* maintenance */
void settings_init(void * bptr);
void * get_beacon_ptr();

/* yes, this is useful! */
unsigned int bigger_rand();

/* debugging! FTW */
// void dlog(char * fmt, ...);