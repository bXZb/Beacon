/* nc_argwalk.c - minimal repro for the No-Consolation arg-parse crash.
 * Performs EXACTLY NC's entry.c read sequence over the same 28-arg blob
 * (ZzZbziiiZzziiiziiizzziiizzzi per the official cna) and prints one line
 * per read, so the live run shows which extraction breaks on our runtime.
 */
#include <windows.h>
#include <stdio.h>
#include "beacon.h"

void go(char * args, int alen)
{
    datap parser;
    char * wname, * name, * wpath, * bytes, * path;
    int local, timeout, headers;
    char * cmdwline, * cmdline, * method;
    int use_unicode, nooutput, alloc_console, close_handles;
    char * unload_libs;
    int dont_save, list_pes;
    char * unload_pe, * username, * loadtime;
    int link_to_peb, dont_unload, load_all_deps;
    char * but, * deps, * search;
    int inthread;
    int pe_length = 0;
    char msg[160];

    BeaconDataParse(&parser, args, alen);
#define WALK(n, expr) do { expr; \
    _snprintf(msg, sizeof(msg) - 1, "read%02d len=%d rem=%d\n", n, \
              (int)BeaconDataLength(&parser) >= 0 ? 0 : 0, 0); \
    BeaconPrintf(CALLBACK_OUTPUT, "read%02d done rem=%d\n", n, BeaconDataLength(&parser)); \
} while (0)

    wname   = (char *)BeaconDataExtract(&parser, NULL);
    BeaconPrintf(CALLBACK_OUTPUT, "r01 wname=%p first=%02x rem=%d\n",
                 wname, wname ? (unsigned char)wname[0] : 0, BeaconDataLength(&parser));
    name    = BeaconDataExtract(&parser, NULL);
    BeaconPrintf(CALLBACK_OUTPUT, "r02 name=%p first=%02x rem=%d\n",
                 name, name ? (unsigned char)name[0] : 0, BeaconDataLength(&parser));
    wpath   = BeaconDataExtract(&parser, NULL);
    BeaconPrintf(CALLBACK_OUTPUT, "r03 wpath=%p first=%02x rem=%d\n",
                 wpath, wpath ? (unsigned char)wpath[0] : 0, BeaconDataLength(&parser));
    bytes   = BeaconDataExtract(&parser, &pe_length);
    BeaconPrintf(CALLBACK_OUTPUT, "r04 bytes=%p len=%d rem=%d\n",
                 bytes, pe_length, BeaconDataLength(&parser));
    path    = BeaconDataExtract(&parser, NULL);
    BeaconPrintf(CALLBACK_OUTPUT, "r05 path=%p first=%02x rem=%d\n",
                 path, path ? (unsigned char)path[0] : 0, BeaconDataLength(&parser));
    local   = BeaconDataInt(&parser);
    timeout = BeaconDataInt(&parser);
    headers = BeaconDataInt(&parser);
    BeaconPrintf(CALLBACK_OUTPUT, "r06-08 ints %d %d %d rem=%d\n",
                 local, timeout, headers, BeaconDataLength(&parser));
    cmdwline = BeaconDataExtract(&parser, NULL);
    cmdline  = BeaconDataExtract(&parser, NULL);
    method   = BeaconDataExtract(&parser, NULL);
    BeaconPrintf(CALLBACK_OUTPUT, "r09-11 cmd=%p line=%p meth=%p rem=%d\n",
                 cmdwline, cmdline, method, BeaconDataLength(&parser));
    use_unicode   = BeaconDataInt(&parser);
    nooutput      = BeaconDataInt(&parser);
    alloc_console = BeaconDataInt(&parser);
    close_handles = BeaconDataInt(&parser);
    BeaconPrintf(CALLBACK_OUTPUT, "r12-15 ints %d %d %d %d rem=%d\n",
                 use_unicode, nooutput, alloc_console, close_handles,
                 BeaconDataLength(&parser));
    unload_libs = BeaconDataExtract(&parser, NULL);
    BeaconPrintf(CALLBACK_OUTPUT, "r16 libs=%p first=%02x rem=%d\n",
                 unload_libs, unload_libs ? (unsigned char)unload_libs[0] : 0,
                 BeaconDataLength(&parser));
    dont_save = BeaconDataInt(&parser);
    list_pes  = BeaconDataInt(&parser);
    BeaconPrintf(CALLBACK_OUTPUT, "r17-18 ints %d %d rem=%d\n",
                 dont_save, list_pes, BeaconDataLength(&parser));
    unload_pe = BeaconDataExtract(&parser, NULL);
    BeaconPrintf(CALLBACK_OUTPUT, "r19 upe=%p first=%02x rem=%d\n",
                 unload_pe, unload_pe ? (unsigned char)unload_pe[0] : 0,
                 BeaconDataLength(&parser));
    username = BeaconDataExtract(&parser, NULL);
    BeaconPrintf(CALLBACK_OUTPUT, "r20 user=%p first=%02x rem=%d\n",
                 username, username ? (unsigned char)username[0] : 0,
                 BeaconDataLength(&parser));
    loadtime = BeaconDataExtract(&parser, NULL);
    BeaconPrintf(CALLBACK_OUTPUT, "r21 time=%p first=%02x rem=%d\n",
                 loadtime, loadtime ? (unsigned char)loadtime[0] : 0,
                 BeaconDataLength(&parser));
    link_to_peb   = BeaconDataInt(&parser);
    dont_unload   = BeaconDataInt(&parser);
    load_all_deps = BeaconDataInt(&parser);
    BeaconPrintf(CALLBACK_OUTPUT, "r22-24 ints %d %d %d rem=%d\n",
                 link_to_peb, dont_unload, load_all_deps,
                 BeaconDataLength(&parser));
    but     = BeaconDataExtract(&parser, NULL);
    deps    = BeaconDataExtract(&parser, NULL);
    search  = BeaconDataExtract(&parser, NULL);
    BeaconPrintf(CALLBACK_OUTPUT, "r25-27 but=%p deps=%p search=%p rem=%d\n",
                 but, deps, search, BeaconDataLength(&parser));
    inthread = BeaconDataInt(&parser);
    BeaconPrintf(CALLBACK_OUTPUT, "r28 int=%d rem=%d ALL-DONE\n",
                 inthread, BeaconDataLength(&parser));
}
