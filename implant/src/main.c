#include "beacon.h"
#include "debug.h"
#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;
    srand((unsigned)time(NULL) ^ (unsigned)getpid());
    curl_global_init(CURL_GLOBAL_DEFAULT);
    DEBUG_PRINT("LinuxBeacon starting\n");
    beacon_main();
    curl_global_cleanup();
    return 0;
}
