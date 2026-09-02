#pragma once
#include "profile.h"

void hostprof_reload(void);
void hostprof_apply(const char * hostname, profile * p, int is_post);
int  hostprof_count(void);
const char * hostprof_host_at(int index);
const char * hostprof_get_uri_at(int index);
const char * hostprof_post_uri_at(int index);
