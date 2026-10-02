#pragma once

typedef struct {
	char * headers;
	char * parameters;
	char * uri;
	char * buffer; /* printing buffer */
	int    blen;
	int    max;    /* max of temp, stage */
	char * temp;   /* something useful */
	char * stage;  /* whateverz */
	void * manager;
} profile;

void profile_setup(profile * prof, int size);
void profile_free(profile * prof,  int size);

void apply(char * program, int plen, profile * myprofile, char * arg1, int len1, char * arg2, int len2);
int recover(char *program, int plen, char * buffer, int read, int max);