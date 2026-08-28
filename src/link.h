#include <stdlib.h>
/* link API */
void command_link_start(char * buffer, int length, void (*callback)(char * buffer, int length, int type));
void command_link_route(char * buffer, int length, void (*callback)(char * buffer, int length, int type));
void command_link_stop(char * buffer, int length, void (*callback)(char * buffer, int length, int type));
void command_link_reopen(char * buffer, int length, void (*callback)(char * buffer, int length, int type));

/* report all links */
void link_poll(void(*callback)(char * buffer, int length, int type));

/* utility to build our frames */
char * link_frame_header(int type, int message, int * size);


BOOL write_all(HANDLE pipe, char* buffer, int size);