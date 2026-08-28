/*
 * API to build a buffer into a ready-to-encrypt frame
 */
typedef struct {
	char * dest;
	int  len;
	int  max;
} builder;

void build_init(builder * b, char * dest, int max);
void build_add_data(builder * b, char * data, int len);
void build_add_int(builder * b, DWORD data);
void build_add_short(builder * b, WORD data);
void build_add_byte(builder *b, BYTE number);
int  build_length(builder * b);
int  build_length_rsa(builder * b);