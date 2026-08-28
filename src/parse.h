/* data parser */
typedef struct {
	char * original; /* the original buffer [so we can free it] */
	char * buffer;   /* current pointer into our buffer */
	int    length;   /* remaining length of data */
	int    size;     /* total size of this buffer */
} datap;

typedef struct {
	char * buffer;
	int    length;
} datap_buffer;

/* initializes a data parser */
void data_init(datap * temp, char * buffer, int length);

/* extracts an integer from data parser */
unsigned int data_int(datap * d);

/* extracts an unsigned short from data parser */
unsigned short data_short(datap * d);

/* extracts a pointer from data parser */
char * data_ptr(datap * d, int length);

/* extracts a pointer and length */
datap_buffer data_extract(datap * d);

/* extracts a string from data parser and copies it
   provided buffer. Returns length of string */
int data_string(datap * d, char * buffer, int max);

/* allocate memory and return a parser that points to it */
datap * data_alloc(int size);

/* free memory please */
void data_free(datap * temp);

/* return length of remaining data */
int data_length(datap * d);

/* return a pointer to the current buffer */
char * data_buffer(datap * d);

/* extract a one-off string, null terminate it, and put it in our buffer */
int data_string_oneoff(datap * d, char * buffer, int max);

/* alloc a buffer, extract a one-off string, null terminate it. Caller must free string! */
char * data_string_oneoff_FREEME(datap * d, int max);

/* extracts a NULL terminated length+string from our buffer */
char * data_string_asciiz(datap * d);

/* clear the contents of the buffer associated with this */
void data_cleanup(datap * temp);

/* grab a single byte... */
unsigned int data_byte(datap * d);

/* grab a fixed block of data */
char * data_ptr_extract(datap * d, int * size);