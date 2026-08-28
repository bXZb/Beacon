int netbios_encode(char base, char * src, int length, char * dst, int maxlength);
int netbios_decode(char base, char * src, int length, char * dst, int maxlength);

/* compatable with tomcrypt's signatures as we're essentially wrapping its base64 functions and transforming the output. */
int base64url_encode(const unsigned char* in, unsigned long len, unsigned char* out, unsigned long* outlen);
//int base64url_decode(const unsigned char * in, unsigned long len, unsigned long max, unsigned char * out, unsigned long *outlen);
int base64url_decode(unsigned char* in, unsigned long len, unsigned long max, unsigned char* out, unsigned long* outlen);

/* mask encoder */
int xor_encode(char * src, int length, char * dst, int maxlength);
int xor_decode(char * src, int length, char * dst, int maxlength);