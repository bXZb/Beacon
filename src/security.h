/*
   Define crypto constants for our hash and cipher choices
   KEY_SIZE 16 for AES-128
   HASH_SIZE 32 for SHA256
   HMAC_SIZE 16 for Truncated HmacSHA256
 */
#define KEY_SIZE 16
#define HASH_SIZE 32
#define HMAC_SIZE 16
int security_decrypt(char * buffer, int length);
int security_encrypt(char * buffer, int length);
void security_init(char * k);
int rsa_encrypt_once(char * kbuffer, char * indata, int inlen, char * outdata, int * outlen);

int createWMKey(unsigned int watermark);
int decodeWatermark(unsigned char * encodedText, unsigned long encodedLen, int watermarkKey, unsigned int watermark);
