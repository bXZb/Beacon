/* definition of our "link" channel */
typedef struct {
	HANDLE pipe;
	SOCKET socket;
	int(*read)(void * thisp, char * buffer, int max);
	int(*write)(void * thisp, char * buffer, int length);
	void(*close)(void * thisp);
	void(*flush)(void * thisp);
	int(*ready)(void * thisp, int timeout);
	void(*wait)(void *thisp);
} LCHANNEL;

/* 
 * LCHANNEL_READ_FRAME return value contract:
 * >0 .. I read X bytes
 *  0 .. No data is available to read.
 * <0 .. Connection failed!
 */
#define LCHANNEL_READ_FRAME(channel, buffer, max) channel.read(&channel, buffer, max)

/*
 * LCHANNEL_WRITE_FRAME return value contract:
 * TRUE  .. the write was successful 
 * FALSE .. Connection failed!
 */
#define LCHANNEL_WRITE_FRAME(channel, buffer, length) channel.write(&channel, buffer, length)
#define LCHANNEL_CLOSE(channel) channel.close(&channel)
#define LCHANNEL_FLUSH(channel) channel.flush(&channel)

/* LCHANNEL_WAIT
 * block and wait indefinitely for the channel to be ready to read.
 */
#define LCHANNEL_WAIT(channel) channel.wait(&channel)

/*
 * LCHANNEL_READY return value contract:
 * TRUE  .. the channel is ready to read
 * FALSE .. the channel is dead or not ready to read (kill it, either way)
 */
#define LCHANNEL_READ_READY(channel, timeout) channel.ready(&channel, timeout)

/* initialize an SMB link channel */
LCHANNEL lchannel_smb(HANDLE pipe);

/* intialize a SOCKET link channel */
LCHANNEL lchannel_tcp(SOCKET socket);

/* register a new link */
BOOL link_register(LCHANNEL channel, int hint, void(*callback)(char * buffer, int length, int type));

/* for setting metadata about a new channel */
#define HINT_REVERSE    0x00010000
#define HINT_FORWARD    0x00000000
#define HINT_PROTO_PIPE 0x00000000
#define HINT_PROTO_TCP  0x00100000

#define CHANNEL_FORWARD_TCP(x)  (HINT_FORWARD | HINT_PROTO_TCP | x)
#define CHANNEL_FORWARD_PIPE(x) (HINT_FORWARD | HINT_PROTO_PIPE | x)
#define CHANNEL_REVERSE_TCP(x)  (HINT_REVERSE | HINT_PROTO_TCP | x)
#define CHANNEL_REVERSE_PIPE(x) (HINT_REVERSE | HINT_PROTO_PIPE | x)