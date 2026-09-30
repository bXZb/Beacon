#ifndef LINUX_BEACON_COMMANDS_H
#define LINUX_BEACON_COMMANDS_H

/* Callback types — official */
#define CALLBACK_OUTPUT       0x00
#define CALLBACK_KEYSTROKES   0x01
#define CALLBACK_FILE         0x02
#define CALLBACK_SCREENSHOT   0x03
#define CALLBACK_CLOSE        0x04
#define CALLBACK_READ         0x05
#define CALLBACK_CONNECT      0x06
#define CALLBACK_PING         0x07
#define CALLBACK_FILE_WRITE   0x08
#define CALLBACK_FILE_CLOSE   0x09
#define CALLBACK_PIPE_OPEN    0x0a
#define CALLBACK_PIPE_CLOSE   0x0b
#define CALLBACK_PIPE_READ    0x0c
#define CALLBACK_POST_ERROR   0x0d
#define CALLBACK_PIPE_PING    0x0e
#define CALLBACK_TOKEN_STOLEN 0x0f
#define CALLBACK_TOKEN_GETUID 0x10
#define CALLBACK_PROCESS_LIST 0x11
#define CALLBACK_POST_REPLAY_ERROR 0x12
#define CALLBACK_PWD          0x13
#define CALLBACK_JOBS         0x14
#define CALLBACK_HASHDUMP     0x15
#define CALLBACK_PENDING      0x16  /* file browser listing (also called LIST_FILES) */
#define CALLBACK_LIST_FILES   0x16
#define CALLBACK_ACCEPT       0x17
#define CALLBACK_NETVIEW      0x18
#define CALLBACK_PORTSCAN     0x19
#define CALLBACK_DEAD         0x1a
#define CALLBACK_SSH_STATUS   0x1b
#define CALLBACK_CHUNK_ALLOCATE 0x1c
#define CALLBACK_CHUNK_SEND     0x1d
#define CALLBACK_OUTPUT_OEM     0x1e
#define CALLBACK_ERROR          0x1f  /* structured only — do not send free text */
#define CALLBACK_OUTPUT_UTF8    0x20

/* Command IDs — official proto.cpp / Tasks.java */
#define COMMAND_SPAWN          0x01
#define COMMAND_SHELL          0x02  /* session-style shell (raw command string) */
#define COMMAND_DIE            0x03
#define COMMAND_SLEEP          0x04
#define COMMAND_CD             0x05
#define COMMAND_CHECKIN        0x08
#define COMMAND_UPLOAD         0x0A
#define COMMAND_DOWNLOAD       0x0B
#define COMMAND_EXECUTE        0x0C
#define COMMAND_CONNECT        0x0E
#define COMMAND_SEND           0x0F
#define COMMAND_CLOSE          0x10
#define COMMAND_LISTEN         0x11
#define COMMAND_DOWNLOAD_STOP  0x13
#define COMMAND_TOKEN_GETUID   0x1B
#define COMMAND_PS_LIST        0x20
#define COMMAND_PS_KILL        0x21
#define COMMAND_PWD            0x27
#define COMMAND_JOB_REGISTER   0x28
#define COMMAND_JOBS           0x29
#define COMMAND_JOB_KILL       0x2a
#define COMMAND_LSOCKET_BIND   0x32  /* 50 rportfwd bind 0.0.0.0 */
#define COMMAND_LSOCKET_CLOSE  0x33  /* 51 rportfwd stop by port */
#define COMMAND_FILE_LIST      0x35
#define COMMAND_FILE_MKDIR     0x36
#define COMMAND_FILE_DRIVES    0x37
#define COMMAND_FILE_RM        0x38
#define COMMAND_UPLOAD_CONTINUE 0x43
#define COMMAND_FILE_COPY      0x49
#define COMMAND_FILE_MOVE      0x4a
#define COMMAND_SETENV         0x48
#define COMMAND_EXECUTE_JOB    0x4e  /* beacon shell: COMSPEC + /C args */
#define COMMAND_LSOCKET_TCPPIVOT 0x52 /* 82 */
#define COMMAND_INLINE_EXECUTE_OBJECT 0x64
#define COMMAND_TCP_CONNECT    0x56
#define COMMAND_LSOCKET_BIND_LOCALHOST 0x66 /* 102 rportfwd 127.0.0.1 */

void process_message(unsigned int type, char *buffer, int length);

#endif
