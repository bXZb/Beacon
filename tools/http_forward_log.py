# -*- coding: utf-8 -*-
"""http_forward_log.py - logging TCP forwarder 8082 -> 8083 (TS listener
moved there).  Prints the first request line + headers per connection."""
import socket
import threading

LISTEN = ("0.0.0.0", 8082)
TARGET = ("127.0.0.1", 8083)
OUT = open(r"C:\Users\Public\http_forward.log", "w", encoding="utf-8")


def log(m):
    OUT.write(m + "\n")
    OUT.flush()
    print(m, flush=True)


def pipe(src, dst, label):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            if label == "c2s" and len(data) < 4096:
                log("[%s] %r" % (label, data[:600]))
            dst.sendall(data)
    except Exception:
        pass
    try:
        dst.shutdown(socket.SHUT_WR)
    except Exception:
        pass


def handle(client):
    try:
        server = socket.create_connection(TARGET, timeout=10)
    except Exception as e:
        log("target fail: %s" % e)
        client.close()
        return
    t1 = threading.Thread(target=pipe, args=(client, server, "c2s"), daemon=True)
    t2 = threading.Thread(target=pipe, args=(server, client, "s2c"), daemon=True)
    t1.start()
    t2.start()
    t1.join(600)
    try:
        client.close()
    except Exception:
        pass


def main():
    log("forwarder 8082 -> 8083")
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(LISTEN)
    s.listen(16)
    while True:
        c, _ = s.accept()
        threading.Thread(target=handle, args=(c,), daemon=True).start()


if __name__ == "__main__":
    main()
