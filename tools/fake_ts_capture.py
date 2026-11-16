# -*- coding: utf-8 -*-
"""fake_ts_capture.py - capture the OpenBeacon's GET /activity Cookie value
(metadata ciphertext) with a python listener, then RSA-decrypt it with our
TS beacon_keys via the fat jar to locate the format mismatch."""
import base64
import socket

OUT = open(r"C:\Users\Public\ob_cookie.log", "w", encoding="utf-8")


def log(m):
    OUT.write(m + "\n")
    OUT.flush()
    print(m, flush=True)


def main():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", 8083))
    s.listen(4)
    log("fake ts bound 8082")
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
    log("=== REQUEST ===")
    log(text[:800])
    cookie = ""
    for line in text.splitlines():
        if line.lower().startswith("cookie:"):
            cookie = line.split(":", 1)[1].strip()
    log("cookie: %s" % cookie[:400])
    with open(r"C:\Users\Public\ob_cookie_b64.txt", "w") as f:
        f.write(cookie)
    # respond like the TS would (empty-ish)
    c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
    c.close()
    log("answered 200; cookie saved")


if __name__ == "__main__":
    main()
