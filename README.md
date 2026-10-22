# php2shell

CVE-2026-109618 / CVE-2026-109619. Pre-auth RCE through PHP `session.upload_progress`.

Affected: PHP 5.4.0 -- 8.5.11. Fixed in 8.2.35, 8.3.36, 8.4.27, 8.5.12.

## Vulnerability

Two memory-safety bugs in PHP's RFC1867 multipart handler (`php_session_rfc1867_callback` in `ext/session/session.c`). Both fire during multipart POST processing, before application code runs. No authentication required.

**CVE-2026-109618** (CVSS 9.2): OOM during `session.upload_progress` leaves `PS(id)` pointing at freed memory. The next request on the same worker reads the stale pointer as a `zend_string` and URL-encodes it into `Set-Cookie: PHPSESSID=...`. The attacker URL-decodes the cookie and gets raw process memory: heap pointers, PHP base address, libc offsets. ASLR defeated.

**CVE-2026-109619** (CVSS 9.2): Fatal-error backtrace UAF + OPcache type confusion. Stale `CG(map_ptr_last)` lets `zend_accel_script_persist()` write to attacker-controlled addresses. Combined with CVE-2026-109618's leaked addresses → pre-auth RCE.

## Exploit

Three-stage ASLR bypass RCE via pure HTTP. Works against any PHP page (even `<?php echo "OK"; ?>`).

**Stage 1 — heap leak.** 1001 fields exceed `max_input_vars` (warning sets `headers_sent=1`), `PHPSESSID=\x00` creates a new session id, then a 12MB field OOMs. `PS(id)` dangles. Spray reoccupies the stale block with forged `len=0x1000`. `php_url_encode` does a 4096-byte OOB read into `Set-Cookie`. The 2MB-aligned mode of heap pointers = Zend MM chunk base.

**Stage 2 — libphp leak.** Different field shape places stale `PS(id)` inside a 56-byte HashTable page. Nested arrays expand so the data window covers `pDestructor` (= `ZVAL_PTR_DTOR = libphp+offset`). Decoded from Set-Cookie.

**Stage 3 — command execution.** Pad fields + OOM create a dangling `PS(http_session_vars)` reference. Spray overwrites it with `{rc=1, IS_REFERENCE, val=htdata}` and 15 copies of a 167-byte fake HashTable with `pDestructor = zif_system` (inside libphp, no libc needed). Trigger chain:

```
php_session_track_init -> zval_ptr_dtor(PS(http_session_vars))
  -> zend_reference_destroy -> zval_ptr_dtor(&ref->val)
    -> zend_array_destroy -> zend_hash_destroy
      -> pDestructor(&bucket->val) = zif_system("id>/tmp/cc")
```

Worker rotation between stages: OOM corrupts heap → session-initializing request triggers `zend_mm_panic` → SIGABRT → prefork respawns with same address layout.

**Constraints:** `display_errors=On`, `memory_limit=8M`, `post_max_size>12M`, single-worker prefork, `session.use_strict_mode=0` (default). Commands limited to 14 bytes (use `sh</tmp/c` for longer scripts). Offsets are build-specific; defaults match `php:8.4.26-apache`.

## Usage

```bash
docker compose up -d
python3 php2shell.py 127.0.0.1 8860 -c 'id>/tmp/cc'
docker exec p2s-final cat /tmp/cc
```

Custom offsets (different PHP build):

```bash
python3 php2shell.py 10.0.0.1 80 -c 'id>/tmp/cc' \
  --zif-offset 0x465370 --dtor-offset 0x65eb60 --htdata-offset 0x690d8
```

| Flag | Default | Description |
|------|---------|-------------|
| `-c` | `id` | OS command (max 14 bytes) |
| `--path` | `/index.php` | Target endpoint |
| `--huge-mb` | `12` | OOM field size in MB |
| `--retries` | `3` | Retries per stage |
| `--zif-offset` | `0x465370` | zif_system offset in libphp |
| `--dtor-offset` | `0x65eb60` | ZVAL_PTR_DTOR offset in libphp |
| `--htdata-offset` | `0x690d8` | Chunk-relative fake HT offset |

## Mitigation

Patch to PHP 8.2.35+, 8.3.36+, 8.4.27+, or 8.5.12+.

```ini
session.upload_progress.enabled = Off
memory_limit = -1
```

## References

- https://calif.io/php2shell/
- https://www.php2shell.com/
- https://www.wiz.io/blog/php2shell-php-rce
- https://www.php.net/archive/2026.php#2026-10-20-1

## Disclaimer

For authorized defensive research and security testing only.
