# Security Model

Osiris Portable Files Indexer & Deleter Suite is designed for **100% local, offline operation** with defense-in-depth protections against both accidental data loss and cross-origin browser attacks.

## Built-In Protections

1. **Loopback-Only Binding & Port Exclusivity**
   - `files_indexer.py` binds exclusively to `127.0.0.1` (`localhost`).
   - On Windows, `allow_reuse_address` is disabled to prevent local port-hijacking via `SO_REUSEADDR`.
   - `Host` header validation rejects DNS rebinding attempts (`403`).

2. **Per-Session CSRF Token & Origin Isolation**
   - Each server startup generates a fresh 192-bit random token (`secrets.token_hex(24)`) injected into served `/` and `/deleter` HTML via `<meta name="osiris-token">`.
   - All privileged endpoints (`POST /api/open-location`, `POST /api/heartbeat`, `POST /api/deleter/*`, `GET /api/deleter/quarantine`) enforce constant-time `X-Osiris-Token` matching (`secrets.compare_digest`), block `Origin: null` (sandboxed iframe bypass) and `Sec-Fetch-Site: cross-site`, and close connections cleanly (`Connection: close`) on `4xx`/`5xx` responses.
   - Served HTML pages send `X-Frame-Options: DENY` and `Content-Security-Policy: frame-ancestors 'none'`.

3. **Active Preview Sandboxing**
   - Active file types served through `/api/file` (`.html`, `.htm`, `.shtml`, `.svg`, `.svgz`, `.xml`, `.xhtml`, `.xht`, `.mht`, `.mhtml`, and matching MIME types) are served with `Content-Security-Policy: sandbox; default-src 'none'; ...`, `X-Content-Type-Options: nosniff`, and `Referrer-Policy: no-referrer`, preventing stored XSS in indexed files from accessing the local origin.

4. **Read-Only Indexer & Strict `C:\` Exclusion**
   - `DELETE`, `PUT`, and `PATCH` requests return `405`; legacy destructive paths (`/api/delete`, `/api/remove`, `/api/unlink`, `/api/trash`) return `403`.
   - All Deleter endpoints strictly block the Windows system drive (`C:\`, `C:/`, `\\?\C:\`, etc.) with `403 C_DRIVE_PROTECTED` and protect suite files from self-quarantine.
   - All deletion requires a 2-stage workflow through `_OSIRIS_QUARANTINE` with manual review and explicit confirmation.

5. **Filesystem, Archive & Shell Hardening**
   - Blocks UNC paths, NTFS Alternate Data Streams (`path:stream`), drive-relative paths (`D:file`), Windows reserved device names (`CON`, `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9`), path traversal (`..`), and symlinks/reparse points.
   - Deep-check archive inspection enforces ZIP uncompressed-size and compression-ratio limits (`512 MB` / `>100x` above `64 MB`), streaming decompression caps (`256 MB` for GZ/BZ2/XZ), and skips `<!DOCTYPE`/`<!ENTITY` XML expansion.
   - Windows shortcut and fallback PowerShell invocations use UTF-16LE Base64 `-EncodedCommand` with environment variables rather than interpolated command strings.

## Reporting a Vulnerability

If you discover a security issue, please open a private security advisory on GitHub rather than posting exploit details publicly.
