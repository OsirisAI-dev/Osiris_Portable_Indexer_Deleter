from __future__ import annotations

import argparse
import base64
import bz2
import ctypes
import gzip
import hashlib
import http.server
import json
import lzma
import mimetypes
import os
import secrets
import shutil
import socketserver
import string
import struct
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.parse
import webbrowser
import xml.etree.ElementTree as ET
import zipfile
import zlib
from datetime import datetime
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parent
HTML_PATH = BASE_DIR / "FILES_INDEXATION_SYSTEM.html"
DELETER_DIR = BASE_DIR / "FILES INDEXATION_DELETER"
DELETER_HTML_PATH = DELETER_DIR / "CHECKER_DELETER.html"
DATA_JS_PATH = BASE_DIR / "files_index_data.js"
EXE_PATH = BASE_DIR / "Osiris_Indexer_Deleter.exe"
DEFAULT_PORT = 8765
QUARANTINE_DIR_NAME = "_OSIRIS_QUARANTINE"
QUARANTINE_MANIFEST_NAME = "_quarantine_manifest.json"
SERVER_TOKEN = secrets.token_hex(24)
MAX_DEEP_DECOMPRESS_BYTES = 256 * 1024 * 1024
MAX_ZIP_TOTAL_UNCOMPRESSED = 512 * 1024 * 1024


def detect_default_root() -> str:
    anchor = Path(BASE_DIR).anchor
    if anchor:
        return anchor.replace("\\", "/").rstrip("/") + "/"
    if os.name != "nt":
        return "/"
    return (os.environ.get("SystemDrive", "C:").rstrip("\\/") + "/")


DEFAULT_ROOT = detect_default_root()

SKIP_DIRS = {
    "$recycle.bin", "$winreagent", "$sysreset", "$windows.~bt", "$windows.~ws",
    "system volume information", "windows", "winnt", "program files", "program files (x86)",
    "programdata", "recovery", "config.msi", "documents and settings", "perflogs",
    "msocache", "onedrivetemp", "system32", "syswow64", "winsxs", "boot", "efi",
    "appdata", "application data", "local settings", "cookies", "nethood",
    "printhood", "recent", "sendto", "start menu", "templates",
    "all users", "default", "default user",
    "temp", "tmp", "cache", "caches", "gpucache", "code cache", "shadercache",
    "crashpad", "thumbnails", ".thumbnails", "node_modules", "bower_components",
    "vendor", ".git", ".hg", ".svn", "__pycache__", ".venv", "venv", "env",
    ".tox", ".pytest_cache", ".mypy_cache", ".ruff_cache", "site-packages", "dist-packages",
    ".gemini", ".cache", ".npm", ".yarn", ".pnpm-store", ".cargo", ".rustup",
    ".vscode", ".cursor", ".idea", ".gradle", ".m2", ".android", ".lmstudio", ".ollama", ".nuget",
    "_osiris_quarantine", "_osiris_runtime",
}

SKIP_FILES = {
    "pagefile.sys", "hiberfil.sys", "swapfile.sys", "dumpstack.log", "dumpstack.log.tmp",
    "thumbs.db", "ehthumbs.db", "ehthumbs_vista.db", "desktop.ini", "iconcache.db", ".ds_store",
    "ntuser.dat", "ntuser.dat.log1", "ntuser.dat.log2", "ntuser.ini",
    "usrclass.dat", "usrclass.dat.log1", "usrclass.dat.log2",
}

PROTECTED_SUITE_NAMES = {
    "files_indexation_system.html",
    "files_indexer.py",
    "files_index_data.js",
    "osiris_indexer_deleter.exe",
    "osiris_instructions_readme.txt",
    "osiris_portable_indexer_deleter_suite.zip",
    "osiris_portable_indexer_deleter_suite_lite.zip",
    "osiris_portable_indexer_deleter_suite_full.zip",
    "checker_deleter.html",
    "osiris_suite.ico",
    "osiris_deleter.ico",
}


def should_skip_dir(dirname: str, include_system: bool = False) -> bool:
    low = dirname.lower()
    if low in ("$recycle.bin", "system volume information", "_osiris_quarantine", "_osiris_runtime"):
        return True
    if include_system:
        return False
    return low in SKIP_DIRS or dirname.startswith("$") or dirname.startswith(".")


def should_skip_file(filename: str, include_system: bool = False) -> bool:
    if filename.startswith(".tmp_idx_"):
        return True
    if include_system:
        return False
    low = filename.lower()
    return low in SKIP_FILES or low.startswith("ntuser.dat")


EXT_CATEGORIES = {
    "video": {".mp4", ".mkv", ".avi", ".mov", ".webm", ".wmv", ".flv", ".m4v", ".mpg", ".mpeg", ".3gp", ".3g2", ".ogv"},
    "audio": {".mp3", ".wav", ".flac", ".aac", ".ogg", ".oga", ".m4a", ".m4b", ".m4p", ".wma", ".opus", ".aif", ".aiff", ".mid", ".midi"},
    "image": {".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".bmp", ".ico", ".tif", ".tiff", ".avif", ".heic", ".heif"},
    "pdf": {".pdf"},
    "doc": {".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".ods", ".odp", ".txt", ".md", ".csv", ".rtf", ".log", ".epub"},
    "code": {
        ".py", ".js", ".ts", ".jsx", ".tsx", ".html", ".htm", ".css", ".scss",
        ".json", ".xml", ".yaml", ".yml", ".c", ".cpp", ".h", ".hpp", ".ino",
        ".java", ".kt", ".go", ".rs", ".php", ".sh", ".bat", ".ps1", ".sql", ".vbs",
    },
    "archive": {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".zst", ".iso", ".dmg"},
    "exe": {".exe", ".msi", ".apk", ".dll", ".appx", ".sys", ".so"},
}

EXTRA_MIMES = {
    ".mp4": "video/mp4",
    ".m4v": "video/mp4",
    ".webm": "video/webm",
    ".mkv": "video/x-matroska",
    ".avi": "video/x-msvideo",
    ".mov": "video/quicktime",
    ".ogv": "video/ogg",
    ".3gp": "video/3gpp",
    ".3g2": "video/3gpp2",
    ".wmv": "video/x-ms-wmv",
    ".flv": "video/x-flv",
    ".mpg": "video/mpeg",
    ".mpeg": "video/mpeg",
    ".mp3": "audio/mpeg",
    ".aac": "audio/aac",
    ".m4a": "audio/mp4",
    ".m4b": "audio/mp4",
    ".m4p": "audio/mp4",
    ".ogg": "audio/ogg",
    ".oga": "audio/ogg",
    ".opus": "audio/opus",
    ".flac": "audio/flac",
    ".wav": "audio/wav",
    ".aif": "audio/aiff",
    ".aiff": "audio/aiff",
    ".wma": "audio/x-ms-wma",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".png": "image/png",
    ".gif": "image/gif",
    ".bmp": "image/bmp",
    ".ico": "image/x-icon",
    ".webp": "image/webp",
    ".avif": "image/avif",
    ".svg": "image/svg+xml",
    ".tif": "image/tiff",
    ".tiff": "image/tiff",
    ".heic": "image/heic",
    ".heif": "image/heif",
    ".pdf": "application/pdf",
    ".md": "text/plain; charset=utf-8",
    ".log": "text/plain; charset=utf-8",
    ".py": "text/plain; charset=utf-8",
    ".ps1": "text/plain; charset=utf-8",
    ".bat": "text/plain; charset=utf-8",
    ".vbs": "text/plain; charset=utf-8",
    ".json": "application/json; charset=utf-8",
}

_SCAN_LOCK = threading.Lock()
_DELETER_LOCK = threading.Lock()
_DRIVE_TYPE_MAP = {2: "removable", 3: "fixed", 4: "network", 5: "cdrom"}


def categorize_extension(ext: str) -> str:
    ext_l = ext.lower()
    for cat, exts in EXT_CATEGORIES.items():
        if ext_l in exts:
            return cat
    return "other"


def _get_windows_volume_meta(root_backslash: str) -> tuple[str, str]:
    if os.name != "nt":
        return "", "fixed"
    target = root_backslash.rstrip("\\/") + "\\"
    label = ""
    kind = "unknown"
    try:
        kernel32 = ctypes.windll.kernel32
        dtype = kernel32.GetDriveTypeW(ctypes.c_wchar_p(target))
        kind = _DRIVE_TYPE_MAP.get(int(dtype), "unknown")
        vol_buf = ctypes.create_unicode_buffer(261)
        if kernel32.GetVolumeInformationW(
            ctypes.c_wchar_p(target), vol_buf, 261, None, None, None, None, 0
        ):
            label = vol_buf.value.strip()
    except Exception:
        pass
    return label, kind


def get_drive_info(root_path: str) -> dict[str, Any]:
    norm_root = os.path.abspath(root_path)
    anchor = Path(norm_root).anchor or norm_root
    usage_target = anchor if os.path.exists(anchor) else norm_root
    total = used = free = 0
    try:
        du = shutil.disk_usage(usage_target)
        total, used, free = int(du.total), int(du.used), int(du.free)
    except OSError:
        pass
    pct = round((used / total) * 100.0, 2) if total > 0 else 0.0
    drive_str = anchor.rstrip("\\/") + "\\" if ":" in anchor else anchor
    label, kind = _get_windows_volume_meta(drive_str)
    return {
        "drive": drive_str,
        "root": norm_root.replace("\\", "/"),
        "total": total,
        "used": used,
        "free": free,
        "percent_used": pct,
        "label": label,
        "kind": kind,
    }


def list_mounted_drives() -> list[dict[str, Any]]:
    drives: list[dict[str, Any]] = []
    if os.name == "nt":
        for ch in string.ascii_uppercase:
            root = f"{ch}:\\"
            if os.path.exists(root):
                try:
                    du = shutil.disk_usage(root)
                    pct = round((du.used / du.total) * 100.0, 2) if du.total > 0 else 0.0
                    label, kind = _get_windows_volume_meta(root)
                    drives.append({
                        "drive": root,
                        "root": f"{ch}:/",
                        "total": int(du.total),
                        "used": int(du.used),
                        "free": int(du.free),
                        "percent_used": pct,
                        "label": label,
                        "kind": kind,
                    })
                except OSError:
                    continue
    else:
        drives.append(get_drive_info("/"))
    return drives


def _is_c_drive_blocked(path_str: str) -> bool:
    raw = str(path_str or "").strip()
    if not raw or "\x00" in raw:
        return True
    sys_drv = os.environ.get("SystemDrive", "C:").rstrip("\\/").upper() or "C:"
    for candidate in (raw, os.path.abspath(raw), os.path.realpath(raw)):
        cleaned = candidate.strip()
        for prefix in ("\\\\?\\", "\\\\.\\"):
            if cleaned.startswith(prefix):
                cleaned = cleaned[len(prefix):]
        drv, _ = os.path.splitdrive(cleaned)
        drv_u = drv.rstrip("\\/").upper()
        if drv_u in ("C:", sys_drv):
            return True
        norm_u = cleaned.replace("\\", "/").upper()
        if norm_u == "C:" or norm_u.startswith("C:/") or norm_u == sys_drv or norm_u.startswith(sys_drv + "/"):
            return True
    return False


def list_deleter_drives() -> list[dict[str, Any]]:
    return [d for d in list_mounted_drives() if not _is_c_drive_blocked(str(d.get("drive") or d.get("root") or ""))]


def _is_protected_suite_path(filepath: str) -> bool:
    try:
        target_res = Path(os.path.realpath(filepath))
        base_res = Path(os.path.realpath(str(BASE_DIR)))
        deleter_res = Path(os.path.realpath(str(DELETER_DIR)))
        runtime_res = Path(os.path.realpath(str(BASE_DIR / "_osiris_runtime")))
        if target_res == runtime_res or runtime_res in target_res.parents:
            return True
        if target_res.parent in (base_res, deleter_res) and target_res.name.lower() in PROTECTED_SUITE_NAMES:
            return True
    except OSError:
        return True
    return False


def scan_directory(root_path: str = DEFAULT_ROOT, include_system: bool = False) -> dict[str, Any]:
    t0 = time.perf_counter()
    abs_root = os.path.abspath(root_path)
    if not os.path.exists(abs_root):
        raise FileNotFoundError(f"Path not found: {abs_root}")

    files: list[dict[str, Any]] = []
    total_size = 0
    root_posix = abs_root.replace("\\", "/")
    root_posix_prefix = root_posix if root_posix.endswith("/") else root_posix + "/"

    skipped_dirs = 0
    stack = [abs_root]
    while stack:
        current_dir = stack.pop()
        dir_posix = current_dir.replace("\\", "/").rstrip("/")
        dir_posix_prefix = "/" if dir_posix == "" else dir_posix + "/"
        try:
            with os.scandir(current_dir) as it:
                for entry in it:
                    name = entry.name
                    try:
                        is_dir = entry.is_dir(follow_symlinks=False)
                    except OSError:
                        continue
                    if is_dir:
                        if should_skip_dir(name, include_system=include_system):
                            skipped_dirs += 1
                        else:
                            stack.append(entry.path)
                        continue
                    try:
                        if not entry.is_file(follow_symlinks=False):
                            continue
                        if should_skip_file(name, include_system=include_system):
                            continue
                        st = entry.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    size = int(st.st_size)
                    mtime = int(st.st_mtime)
                    total_size += size
                    _, ext = os.path.splitext(name)
                    ext_clean = ext.lstrip(".").upper() if ext else ""
                    full_posix = f"{dir_posix_prefix}{name}"
                    if full_posix.startswith(root_posix_prefix):
                        rel_posix = full_posix[len(root_posix_prefix):]
                    else:
                        rel_posix = os.path.relpath(entry.path, abs_root).replace("\\", "/")
                    files.append({
                        "n": name,
                        "d": mtime,
                        "s": size,
                        "t": categorize_extension(ext),
                        "e": ext_clean or "-",
                        "p": full_posix,
                        "r": rel_posix,
                    })
        except OSError:
            continue

    elapsed = round(time.perf_counter() - t0, 3)
    return {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "root": root_posix,
        "drive": get_drive_info(abs_root),
        "drives": list_mounted_drives(),
        "total_files": len(files),
        "total_size": total_size,
        "elapsed_sec": elapsed,
        "excluded_system": not include_system,
        "skipped_dirs": skipped_dirs,
        "files": files,
    }


def _compute_sha256(filepath: str, max_bytes: int = 256 * 1024 * 1024) -> str:
    try:
        if os.path.getsize(filepath) > max_bytes:
            return ""
        h = hashlib.sha256()
        with open(filepath, "rb") as fh:
            while True:
                chunk = fh.read(262144)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return ""


def _detect_actual_image_type(head: bytes) -> str | None:
    if head.startswith(b"\xff\xd8\xff"):
        return "JPG"
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "PNG"
    if head.startswith((b"GIF87a", b"GIF89a")):
        return "GIF"
    if head.startswith(b"RIFF") and len(head) >= 12 and head[8:12] == b"WEBP":
        return "WEBP"
    if head.startswith(b"BM"):
        return "BMP"
    return None


def _check_isobmff_atoms(filepath: str, file_size: int) -> tuple[bool, str]:
    has_moov = False
    offset = 0
    atom_count = 0
    try:
        with open(filepath, "rb") as fh:
            while offset < file_size and atom_count < 4096:
                if file_size - offset < 8:
                    return False, "Truncated ISO BMFF container atom at EOF."
                fh.seek(offset)
                hdr = fh.read(8)
                if len(hdr) < 8:
                    return False, "Truncated ISO BMFF atom header."
                size32, box_type = struct.unpack(">I4s", hdr)
                if box_type in (b"moov", b"moof"):
                    has_moov = True
                if size32 == 0:
                    offset = file_size
                    atom_count += 1
                    break
                if size32 == 1:
                    if file_size - offset < 16:
                        return False, "Truncated 64-bit ISO BMFF atom."
                    ext_hdr = fh.read(8)
                    if len(ext_hdr) < 8:
                        return False, "Truncated 64-bit ISO BMFF size."
                    box_size = struct.unpack(">Q", ext_hdr)[0]
                    if box_size < 16:
                        return False, "Invalid 64-bit ISO BMFF atom size."
                else:
                    box_size = size32
                    if box_size < 8:
                        return False, "Invalid ISO BMFF atom size."
                if offset + box_size > file_size:
                    return False, "ISO BMFF atom extends past end of file."
                offset += box_size
                atom_count += 1
    except OSError as exc:
        return False, f"Read error: {exc}"
    if not has_moov:
        return False, "Missing moov/moof metadata atom."
    return True, "Valid ISO BMFF container and moov structure."


def _check_zip_container(filepath: str, ext: str, file_size: int) -> tuple[str, str]:
    req_map = {
        "docx": "word/document.xml",
        "xlsx": "xl/workbook.xml",
        "pptx": "ppt/presentation.xml",
        "epub": "META-INF/container.xml",
    }
    try:
        with zipfile.ZipFile(filepath, "r") as zf:
            infos = zf.infolist()
            total_uncomp = sum(max(0, zi.file_size) for zi in infos)
            if total_uncomp > MAX_ZIP_TOTAL_UNCOMPRESSED or (file_size > 0 and total_uncomp > 64 * 1024 * 1024 and (total_uncomp / file_size) > 100):
                return "UNKNOWN", "Archive exceeds deep-decompression safety limit (possible compression bomb)."
            bad = zf.testzip()
            if bad is not None:
                return "CORRUPTED", f"Archive CRC check failed on {bad}."
            req = req_map.get(ext)
            if req and req not in {zi.filename for zi in infos}:
                return "CORRUPTED", f"Missing required {ext.upper()} component ({req})."
    except (zipfile.BadZipFile, OSError, EOFError, zlib.error, RuntimeError):
        return "CORRUPTED", "Damaged APK/ZIP structure." if ext == "apk" else "Damaged ZIP/OpenXML archive structure."
    if ext == "apk":
        return "VALID", "Valid APK (ZIP) container signature."
    if ext == "epub":
        return "VALID", "Valid EPUB (ZIP) container."
    return "VALID", "Valid ZIP/OpenXML PK header."


def _check_compressed_stream(opener, filepath: str) -> tuple[str, str]:
    total_read = 0
    try:
        with opener(filepath, "rb") as stream:
            while True:
                chunk = stream.read(262144)
                if not chunk:
                    break
                total_read += len(chunk)
                if total_read > MAX_DEEP_DECOMPRESS_BYTES:
                    return "UNKNOWN", "Archive exceeds deep-decompression safety limit (possible compression bomb)."
    except Exception:
        return "CORRUPTED", "Truncated or CRC-damaged compressed stream."
    return "VALID", ""


def check_file_integrity(filepath: str, deep: bool = False) -> dict[str, Any]:
    try:
        size = int(os.path.getsize(filepath))
    except OSError as exc:
        return {"status": "UNKNOWN", "details": f"Unreadable file metadata: {exc}", "size": 0, "sha256": ""}

    ext = os.path.splitext(filepath)[1].lstrip(".").lower()
    if size == 0:
        return {"status": "CORRUPTED", "details": "0-byte empty file.", "size": 0, "sha256": ""}

    try:
        with open(filepath, "rb") as fh:
            head = fh.read(4096)
    except OSError as exc:
        return {"status": "UNKNOWN", "details": f"Read permission or I/O error: {exc}", "size": size, "sha256": ""}

    def finish(status: str, details: str) -> dict[str, Any]:
        return {
            "status": status,
            "details": details,
            "size": size,
            "sha256": _compute_sha256(filepath) if deep else "",
        }

    def check_sig(ok: bool, good: str = "Valid header signature confirmed.", bad: str = "Invalid or missing container signature.") -> dict[str, Any]:
        return finish("VALID" if ok else "CORRUPTED", good if ok else bad)

    if ext in ("exe", "dll"):
        if not head.startswith(b"MZ"):
            return finish("CORRUPTED", "Missing DOS MZ signature.")
        if deep and len(head) >= 0x40:
            e_lfanew = struct.unpack_from("<I", head, 0x3C)[0]
            if 0x40 <= e_lfanew <= size - 4:
                try:
                    with open(filepath, "rb") as fh:
                        fh.seek(e_lfanew)
                        if fh.read(4) != b"PE\x00\x00":
                            return finish("CORRUPTED", "Invalid PE header signature at e_lfanew.")
                except OSError:
                    pass
            elif e_lfanew > size:
                return finish("CORRUPTED", "Truncated PE executable header.")
        return finish("VALID", "Valid PE/MZ header.")

    if ext == "so":
        return check_sig(head.startswith(b"\x7fELF"), "Valid ELF header.", "Missing ELF magic bytes.")

    if ext in ("apk", "zip", "docx", "xlsx", "pptx", "ods", "odt", "odp", "epub"):
        if not head.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
            bad_msg = (
                "Missing APK/ZIP header signature." if ext == "apk" else
                "Missing EPUB/ZIP PK header." if ext == "epub" else
                "Missing PK archive header."
            )
            return finish("CORRUPTED", bad_msg)
        if deep:
            st, msg = _check_zip_container(filepath, ext, size)
            return finish(st, msg)
        good_msg = (
            "Valid APK (ZIP) container signature." if ext == "apk" else
            "Valid EPUB (ZIP) container." if ext == "epub" else
            "Valid ZIP/OpenXML PK header."
        )
        return finish("VALID", good_msg)

    if ext == "dmg":
        if size >= 512:
            try:
                with open(filepath, "rb") as fh:
                    fh.seek(max(0, size - 512))
                    tail = fh.read(512)
                if b"koly" in tail or head.startswith(b"\x78\x01\x73\x0d\x62\x62\x60\x60"):
                    return finish("VALID", "Valid DMG UDIF koly signature.")
            except OSError:
                pass
        return finish(
            "VALID" if size > 512 else "UNKNOWN",
            "DMG structure plausible (trailer check requires full read)." if size > 512 else "DMG header inconclusive.",
        )

    if ext == "iso":
        if size < 2048:
            return finish("CORRUPTED", "File too small to be a valid ISO image.")
        if deep and size >= 0x8006:
            try:
                with open(filepath, "rb") as fh:
                    for off in (0x8001, 0x8801, 0x9001):
                        if off + 5 <= size:
                            fh.seek(off)
                            if fh.read(5) == b"CD001":
                                return finish("VALID", "Valid ISO 9660 CD001 primary volume descriptor.")
                return finish("UNKNOWN", "ISO header inconclusive.")
            except OSError:
                pass
        return finish("VALID", "ISO size plausible; deep sector check not possible in-browser.")

    if ext == "pdf":
        if b"%PDF-" not in head[:1024]:
            return finish("CORRUPTED", "Missing %PDF signature.")
        if deep:
            try:
                with open(filepath, "rb") as fh:
                    fh.seek(max(0, size - 4096))
                    if b"%%EOF" not in fh.read(4096):
                        return finish("CORRUPTED", "PDF truncated: missing %%EOF trailer marker.")
            except OSError:
                pass
        return finish("VALID", "Valid %PDF signature.")

    if ext == "rtf":
        return check_sig(head.lstrip().startswith(b"{\\rtf"), "Valid RTF {\\rtf signature.", "Missing RTF opening brace/signature.")

    if ext in ("txt", "csv", "md", "log", "ini", "cfg"):
        has_utf16 = head.startswith((b"\xff\xfe", b"\xfe\xff"))
        return check_sig(has_utf16 or b"\x00" not in head, "No binary NUL bytes; appears to be valid text.", "Binary NUL bytes detected in text file.")

    if ext in ("xml", "svg"):
        if ext == "svg":
            txt = head.decode("utf-8", errors="ignore").lower()
            if "<svg" not in txt and "<?xml" not in txt:
                return finish("CORRUPTED", "SVG missing <svg or <?xml tag.")
        else:
            if not head.lstrip(b"\xef\xbb\xbf\r\n\t ").startswith(b"<"):
                return finish("CORRUPTED", "Missing XML declaration or opening tag.")
        if deep and size <= 50 * 1024 * 1024:
            try:
                raw_xml = Path(filepath).read_bytes()
                upper_xml = raw_xml.upper()
                if b"<!ENTITY" not in upper_xml and b"<!DOCTYPE" not in upper_xml:
                    ET.fromstring(raw_xml)
            except ET.ParseError:
                return finish("CORRUPTED", "Malformed XML/SVG document tree.")
            except OSError:
                pass
        return finish("VALID", "SVG contains valid opening tag." if ext == "svg" else "Valid XML/UTF-8 BOM opening tag.")

    if ext == "json":
        snip = head.decode("utf-8-sig", errors="ignore").strip()
        if not (snip.startswith("{") or snip.startswith("[")):
            return finish("CORRUPTED", "JSON does not start with { or [.")
        if deep and size <= 50 * 1024 * 1024:
            try:
                json.loads(Path(filepath).read_text(encoding="utf-8-sig"))
            except Exception:
                return finish("CORRUPTED", "Malformed JSON syntax or truncated file.")
        return finish("VALID", "JSON opens with valid object or array.")

    if ext in ("html", "htm"):
        low = head.decode("utf-8-sig", errors="ignore").lower()
        valid_html = ("<html" in low or "<!doctype" in low or "<body" in low or "<head" in low) and b"\x00" not in head
        return check_sig(valid_html, "Valid HTML opening tag or structure.", "Missing HTML structure or invalid text file.")

    if ext in ("jpg", "jpeg", "png", "gif", "webp", "bmp", "tif", "tiff", "ico", "heic", "heif"):
        expected = {"jpg": "JPG", "jpeg": "JPG", "png": "PNG", "gif": "GIF", "webp": "WEBP"}.get(ext)
        actual = _detect_actual_image_type(head)
        if expected and actual and actual != expected:
            label_ext = ".jpg/.jpeg" if expected == "JPG" else f".{ext}"
            label_act = {"JPG": "JPEG", "PNG": "PNG", "GIF": "GIF", "WEBP": "WebP"}.get(actual, actual)
            return finish("UNKNOWN", f"Extension mismatch: file is a {label_act} image saved with a {label_ext} extension.")

        if ext in ("jpg", "jpeg"):
            if not head.startswith(b"\xff\xd8\xff"):
                return finish("CORRUPTED", "Invalid image magic bytes.")
            if deep:
                try:
                    with open(filepath, "rb") as fh:
                        fh.seek(max(0, size - 16384))
                        if b"\xff\xd9" not in fh.read(16384):
                            return finish("CORRUPTED", "Header valid, but image data fails to decode.")
                except OSError:
                    pass
            return finish("VALID", "Valid image header confirmed.")

        if ext == "png":
            if not head.startswith(b"\x89PNG\r\n\x1a\n"):
                return finish("CORRUPTED", "Invalid image magic bytes.")
            if deep:
                if len(head) < 24 or head[12:16] != b"IHDR":
                    return finish("CORRUPTED", "Header valid, but image data fails to decode.")
                try:
                    with open(filepath, "rb") as fh:
                        fh.seek(max(0, size - 4096))
                        if b"IEND\xaeB`\x82" not in fh.read(4096):
                            return finish("CORRUPTED", "Header valid, but image data fails to decode.")
                except OSError:
                    pass
            return finish("VALID", "Valid image header confirmed.")

        if ext == "gif":
            if not head.startswith((b"GIF87a", b"GIF89a")):
                return finish("CORRUPTED", "Invalid image magic bytes.")
            if deep and size > 14:
                try:
                    with open(filepath, "rb") as fh:
                        fh.seek(max(0, size - 64))
                        if not fh.read(64).rstrip(b"\x00 \r\n").endswith(b";"):
                            return finish("CORRUPTED", "Header valid, but image data fails to decode.")
                except OSError:
                    pass
            return finish("VALID", "Valid image header confirmed.")

        if ext == "webp":
            return check_sig(head.startswith(b"RIFF") and len(head) >= 12 and head[8:12] == b"WEBP", "Valid image header confirmed.", "Invalid image magic bytes.")

        if ext in ("heic", "heif"):
            return check_sig(head[4:16].startswith((b"ftypheic", b"ftypmsf1", b"ftypheif", b"ftypheix", b"ftyphevc", b"ftypmif1")), "Valid HEIC/HEIF ftyp atom.", "Missing HEIC/HEIF ftyp atom.")

        if ext == "bmp":
            return check_sig(head.startswith(b"BM") and size >= 26, "Valid image header confirmed.", "Invalid image magic bytes.")

        if ext in ("tif", "tiff"):
            return check_sig(head.startswith((b"II*\x00", b"MM\x00*")), "Valid image header confirmed.", "Invalid image magic bytes.")

        if ext == "ico":
            return check_sig(head.startswith((b"\x00\x00\x01\x00", b"\x00\x00\x02\x00")), "Valid ICO/CUR magic bytes.", "Missing ICO magic bytes.")

    if ext == "mp3":
        try:
            with open(filepath, "rb") as fh:
                scan_buf = fh.read(65536)
        except OSError:
            scan_buf = head
        is_id3v2 = b"ID3" in scan_buf[:4096]
        is_ftyp = b"ftyp" in head[:32]
        is_apev2 = b"APETAGEX" in head[:32]
        is_flv = b"FLV\x01" in head[:16]
        is_riff = head.startswith(b"RIFF")
        is_mpeg_sync = False
        for i in range(max(0, len(scan_buf) - 2)):
            if scan_buf[i] == 0x49 and scan_buf[i + 1] == 0x44 and scan_buf[i + 2] == 0x33:
                is_id3v2 = True
                break
            if scan_buf[i] == 0xFF and (scan_buf[i + 1] & 0xE0) == 0xE0 and (scan_buf[i + 1] & 0x06) != 0x00:
                is_mpeg_sync = True
                break
        is_id3v1 = False
        if not (is_id3v2 or is_mpeg_sync or is_ftyp or is_apev2 or is_flv or is_riff) and size >= 128:
            try:
                with open(filepath, "rb") as fh:
                    fh.seek(size - 128)
                    is_id3v1 = fh.read(3) == b"TAG"
            except OSError:
                pass
        if not (is_id3v2 or is_mpeg_sync or is_ftyp or is_apev2 or is_flv or is_riff or is_id3v1):
            return finish("CORRUPTED", "Invalid or missing container signature.")
        detail = (
            "M4A/MPEG-4 audio container with .mp3 extension (ftyp box detected)." if is_ftyp else
            "FLV Flash audio container detected." if is_flv else
            "RIFF wrapper detected." if is_riff else
            "ID3v1 tag only (no ID3v2/sync header)." if is_id3v1 else
            "APEv2 tag header detected." if is_apev2 else
            "Valid header signature confirmed."
        )
        return finish("VALID", detail)

    if ext == "aac":
        return check_sig((len(head) >= 2 and head[0] == 0xFF and (head[1] & 0xF6) in (0xF0, 0xE0)) or head.startswith((b"ADIF", b"ID3")) or head[4:8] == b"ftyp")

    if ext in ("m4a", "m4b", "m4p", "mp4", "m4v", "mp4v", "3gp", "3g2", "mov"):
        valid_atoms = (b"ftyp", b"moov", b"wide", b"mdat", b"free", b"skip", b"pnot") if ext == "mov" else (b"ftyp",)
        if head[4:8] not in valid_atoms:
            return finish("CORRUPTED", "Invalid or missing container signature.")
        if deep:
            ok_bmff, msg_bmff = _check_isobmff_atoms(filepath, size)
            if not ok_bmff:
                return finish("CORRUPTED", msg_bmff)
        return finish("VALID", "Valid header signature confirmed.")

    if ext in ("ogg", "oga", "opus", "ogv"):
        return check_sig(head.startswith(b"OggS"))
    if ext == "flac":
        return check_sig(head.startswith((b"fLaC", b"ID3")))
    if ext == "wav":
        ok = head.startswith(b"RIFF") and len(head) >= 12 and head[8:12] == b"WAVE"
        if ok and deep and size < 44:
            return finish("CORRUPTED", "Truncated WAV audio header.")
        return check_sig(ok)
    if ext in ("wma", "wmv", "asf"):
        return check_sig(head.startswith(b"\x30\x26\xb2\x75\x8e\x66\xcf\x11"))
    if ext in ("aiff", "aif"):
        return check_sig(head.startswith(b"FORM") and len(head) >= 12 and head[8:12] in (b"AIFF", b"AIFC"))
    if ext in ("mkv", "webm"):
        return check_sig(head.startswith(b"\x1a\x45\xdf\xa3"))
    if ext == "avi":
        ok = head.startswith(b"RIFF") and len(head) >= 12 and head[8:12] in (b"AVI ", b"AVIX")
        if ok and deep and size < 64:
            return finish("CORRUPTED", "Truncated AVI video container.")
        return check_sig(ok)
    if ext == "flv":
        return check_sig(head.startswith(b"FLV\x01"))
    if ext == "rar":
        return check_sig(head.startswith(b"Rar!\x1a\x07"), "Valid RAR signature.", "Missing RAR magic bytes.")

    if ext == "7z":
        if not head.startswith(b"\x37\x7a\xbc\xaf\x27\x1c"):
            return finish("CORRUPTED", "Missing 7z magic bytes.")
        if deep and len(head) >= 32:
            next_off, next_sz = struct.unpack_from("<QQ", head, 12)
            if 32 + next_off + next_sz > size:
                return finish("CORRUPTED", "Truncated 7-Zip archive container.")
        return finish("VALID", "Valid 7-Zip signature.")

    if ext in ("gz", "tgz", "bz2", "xz"):
        stream_specs = {
            "gz": (b"\x1f\x8b", gzip.GzipFile, "Valid GZip magic bytes.", "Missing GZip magic bytes."),
            "tgz": (b"\x1f\x8b", gzip.GzipFile, "Valid GZip magic bytes.", "Missing GZip magic bytes."),
            "bz2": (b"BZh", bz2.BZ2File, "Valid BZip2 signature (BZh).", "Missing BZip2 magic bytes."),
            "xz": (b"\xfd7zXZ\x00", lzma.LZMAFile, "Valid XZ signature.", "Missing XZ magic bytes."),
        }
        magic, opener, good_m, bad_m = stream_specs[ext]
        if not head.startswith(magic):
            return finish("CORRUPTED", bad_m)
        if deep and size <= 200 * 1024 * 1024:
            st, msg = _check_compressed_stream(opener, filepath)
            if st != "VALID":
                return finish(st, msg)
        return finish("VALID", good_m)

    if ext == "tar":
        is_ustar = len(head) >= 263 and head[257:262] == b"ustar"
        if not is_ustar and not tarfile.is_tarfile(filepath):
            return finish("CORRUPTED", "Missing ustar magic in TAR header block.")
        if deep:
            try:
                with tarfile.open(filepath, "r:*") as tf:
                    for _ in tf:
                        pass
            except Exception:
                return finish("CORRUPTED", "Truncated or invalid TAR member table.")
        return finish("VALID", "Valid TAR ustar magic confirmed.")

    if ext in ("zst", "zstd"):
        return check_sig(head.startswith(b"\x28\xb5\x2f\xfd"), "Valid Zstandard signature.", "Missing Zstandard magic bytes.")

    return finish("UNKNOWN", "Format not natively evaluated.")


def _resolve_deleter_root(raw_root: str) -> tuple[str | None, int, dict[str, Any] | None]:
    root_s = str(raw_root or "").strip()
    if not _is_safe_local_path(root_s):
        return None, 400, {"error": "INVALID_ROOT", "message": "Invalid root path parameter."}
    if _is_c_drive_blocked(root_s):
        return None, 403, {"error": "C_DRIVE_PROTECTED", "message": "C:\\ drive is strictly excluded from Deleter operations."}
    abs_root = os.path.abspath(root_s)
    if not os.path.isdir(abs_root) or os.path.islink(abs_root):
        return None, 404, {"error": "ROOT_NOT_FOUND", "message": f"Directory not found: {abs_root}"}
    return abs_root, 200, None


def _quarantine_paths(abs_root: str) -> tuple[str, str]:
    q_dir = os.path.join(abs_root, QUARANTINE_DIR_NAME)
    manifest_path = os.path.join(q_dir, QUARANTINE_MANIFEST_NAME)
    return q_dir, manifest_path


def _load_manifest(manifest_path: str) -> dict[str, Any]:
    if not os.path.isfile(manifest_path) or os.path.islink(manifest_path):
        return {"items": {}}
    try:
        data = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
        if isinstance(data, dict) and isinstance(data.get("items"), dict):
            return data
    except Exception:
        pass
    return {"items": {}}


def _save_manifest(q_dir: str, manifest_path: str, manifest: dict[str, Any]):
    os.makedirs(q_dir, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=q_dir, prefix=".tmp_q_", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, ensure_ascii=False, indent=2)
        os.replace(tmp_name, manifest_path)
    finally:
        if os.path.exists(tmp_name):
            try:
                os.unlink(tmp_name)
            except OSError:
                pass


def deleter_scan_directory(root_path: str, include_subfolders: bool = True, deep: bool = False) -> dict[str, Any]:
    t0 = time.perf_counter()
    abs_root = os.path.abspath(root_path)
    real_root = os.path.realpath(abs_root)

    results: list[dict[str, Any]] = []
    empty_folders: list[str] = []
    valid_cnt = corrupted_cnt = unknown_cnt = 0

    stack = [abs_root]
    while stack:
        current_dir = stack.pop()
        if _is_c_drive_blocked(current_dir) or os.path.islink(current_dir):
            continue
        child_dirs: list[str] = []
        child_files = 0
        try:
            with os.scandir(current_dir) as it:
                for entry in it:
                    name = entry.name
                    try:
                        is_dir = entry.is_dir(follow_symlinks=False)
                    except OSError:
                        continue
                    if is_dir:
                        low = name.lower()
                        if low in ("$recycle.bin", "system volume information", "_osiris_quarantine", "_osiris_runtime"):
                            continue
                        if _is_c_drive_blocked(entry.path):
                            continue
                        if include_subfolders:
                            stack.append(entry.path)
                        child_dirs.append(entry.path)
                        continue
                    try:
                        if not entry.is_file(follow_symlinks=False):
                            continue
                    except OSError:
                        continue
                    child_files += 1
                    if should_skip_file(name, include_system=False) or _is_protected_suite_path(entry.path):
                        continue
                    info = check_file_integrity(entry.path, deep=deep)
                    rel_path = os.path.relpath(entry.path, abs_root).replace("\\", "/")
                    _, ext = os.path.splitext(name)
                    status = info["status"]
                    if status == "VALID":
                        valid_cnt += 1
                    elif status == "CORRUPTED":
                        corrupted_cnt += 1
                    else:
                        unknown_cnt += 1
                    results.append({
                        "name": name,
                        "ext": ext.lstrip(".").lower() or "-",
                        "size": info["size"],
                        "status": status,
                        "details": info["details"],
                        "path": entry.path.replace("\\", "/"),
                        "rel": rel_path,
                        "sha256": info["sha256"],
                    })
        except OSError:
            continue

        if os.path.realpath(current_dir) != real_root and child_files == 0 and len(child_dirs) == 0:
            empty_folders.append(os.path.relpath(current_dir, abs_root).replace("\\", "/"))

    q_list = deleter_list_quarantine(abs_root)
    return {
        "root": abs_root.replace("\\", "/"),
        "deep": deep,
        "include_subfolders": include_subfolders,
        "elapsed_sec": round(time.perf_counter() - t0, 3),
        "counts": {
            "total": len(results),
            "valid": valid_cnt,
            "corrupted": corrupted_cnt,
            "unknown": unknown_cnt,
            "empty_folders": len(empty_folders),
        },
        "files": results,
        "empty_folders": empty_folders,
        "quarantine": q_list,
    }


def _safe_child_under(base_abs: str, rel_or_abs: str) -> str | None:
    if not _is_safe_local_path(rel_or_abs) if os.path.isabs(rel_or_abs) else ("\x00" in rel_or_abs or ":" in rel_or_abs):
        return None
    candidate = os.path.abspath(os.path.join(base_abs, rel_or_abs))
    if _is_c_drive_blocked(candidate) or os.path.islink(candidate):
        return None
    real_base = os.path.realpath(base_abs)
    real_cand = os.path.realpath(candidate)
    try:
        common = os.path.commonpath([real_base, real_cand])
    except ValueError:
        return None
    if common != real_base or real_cand == real_base:
        return None
    return candidate


def deleter_quarantine_files(
    abs_root: str,
    file_specs: list[dict[str, Any] | str],
    remove_empty_folders: bool = False,
) -> dict[str, Any]:
    q_dir, manifest_path = _quarantine_paths(abs_root)
    if os.path.islink(q_dir):
        return {"moved": [], "moved_count": 0, "removed_empty_dirs": [], "errors": [{"path": q_dir, "error": "Quarantine directory cannot be a symlink."}], "quarantine": deleter_list_quarantine(abs_root)}
    real_q_dir = os.path.realpath(q_dir)
    os.makedirs(q_dir, exist_ok=True)
    manifest = _load_manifest(manifest_path)
    items: dict[str, Any] = manifest["items"]

    moved: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    removed_dirs: list[str] = []

    for spec in file_specs:
        if isinstance(spec, dict):
            raw_rel = str(spec.get("rel") or spec.get("path") or "").strip()
            reason = str(spec.get("reason") or spec.get("details") or "Corrupted file")
        else:
            raw_rel = str(spec or "").strip()
            reason = "Corrupted file"

        if not raw_rel:
            continue

        src_abs = _safe_child_under(abs_root, raw_rel)
        if not src_abs or not os.path.isfile(src_abs) or os.path.islink(src_abs):
            errors.append({"path": raw_rel, "error": "File not found, symlink, or outside allowed root."})
            continue
        if _is_protected_suite_path(src_abs):
            errors.append({"path": raw_rel, "error": "Protected Osiris suite file cannot be quarantined."})
            continue
        real_src = os.path.realpath(src_abs)
        try:
            if os.path.commonpath([real_q_dir, real_src]) == real_q_dir:
                errors.append({"path": raw_rel, "error": "Already inside quarantine folder."})
                continue
        except ValueError:
            pass

        orig_rel = os.path.relpath(src_abs, abs_root).replace("\\", "/")
        dst_abs = os.path.join(q_dir, orig_rel.replace("/", os.sep))
        stem, ext = os.path.splitext(dst_abs)
        counter = 1
        while os.path.exists(dst_abs):
            dst_abs = f"{stem}__{counter}{ext}"
            counter += 1

        os.makedirs(os.path.dirname(dst_abs), exist_ok=True)
        try:
            size = int(os.path.getsize(src_abs))
            shutil.move(src_abs, dst_abs)
        except OSError as exc:
            errors.append({"path": orig_rel, "error": str(exc)})
            continue

        q_rel = os.path.relpath(dst_abs, q_dir).replace("\\", "/")
        entry = {
            "q_rel": q_rel,
            "q_abs": dst_abs.replace("\\", "/"),
            "name": os.path.basename(dst_abs),
            "orig_rel": orig_rel,
            "orig_abs": src_abs.replace("\\", "/"),
            "size": size,
            "reason": reason,
            "quarantined_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        items[q_rel] = entry
        moved.append(entry)

    if remove_empty_folders:
        real_root = os.path.realpath(abs_root)
        for dirpath, _, _ in os.walk(abs_root, topdown=False, followlinks=False):
            real_dp = os.path.realpath(dirpath)
            if real_dp == real_root or _is_c_drive_blocked(dirpath) or os.path.islink(dirpath):
                continue
            try:
                if os.path.commonpath([real_q_dir, real_dp]) == real_q_dir:
                    continue
            except ValueError:
                pass
            low_name = os.path.basename(dirpath).lower()
            if low_name in ("$recycle.bin", "system volume information", "files indexation_deleter"):
                continue
            try:
                if not os.listdir(dirpath):
                    os.rmdir(dirpath)
                    removed_dirs.append(os.path.relpath(dirpath, abs_root).replace("\\", "/"))
            except OSError:
                pass

    _save_manifest(q_dir, manifest_path, manifest)
    return {
        "moved": moved,
        "moved_count": len(moved),
        "removed_empty_dirs": removed_dirs,
        "errors": errors,
        "quarantine": deleter_list_quarantine(abs_root),
    }


def deleter_list_quarantine(abs_root: str) -> dict[str, Any]:
    q_dir, manifest_path = _quarantine_paths(abs_root)
    if not os.path.isdir(q_dir) or os.path.islink(q_dir):
        return {"quarantine_dir": q_dir.replace("\\", "/"), "total": 0, "total_size": 0, "items": []}

    manifest = _load_manifest(manifest_path)
    meta_map: dict[str, Any] = manifest.get("items", {})
    listed: list[dict[str, Any]] = []
    total_size = 0

    for dirpath, _, filenames in os.walk(q_dir, followlinks=False):
        for fname in filenames:
            if fname == QUARANTINE_MANIFEST_NAME or fname.startswith(".tmp_q_"):
                continue
            full_p = os.path.join(dirpath, fname)
            if _is_c_drive_blocked(full_p) or os.path.islink(full_p):
                continue
            try:
                st = os.stat(full_p, follow_symlinks=False)
            except OSError:
                continue
            q_rel = os.path.relpath(full_p, q_dir).replace("\\", "/")
            m = meta_map.get(q_rel) or {}
            size = int(st.st_size)
            total_size += size
            orig_rel = m.get("orig_rel") or q_rel
            orig_abs = m.get("orig_abs") or os.path.join(abs_root, orig_rel.replace("/", os.sep)).replace("\\", "/")
            listed.append({
                "q_rel": q_rel,
                "q_abs": full_p.replace("\\", "/"),
                "name": fname,
                "orig_rel": orig_rel,
                "orig_abs": orig_abs,
                "size": size,
                "reason": m.get("reason") or "Quarantined for manual check",
                "quarantined_at": m.get("quarantined_at") or datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
            })

    return {
        "quarantine_dir": q_dir.replace("\\", "/"),
        "total": len(listed),
        "total_size": total_size,
        "items": listed,
    }


def _prune_empty_quarantine_parents(q_dir: str, start_dir: str):
    real_q = os.path.realpath(q_dir)
    cur = start_dir
    while cur and os.path.realpath(cur) != real_q:
        try:
            if os.path.islink(cur) or os.path.commonpath([real_q, os.path.realpath(cur)]) != real_q:
                break
            if not os.listdir(cur):
                os.rmdir(cur)
                cur = os.path.dirname(cur)
            else:
                break
        except OSError:
            break


def deleter_restore_items(abs_root: str, q_rels: list[str]) -> dict[str, Any]:
    q_dir, manifest_path = _quarantine_paths(abs_root)
    if not os.path.isdir(q_dir) or os.path.islink(q_dir):
        return {"restored": [], "restored_count": 0, "errors": [], "quarantine": deleter_list_quarantine(abs_root)}
    manifest = _load_manifest(manifest_path)
    meta_map: dict[str, Any] = manifest["items"]

    restored: list[dict[str, str]] = []
    errors: list[dict[str, str]] = []

    for q_rel in q_rels:
        q_abs = _safe_child_under(q_dir, str(q_rel).replace("/", os.sep))
        if not q_abs or not os.path.isfile(q_abs) or os.path.islink(q_abs):
            errors.append({"q_rel": str(q_rel), "error": "Quarantined file not found."})
            continue
        norm_rel = os.path.relpath(q_abs, q_dir).replace("\\", "/")
        meta = meta_map.get(norm_rel) or {}
        target_rel = str(meta.get("orig_rel") or norm_rel)
        dst_abs = _safe_child_under(abs_root, target_rel.replace("/", os.sep))
        if not dst_abs:
            errors.append({"q_rel": norm_rel, "error": "Original target path is protected or invalid."})
            continue
        stem, ext = os.path.splitext(dst_abs)
        c = 1
        while os.path.exists(dst_abs):
            dst_abs = f"{stem}_restored{c}{ext}"
            c += 1
        os.makedirs(os.path.dirname(dst_abs), exist_ok=True)
        try:
            shutil.move(q_abs, dst_abs)
            _prune_empty_quarantine_parents(q_dir, os.path.dirname(q_abs))
            meta_map.pop(norm_rel, None)
            restored.append({"q_rel": norm_rel, "restored_to": dst_abs.replace("\\", "/")})
        except OSError as exc:
            errors.append({"q_rel": norm_rel, "error": str(exc)})

    if os.path.isdir(q_dir):
        _save_manifest(q_dir, manifest_path, manifest)
    return {
        "restored": restored,
        "restored_count": len(restored),
        "errors": errors,
        "quarantine": deleter_list_quarantine(abs_root),
    }


def deleter_purge_items(abs_root: str, q_rels: list[str], purge_all: bool = False) -> dict[str, Any]:
    q_dir, manifest_path = _quarantine_paths(abs_root)
    if not os.path.isdir(q_dir) or os.path.islink(q_dir):
        return {"deleted": [], "deleted_count": 0, "errors": [], "quarantine": deleter_list_quarantine(abs_root)}

    manifest = _load_manifest(manifest_path)
    meta_map: dict[str, Any] = manifest["items"]
    targets = [it["q_rel"] for it in deleter_list_quarantine(abs_root)["items"]] if purge_all else [str(x) for x in q_rels]

    deleted: list[str] = []
    errors: list[dict[str, str]] = []

    for q_rel in targets:
        q_abs = _safe_child_under(q_dir, q_rel.replace("/", os.sep))
        if not q_abs or not os.path.isfile(q_abs) or os.path.islink(q_abs):
            errors.append({"q_rel": q_rel, "error": "File not found inside quarantine folder."})
            continue
        if os.path.basename(q_abs) == QUARANTINE_MANIFEST_NAME:
            continue
        norm_rel = os.path.relpath(q_abs, q_dir).replace("\\", "/")
        try:
            os.unlink(q_abs)
            _prune_empty_quarantine_parents(q_dir, os.path.dirname(q_abs))
            meta_map.pop(norm_rel, None)
            deleted.append(norm_rel)
        except OSError as exc:
            errors.append({"q_rel": norm_rel, "error": str(exc)})

    remaining = deleter_list_quarantine(abs_root)
    if remaining["total"] == 0 and not os.path.islink(q_dir):
        try:
            if os.path.isfile(manifest_path) and not os.path.islink(manifest_path):
                os.unlink(manifest_path)
            shutil.rmtree(q_dir, ignore_errors=True)
        except OSError:
            pass
    else:
        _save_manifest(q_dir, manifest_path, manifest)

    return {
        "deleted": deleted,
        "deleted_count": len(deleted),
        "errors": errors,
        "quarantine": deleter_list_quarantine(abs_root),
    }


def install_desktop_shortcuts(include_start_menu: bool = True) -> dict[str, Any]:
    if os.name != "nt":
        return {"ok": False, "error": "Shortcut installation is supported on Windows only."}

    use_exe = EXE_PATH.is_file()
    target_bin = str(EXE_PATH if use_exe else Path(sys.executable))
    py_script = str(BASE_DIR / "files_indexer.py")
    work_dir = str(BASE_DIR)
    ico_path = DELETER_DIR / "osiris_suite.ico"
    del_ico_path = DELETER_DIR / "osiris_deleter.ico"
    icon_loc = f"{EXE_PATH},0" if use_exe else (str(ico_path) if ico_path.is_file() else f"{target_bin},0")
    del_icon_loc = str(del_ico_path) if del_ico_path.is_file() else icon_loc

    desktop = os.path.join(os.path.expanduser("~"), "Desktop")
    start_dir = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "Microsoft", "Windows", "Start Menu", "Programs", "Osiris Suite")
    destinations = [desktop]
    if include_start_menu:
        os.makedirs(start_dir, exist_ok=True)
        destinations.append(start_dir)

    created_paths: list[str] = []
    for folder in destinations:
        if os.path.isdir(folder):
            created_paths.append(os.path.join(folder, "Osiris Files Indexer.lnk"))
            created_paths.append(os.path.join(folder, "Osiris Files Checker & Deleter.lnk"))

    ps_script = (
        "$ws = New-Object -ComObject WScript.Shell; "
        "$dests = ($env:OSIRIS_DESTS -split '\\|') | Where-Object { $_ -and (Test-Path -LiteralPath $_) }; "
        "$specs = @("
        "  @('Osiris Files Indexer.lnk', $env:OSIRIS_ARG1, 'Osiris Portable Files Indexer (Read-Only)', $env:OSIRIS_ICO),"
        "  @('Osiris Files Checker & Deleter.lnk', $env:OSIRIS_ARG2, 'Osiris Corrupted Files Checker & Quarantine Deleter', $env:OSIRIS_DEL_ICO)"
        "); "
        "foreach ($d in $dests) { foreach ($sp in $specs) { "
        "  $s = $ws.CreateShortcut((Join-Path $d $sp[0])); "
        "  $s.TargetPath = $env:OSIRIS_TGT; "
        "  $s.Arguments = $sp[1]; "
        "  $s.WorkingDirectory = $env:OSIRIS_WRK; "
        "  $s.Description = $sp[2]; "
        "  $s.IconLocation = $sp[3]; "
        "  $s.Save(); "
        "} }"
    )
    encoded = base64.b64encode(ps_script.encode("utf-16le")).decode("ascii")
    env = os.environ.copy()
    env.update({
        "OSIRIS_DESTS": "|".join(destinations),
        "OSIRIS_TGT": target_bin,
        "OSIRIS_WRK": work_dir,
        "OSIRIS_ICO": icon_loc,
        "OSIRIS_DEL_ICO": del_icon_loc,
        "OSIRIS_ARG1": "" if use_exe else f'"{py_script}"',
        "OSIRIS_ARG2": "--deleter" if use_exe else f'"{py_script}" --deleter',
    })
    proc = subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded],
        capture_output=True,
        text=True,
        timeout=20,
        env=env,
    )
    if proc.returncode != 0:
        return {"ok": False, "error": proc.stderr.strip() or proc.stdout.strip() or "PowerShell shortcut error."}
    return {"ok": True, "created": created_paths, "target": target_bin}


def write_snapshot_js(payload: dict[str, Any], out_path: Path = DATA_JS_PATH) -> Path:
    if out_path.resolve() != DATA_JS_PATH.resolve():
        raise ValueError(f"Delete protection: target path blocked ({out_path})")
    dumped = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/")
    content = "window.FILES_INDEX_DATA = " + dumped + ";\n"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=str(out_path.parent), prefix=".tmp_idx_", suffix=".js")
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
        os.replace(str(tmp_path), str(out_path))
    finally:
        if tmp_path.exists() and tmp_path.name.startswith(".tmp_idx_") and tmp_path.name.endswith(".js"):
            try:
                tmp_path.unlink()
            except OSError:
                pass
    return out_path


_WIN_RESERVED_DEVICES = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}
_SANDBOXED_EXTS = {".html", ".htm", ".shtml", ".svg", ".svgz", ".xml", ".xhtml", ".xht", ".mht", ".mhtml"}
_SANDBOXED_MIMES = {"text/html", "image/svg+xml", "application/xhtml+xml", "application/xml", "text/xml", "multipart/related"}
_BLOCKED_DELETE_PATHS = ("/api/delete", "/api/remove", "/api/unlink", "/api/trash")


def _is_safe_local_path(raw_path: str) -> bool:
    if not raw_path or "\x00" in raw_path:
        return False
    stripped = raw_path.strip()
    if not stripped or stripped.startswith("\\\\") or stripped.startswith("//"):
        return False
    if ":" in stripped:
        if not (len(stripped) >= 2 and stripped[0].isalpha() and stripped[1] == ":" and ":" not in stripped[2:]):
            return False
        if len(stripped) >= 3 and stripped[2] not in ("\\", "/"):
            return False
    for part in stripped.replace("\\", "/").split("/"):
        if not part or part.endswith(":"):
            continue
        if part.split(".", 1)[0].upper() in _WIN_RESERVED_DEVICES:
            return False
    return True


def _is_host_drive(root_path: str) -> bool:
    norm = os.path.abspath(root_path).replace("\\", "/").rstrip("/").upper()
    host = DEFAULT_ROOT.replace("\\", "/").rstrip("/").upper()
    return norm == host


def _guess_mime(path_str: str) -> str:
    ext = os.path.splitext(path_str)[1].lower()
    if ext in EXTRA_MIMES:
        return EXTRA_MIMES[ext]
    mime, _ = mimetypes.guess_type(path_str)
    return mime or "application/octet-stream"


def _parse_range_header(range_hdr: str, file_size: int) -> tuple[int, int] | None:
    if not range_hdr or not range_hdr.lower().startswith("bytes="):
        return None
    spec = range_hdr[6:].split(",", 1)[0].strip()
    if "-" not in spec:
        return None
    start_s, end_s = spec.split("-", 1)
    if start_s == "" and end_s == "":
        return None
    if start_s == "":
        suffix_len = int(end_s)
        if suffix_len <= 0:
            return None
        start = max(0, file_size - suffix_len)
        end = file_size - 1
    else:
        start = int(start_s)
        end = int(end_s) if end_s else file_size - 1
    if start < 0 or start >= file_size or end < start:
        return None
    end = min(end, file_size - 1)
    return start, end


class FilesIndexHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = 60

    def _allowed_loopback_origins(self) -> tuple[str, ...]:
        port = self.server.server_address[1]
        return (
            "http://127.0.0.1",
            "http://localhost",
            "http://[::1]",
            f"http://127.0.0.1:{port}",
            f"http://localhost:{port}",
            f"http://[::1]:{port}",
        )

    def _validated_origin(self, allow_file_origin: bool = True) -> str | None:
        origin = (self.headers.get("Origin") or "").strip()
        if not origin:
            return None
        low = origin.lower()
        if low in self._allowed_loopback_origins():
            return origin
        if allow_file_origin and (low == "null" or low.startswith("file://")):
            return origin
        return None

    def _is_authorized_request(self, allow_file_origin: bool = True) -> bool:
        port = self.server.server_address[1]
        host_hdr = (self.headers.get("Host") or "").strip().lower()
        allowed_hosts = (
            "127.0.0.1",
            "localhost",
            "[::1]",
            f"127.0.0.1:{port}",
            f"localhost:{port}",
            f"[::1]:{port}",
        )
        if host_hdr not in allowed_hosts:
            self._send_json(403, {"error": "Forbidden host header"})
            return False

        origin = (self.headers.get("Origin") or "").strip()
        if origin and self._validated_origin(allow_file_origin=allow_file_origin) is None:
            self._send_json(403, {"error": "Forbidden origin"})
            return False

        sec_site = (self.headers.get("Sec-Fetch-Site") or "").strip().lower()
        if sec_site == "cross-site":
            if not allow_file_origin or (origin != "null" and not origin.lower().startswith("file://")):
                self._send_json(403, {"error": "Forbidden cross-site request"})
                return False
        return True

    def _require_csrf_token(self) -> bool:
        origin = (self.headers.get("Origin") or "").strip()
        if origin and self._validated_origin(allow_file_origin=False) is None:
            self._send_json(403, {"error": "CSRF_ORIGIN_BLOCKED", "message": "Privileged operations require same-origin local server context."})
            return False
        sec_site = (self.headers.get("Sec-Fetch-Site") or "").strip().lower()
        if sec_site == "cross-site":
            self._send_json(403, {"error": "CSRF_CROSS_SITE_BLOCKED"})
            return False
        supplied = (self.headers.get("X-Osiris-Token") or "").strip()
        if not supplied or not secrets.compare_digest(supplied, SERVER_TOKEN):
            self._send_json(403, {"error": "CSRF_TOKEN_INVALID", "message": "Missing or invalid session token."})
            return False
        return True

    def _send_common_headers(self, extra_no_store: bool = False, allow_file_origin: bool = True):
        allowed_origin = self._validated_origin(allow_file_origin=allow_file_origin)
        if allowed_origin is not None:
            self.send_header("Access-Control-Allow-Origin", allowed_origin)
        self.send_header("Vary", "Origin")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Range, X-Osiris-Token, Access-Control-Request-Private-Network")
        self.send_header("Access-Control-Expose-Headers", "Content-Range, Accept-Ranges, Content-Length")
        if allow_file_origin:
            self.send_header("Access-Control-Allow-Private-Network", "true")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        if extra_no_store:
            self.send_header("Cache-Control", "no-store")

    def _send_json(self, status_code: int, payload: dict[str, Any], allow_file_origin: bool = True):
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if status_code >= 400 or self.close_connection:
            self.close_connection = True
            self.send_header("Connection", "close")
        self._send_common_headers(extra_no_store=True, allow_file_origin=allow_file_origin)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _serve_static_file(self, path_obj: Path, content_type: str, inject_token: bool = False):
        if not path_obj.is_file():
            self._send_json(404, {"error": f"File not found: {path_obj.name}"})
            return
        data = path_obj.read_bytes()
        is_html = content_type.startswith("text/html")
        if inject_token and is_html:
            meta_tag = f'<meta name="osiris-token" content="{SERVER_TOKEN}">'.encode("utf-8")
            idx = data.find(b"<head>")
            if idx != -1:
                pos = idx + 6
                data = data[:pos] + b"\n" + meta_tag + data[pos:]
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        if is_html:
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Content-Security-Policy", "frame-ancestors 'none'")
        self._send_common_headers(extra_no_store=True, allow_file_origin=not is_html)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _read_json_body(self, max_bytes: int = 8 * 1024 * 1024) -> dict[str, Any] | None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except (TypeError, ValueError):
            self._send_json(400, {"error": "Invalid Content-Length"}, allow_file_origin=False)
            return None
        if length < 0 or length > max_bytes:
            self._send_json(413, {"error": "Payload too large"}, allow_file_origin=False)
            return None
        try:
            raw = self.rfile.read(length) if length > 0 else b"{}"
            body = json.loads(raw.decode("utf-8"))
            if not isinstance(body, dict):
                self._send_json(400, {"error": "Expected JSON object"}, allow_file_origin=False)
                return None
            return body
        except Exception:
            self._send_json(400, {"error": "Invalid JSON body"}, allow_file_origin=False)
            return None

    def _require_deleter_root(self, raw_root: str) -> str | None:
        abs_root, err_code, err_payload = _resolve_deleter_root(raw_root)
        if err_payload is not None or abs_root is None:
            self._send_json(err_code, err_payload or {"error": "Invalid root"}, allow_file_origin=False)
            return None
        return abs_root

    def do_OPTIONS(self):
        clean_path = urllib.parse.unquote(urllib.parse.urlparse(self.path).path)
        allow_file = not (clean_path in ("/api/open-location", "/api/heartbeat") or clean_path.startswith("/api/deleter/"))
        if not self._is_authorized_request(allow_file_origin=allow_file):
            return
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self._send_common_headers(extra_no_store=True, allow_file_origin=allow_file)
        self.end_headers()

    def do_HEAD(self):
        self.do_GET()

    def _reject_destructive(self, status_code: int = 405):
        if not self._is_authorized_request():
            return
        self._send_json(status_code, {
            "error": "Delete protection active: no files can be deleted or modified in indexer.",
            "delete_protected": True,
        })

    def do_DELETE(self):
        self._reject_destructive(405)

    def do_PUT(self):
        self._reject_destructive(405)

    def do_PATCH(self):
        self._reject_destructive(405)

    def do_GET(self):
        if not self._is_authorized_request():
            return
        parsed = urllib.parse.urlparse(self.path)
        clean_path = urllib.parse.unquote(parsed.path)
        qs = urllib.parse.parse_qs(parsed.query)

        if clean_path in _BLOCKED_DELETE_PATHS:
            self._reject_destructive(403)
            return

        if clean_path in ("/", "/FILES_INDEXATION_SYSTEM.html", "/index.html"):
            if self.command == "GET":
                self.server.mark_page_served()
            self._serve_static_file(HTML_PATH, "text/html; charset=utf-8", inject_token=True)
            return

        if clean_path in ("/deleter", "/FILES INDEXATION_DELETER/CHECKER_DELETER.html", "/FILES INDEXATION_DELETER/"):
            if self.command == "GET":
                self.server.mark_page_served()
            self._serve_static_file(DELETER_HTML_PATH, "text/html; charset=utf-8", inject_token=True)
            return

        if clean_path == "/favicon.ico":
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self._send_common_headers()
            self.end_headers()
            return

        if clean_path == "/files_index_data.js":
            self._serve_static_file(DATA_JS_PATH, "application/javascript; charset=utf-8")
            return

        if clean_path == "/api/status":
            self.server.extend_pending_open()
            self._send_json(200, {
                "online": True,
                "delete_protected": True,
                "read_only": True,
                "system_exclusion": True,
                "deleter_enabled": True,
                "deleter_c_excluded": True,
                "exe_present": EXE_PATH.is_file(),
                "default_root": DEFAULT_ROOT,
                "host_drive": get_drive_info(DEFAULT_ROOT),
                "drives": list_mounted_drives(),
                "deleter_drives": list_deleter_drives(),
            })
            return

        if clean_path == "/api/deleter/drives":
            self._send_json(200, {
                "c_excluded": True,
                "system_drive": os.environ.get("SystemDrive", "C:") + "\\",
                "default_root": DEFAULT_ROOT if not _is_c_drive_blocked(DEFAULT_ROOT) else "",
                "drives": list_deleter_drives(),
            })
            return

        if clean_path == "/api/deleter/quarantine":
            if not self._require_csrf_token():
                return
            abs_root = self._require_deleter_root((qs.get("root") or [DEFAULT_ROOT])[0].strip())
            if abs_root is None:
                return
            self._send_json(200, deleter_list_quarantine(abs_root), allow_file_origin=False)
            return

        if clean_path == "/api/index":
            root_arg = (qs.get("root") or [DEFAULT_ROOT])[0].strip() or DEFAULT_ROOT
            if not _is_safe_local_path(root_arg):
                self._send_json(400, {"error": "Invalid root path parameter."})
                return
            inc_sys = ((qs.get("include_system") or ["0"])[0] == "1")
            try:
                with _SCAN_LOCK:
                    payload = scan_directory(root_arg, include_system=inc_sys)
                    if _is_host_drive(root_arg) and not inc_sys:
                        write_snapshot_js(payload)
                self._send_json(200, payload)
            except FileNotFoundError as exc:
                self._send_json(404, {"error": str(exc)})
            except Exception as exc:
                self._send_json(500, {"error": str(exc)})
            return

        if clean_path == "/api/file":
            raw_p = (qs.get("path") or [""])[0]
            if not _is_safe_local_path(raw_p):
                self._send_json(400, {"error": "Missing or invalid path parameter."})
                return
            target = os.path.abspath(raw_p)
            if not os.path.isfile(target):
                self._send_json(404, {"error": f"File not found: {target}"})
                return
            self._stream_media_file(target)
            return

        self._send_json(404, {"error": "Endpoint not found"})

    def _stream_media_file(self, filepath: str):
        try:
            file_size = os.path.getsize(filepath)
        except OSError as exc:
            self._send_json(404, {"error": str(exc)})
            return

        mime = _guess_mime(filepath)
        range_hdr = self.headers.get("Range")
        byte_range = None
        if range_hdr:
            if file_size == 0:
                self.send_response(416)
                self.send_header("Content-Range", "bytes */0")
                self.send_header("Content-Length", "0")
                self._send_common_headers()
                self.end_headers()
                return
            try:
                byte_range = _parse_range_header(range_hdr, file_size)
            except ValueError:
                byte_range = None
            if byte_range is None:
                self.send_response(416)
                self.send_header("Content-Range", f"bytes */{file_size}")
                self.send_header("Content-Length", "0")
                self._send_common_headers()
                self.end_headers()
                return

        if byte_range is not None:
            start, end = byte_range
            length = end - start + 1
            self.send_response(206)
            self.send_header("Content-Range", f"bytes {start}-{end}/{file_size}")
        else:
            start = 0
            length = file_size
            self.send_response(200)

        self.send_header("Content-Type", mime)
        self.send_header("Accept-Ranges", "bytes")
        self.send_header("Content-Length", str(length))
        fname = os.path.basename(filepath)
        self.send_header("Content-Disposition", f"inline; filename*=UTF-8''{urllib.parse.quote(fname)}")
        if os.path.splitext(filepath)[1].lower() in _SANDBOXED_EXTS or mime.split(";", 1)[0].strip().lower() in _SANDBOXED_MIMES:
            self.send_header(
                "Content-Security-Policy",
                "sandbox; default-src 'none'; img-src 'self' data:; media-src 'self'; style-src 'unsafe-inline'",
            )
        self._send_common_headers()
        self.end_headers()

        if self.command == "HEAD" or length == 0:
            return

        chunk_size = 65536
        remaining = length
        try:
            with open(filepath, "rb") as fh:
                fh.seek(start)
                while remaining > 0:
                    chunk = fh.read(min(chunk_size, remaining))
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                    remaining -= len(chunk)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass

    def _open_explorer_path(self, raw_path: str):
        if not _is_safe_local_path(raw_path):
            self._send_json(400, {"error": "Missing or invalid path"}, allow_file_origin=False)
            return
        norm_target = os.path.normpath(os.path.abspath(raw_path))
        if not os.path.exists(norm_target):
            parent_dir = os.path.dirname(norm_target)
            if os.path.isdir(parent_dir):
                norm_target = parent_dir
            else:
                self._send_json(404, {"error": f"Path not found: {norm_target}"}, allow_file_origin=False)
                return
        try:
            if os.name == "nt":
                if os.path.isfile(norm_target):
                    subprocess.Popen(["explorer.exe", f"/select,{norm_target}"])
                else:
                    subprocess.Popen(["explorer.exe", norm_target])
            elif sys.platform == "darwin":
                subprocess.Popen(["open", "-R", norm_target] if os.path.isfile(norm_target) else ["open", norm_target])
            else:
                folder = os.path.dirname(norm_target) if os.path.isfile(norm_target) else norm_target
                subprocess.Popen(["xdg-open", folder])
            self._send_json(200, {"ok": True, "opened": norm_target}, allow_file_origin=False)
        except Exception as exc:
            self._send_json(500, {"error": str(exc)}, allow_file_origin=False)

    def do_POST(self):
        if not self._is_authorized_request(allow_file_origin=False):
            return
        parsed = urllib.parse.urlparse(self.path)
        clean_path = urllib.parse.unquote(parsed.path)

        if clean_path in _BLOCKED_DELETE_PATHS:
            self._reject_destructive(403)
            return

        if not self._require_csrf_token():
            return

        body = self._read_json_body()
        if body is None:
            return

        if clean_path == "/api/heartbeat":
            tab_id = str(body.get("tab_id") or "").strip()[:64]
            if not tab_id:
                self._send_json(400, {"error": "Missing tab_id"}, allow_file_origin=False)
                return
            hb_state = str(body.get("state") or "alive").strip().lower()
            active_cnt = self.server.record_heartbeat(tab_id, hb_state)
            if hb_state == "closing":
                self.close_connection = True
            self._send_json(200, {"ok": True, "active_tabs": active_cnt}, allow_file_origin=False)
            return

        if clean_path == "/api/open-location":
            self._open_explorer_path(str(body.get("path") or "").strip())
            return

        if clean_path == "/api/deleter/install":
            res = install_desktop_shortcuts(include_start_menu=bool(body.get("start_menu", True)))
            self._send_json(200 if res.get("ok") else 500, res, allow_file_origin=False)
            return

        if clean_path == "/api/deleter/scan":
            abs_root = self._require_deleter_root(str(body.get("root") or DEFAULT_ROOT).strip())
            if abs_root is None:
                return
            inc_sub = bool(body.get("include_subfolders", True))
            deep = bool(body.get("deep", False))
            with _DELETER_LOCK:
                res = deleter_scan_directory(abs_root, include_subfolders=inc_sub, deep=deep)
            self._send_json(200, res, allow_file_origin=False)
            return

        if clean_path == "/api/deleter/quarantine":
            abs_root = self._require_deleter_root(str(body.get("root") or "").strip())
            if abs_root is None:
                return
            files_list = body.get("files") or []
            if not isinstance(files_list, list):
                self._send_json(400, {"error": "files must be an array"}, allow_file_origin=False)
                return
            for entry in files_list:
                cand = entry.get("path") or entry.get("rel") or "" if isinstance(entry, dict) else str(entry or "")
                if os.path.isabs(cand) and _is_c_drive_blocked(cand):
                    self._send_json(403, {"error": "C_DRIVE_PROTECTED", "message": "C:\\ drive is strictly excluded from Deleter operations."}, allow_file_origin=False)
                    return
            rem_empty = bool(body.get("remove_empty_folders", False))
            with _DELETER_LOCK:
                res = deleter_quarantine_files(abs_root, files_list, remove_empty_folders=rem_empty)
            self._send_json(200, res, allow_file_origin=False)
            return

        if clean_path == "/api/deleter/restore":
            abs_root = self._require_deleter_root(str(body.get("root") or "").strip())
            if abs_root is None:
                return
            items = body.get("items") or []
            if not isinstance(items, list):
                self._send_json(400, {"error": "items must be an array"}, allow_file_origin=False)
                return
            with _DELETER_LOCK:
                res = deleter_restore_items(abs_root, [str(x) for x in items])
            self._send_json(200, res, allow_file_origin=False)
            return

        if clean_path == "/api/deleter/purge":
            abs_root = self._require_deleter_root(str(body.get("root") or "").strip())
            if abs_root is None:
                return
            items = body.get("items") or []
            purge_all = bool(body.get("all", False))
            if not isinstance(items, list):
                self._send_json(400, {"error": "items must be an array"}, allow_file_origin=False)
                return
            with _DELETER_LOCK:
                res = deleter_purge_items(abs_root, [str(x) for x in items], purge_all=purge_all)
            self._send_json(200, res, allow_file_origin=False)
            return

        self._send_json(404, {"error": "Endpoint not found"}, allow_file_origin=False)

    def log_message(self, format: str, *args):
        pass


class _ThreadingServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = os.name != "nt"

    def __init__(self, server_address, RequestHandlerClass):
        super().__init__(server_address, RequestHandlerClass)
        self._hb_lock = threading.Lock()
        self._active_tabs: dict[str, float] = {}
        self._had_client = False
        self._last_page_ts = -1.0
        self._last_close_ts = -1.0
        self._stop_watchdog = threading.Event()

    def mark_page_served(self):
        now = time.monotonic()
        with self._hb_lock:
            self._had_client = True
            self._last_page_ts = now

    def extend_pending_open(self):
        now = time.monotonic()
        with self._hb_lock:
            if self._had_client and not self._active_tabs:
                self._last_page_ts = now

    def record_heartbeat(self, tab_id: str, state: str = "alive") -> int:
        now = time.monotonic()
        with self._hb_lock:
            self._had_client = True
            if state == "closing":
                self._active_tabs.pop(tab_id, None)
                self._last_close_ts = now
            else:
                self._active_tabs[tab_id] = now
                if len(self._active_tabs) > 128:
                    oldest = sorted(self._active_tabs.items(), key=lambda kv: kv[1])[:-128]
                    for old_k, _ in oldest:
                        self._active_tabs.pop(old_k, None)
            return len(self._active_tabs)

    def start_auto_shutdown_watchdog(
        self,
        close_grace_sec: float = 3.0,
        page_boot_grace_sec: float = 15.0,
        stale_sec: float = 120.0,
        poll_sec: float = 0.4,
    ):
        def _watch():
            while not self._stop_watchdog.wait(poll_sec):
                if _SCAN_LOCK.locked() or _DELETER_LOCK.locked():
                    continue
                now = time.monotonic()
                should_stop = False
                with self._hb_lock:
                    if not self._had_client:
                        continue
                    if self._active_tabs:
                        stale_ids = [tid for tid, ts in self._active_tabs.items() if (now - ts) > stale_sec]
                        for tid in stale_ids:
                            self._active_tabs.pop(tid, None)
                        if stale_ids and not self._active_tabs:
                            self._last_close_ts = now
                    if not self._active_tabs:
                        if self._last_page_ts > self._last_close_ts:
                            if (now - self._last_page_ts) >= page_boot_grace_sec:
                                should_stop = True
                        elif self._last_close_ts >= 0.0 and (now - self._last_close_ts) >= close_grace_sec:
                            should_stop = True
                if should_stop:
                    self._stop_watchdog.set()
                    try:
                        self.shutdown()
                    except Exception:
                        pass
                    return

        t = threading.Thread(target=_watch, name="osiris-idle-watchdog", daemon=True)
        t.start()
        return t

    def server_close(self):
        self._stop_watchdog.set()
        super().server_close()


def create_server(port: int = DEFAULT_PORT, host: str = "127.0.0.1") -> _ThreadingServer:
    return _ThreadingServer((host, port), FilesIndexHandler)


def main():
    parser = argparse.ArgumentParser(description="FILES INDEXATION SYSTEM — Local Indexer & Deleter Suite")
    parser.add_argument("--scan-only", action="store_true", help="Scan drive, write files_index_data.js, and exit.")
    parser.add_argument("--root", default=DEFAULT_ROOT, help=f"Root drive or folder to index (default: {DEFAULT_ROOT}).")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"HTTP server port (default: {DEFAULT_PORT}).")
    parser.add_argument("--include-system", action="store_true", help="Include hidden system/cache folders.")
    parser.add_argument("--no-browser", action="store_true", help="Do not open browser automatically.")
    parser.add_argument("--no-auto-shutdown", action="store_true", help="Keep server running after all browser tabs close.")
    parser.add_argument("--deleter", action="store_true", help="Open Files Checker & Deleter directly.")
    parser.add_argument("--install", action="store_true", help="Install Desktop and Start Menu shortcuts for the portable suite.")
    args = parser.parse_args()

    if args.install:
        res = install_desktop_shortcuts(include_start_menu=True)
        print(json.dumps(res, ensure_ascii=False))
        if not args.scan_only and args.no_browser:
            return

    if args.scan_only:
        payload = scan_directory(args.root, include_system=args.include_system)
        snap = write_snapshot_js(payload)
        print(
            f"[INDEXED] root={payload['root']} files={payload['total_files']} "
            f"size={payload['total_size']} elapsed={payload['elapsed_sec']}s -> {snap}"
        )
        return

    route_suffix = "deleter" if args.deleter else ""
    url = f"http://127.0.0.1:{args.port}/{route_suffix}"

    try:
        server = create_server(port=args.port)
    except OSError as exc:
        print(f"[ERROR] Could not bind 127.0.0.1:{args.port}: {exc}")
        if not args.no_browser:
            webbrowser.open(url)
        return

    print(f"[SERVER] Listening on http://127.0.0.1:{args.port}/")
    if not args.no_auto_shutdown:
        server.start_auto_shutdown_watchdog()
    if not args.no_browser:
        threading.Timer(0.35, lambda: webbrowser.open(url)).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[SERVER] Shutting down.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
