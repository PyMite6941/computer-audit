"""Storage bloat scanner.

Scans a device's storage for uncritical bloat that can be safely removed:
- Temporary files and folders
- Browser and system caches
- Old download files
- Large unused files
- Duplicate files (by hash)
- Thumbnail caches
- Log files older than threshold
- Empty folders

Designed to run portably on any attached device (Windows, macOS, Linux).
Stdlib-only — no mandatory installs.
"""

from __future__ import annotations

import hashlib
import os
import platform
import stat
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from typing import Any


# File patterns commonly considered bloat
BLOAT_NAME_PATTERNS = (
    ".tmp", ".temp", ".cache", ".log", ".old", ".bak", ".backup",
    ".dmp", ".mdmp", ".wer", ".etl", ".trace",
    "Thumbs.db", "desktop.ini", ".DS_Store",
)

BLOAT_DIR_NAMES = (
    "__pycache__", ".cache", "cache", "tmp", "temp",
    "Thumbnail Cache", "thumbnails", ".thumbnails",
    "Recent", "Cookies", "History",
)

# Common bloat root locations per OS (scanned if they exist)
BLOAT_ROOTS_WINDOWS = [
    os.path.expandvars(r"%TEMP%"),
    os.path.expandvars(r"%TMP%"),
    os.path.expandvars(r"%LOCALAPPDATA%\Temp"),
    os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Windows\INetCache"),
    os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Windows\WebCache"),
    os.path.expandvars(r"%USERPROFILE%\Downloads"),
    os.path.expandvars(r"%USERPROFILE%\AppData\Local\Microsoft\Windows\Explorer"),
    os.path.expandvars(r"%USERPROFILE%\AppData\Local\CrashDumps"),
    os.path.expandvars(r"%SYSTEMROOT%\Temp"),
    os.path.expandvars(r"%SYSTEMROOT%\Prefetch"),
]

BLOAT_ROOTS_DARWIN = [
    os.path.expanduser("~/Library/Caches"),
    os.path.expanduser("~/Library/Logs"),
    os.path.expanduser("~/Downloads"),
    os.path.expanduser("~/Library/Containers/com.apple.Safari/Cache"),
    os.path.expanduser("~/Library/Safari/Databases"),
    "/private/var/log",
    "/private/var/folders",
]

BLOAT_ROOTS_LINUX = [
    os.path.expanduser("~/.cache"),
    os.path.expanduser("~/.local/share/Trash"),
    os.path.expanduser("~/Downloads"),
    os.path.expanduser("~/.thumbnails"),
    "/var/log",
    "/var/tmp",
    "/tmp",
]


def _bloat_roots() -> list[str]:
    os_name = platform.system().lower()
    if os_name == "windows":
        return BLOAT_ROOTS_WINDOWS
    if os_name == "darwin":
        return BLOAT_ROOTS_DARWIN
    return BLOAT_ROOTS_LINUX


@dataclass
class BloatFile:
    path: str
    size: int
    category: str          # temp | cache | log | old-download | large-unused | duplicate | thumbnail | empty-dir
    detail: str
    risk: str = "low"      # low | medium | high
    removable: bool = True


@dataclass
class StorageBloatReport:
    os: str
    scanned_roots: list[str]
    files: list[dict[str, Any]]
    total_size: int
    file_count: int
    by_category: dict[str, int]
    summary: str


def _file_size(path: str) -> int:
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


def _file_hash(path: str, chunk_size: int = 65536) -> str | None:
    """Return SHA-256 of a file, or None if unreadable."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(chunk_size), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def _is_name_bloat(name: str) -> bool:
    low = name.lower()
    return any(p in low for p in BLOAT_NAME_PATTERNS) or low in BLOAT_DIR_NAMES


def _age_days(path: str) -> float:
    try:
        mtime = os.path.getmtime(path)
        return (time.time() - mtime) / 86400.0
    except OSError:
        return 0.0


def _scan_directory(root: str, max_files: int = 50000) -> list[BloatFile]:
    """Walk a single root directory and collect bloat candidates."""
    found: list[BloatFile] = []
    count = 0
    try:
        for dirpath, dirnames, filenames in os.walk(root, onerror=lambda e: None):
            # Prune deep system directories to avoid scanning the whole OS
            depth = dirpath[len(root):].count(os.sep)
            if depth > 4:
                dirnames[:] = []
                continue

            # Skip system-critical dirs
            base = os.path.basename(dirpath).lower()
            if base in ("windows", "system32", "syswow64", "bin", "sbin", "lib", "lib64", "usr", "boot", "etc", "proc", "sys", "dev", "run", "var/lib", "var/cache"):
                dirnames[:] = []
                continue

            for name in dirnames:
                full = os.path.join(dirpath, name)
                if _is_name_bloat(name):
                    try:
                        st = os.lstat(full)
                        if stat.S_ISDIR(st.st_mode) and not os.listdir(full):
                            found.append(BloatFile(
                                path=full, size=0, category="empty-dir",
                                detail="Empty folder — likely leftover bloat",
                                risk="low",
                            ))
                    except OSError:
                        pass

            for name in filenames:
                count += 1
                if count > max_files:
                    break
                full = os.path.join(dirpath, name)
                try:
                    st = os.lstat(full)
                except OSError:
                    continue
                if not stat.S_ISREG(st.st_mode):
                    continue

                size = st.st_size
                age = _age_days(full)
                low = name.lower()

                # Temp / cache files
                if _is_name_bloat(name):
                    cat = "temp" if any(p in low for p in (".tmp", ".temp", ".dmp", ".mdmp", ".wer")) else "cache"
                    found.append(BloatFile(
                        path=full, size=size, category=cat,
                        detail=f"{os.path.basename(name)} — {cat} file, {age:.0f} days old",
                        risk="low",
                    ))
                    continue

                # Log files older than 7 days
                if low.endswith(".log") and age > 7:
                    found.append(BloatFile(
                        path=full, size=size, category="log",
                        detail=f"Log file {age:.0f} days old",
                        risk="low",
                    ))
                    continue

                # Old downloads older than 30 days and > 1 MB
                if "download" in dirpath.lower() and age > 30 and size > 1024 * 1024:
                    found.append(BloatFile(
                        path=full, size=size, category="old-download",
                        detail=f"Download {age:.0f} days old, {size / 1024 / 1024:.1f} MB",
                        risk="low",
                    ))
                    continue

                # Large unused files (> 100 MB, > 90 days old)
                if size > 100 * 1024 * 1024 and age > 90:
                    found.append(BloatFile(
                        path=full, size=size, category="large-unused",
                        detail=f"Large unused file {age:.0f} days old, {size / 1024 / 1024:.1f} MB",
                        risk="medium",
                    ))
    except OSError:
        pass
    return found


def _find_duplicates(files: list[BloatFile]) -> list[BloatFile]:
    """Mark duplicate files by hash (keep first, flag rest)."""
    seen: dict[str, str] = {}
    dupes: list[BloatFile] = []
    for bf in files:
        if bf.category in ("empty-dir",) or bf.size == 0:
            continue
        h = _file_hash(bf.path)
        if h is None:
            continue
        if h in seen:
            dupes.append(BloatFile(
                path=bf.path, size=bf.size, category="duplicate",
                detail=f"Duplicate of {seen[h]}",
                risk="low",
            ))
        else:
            seen[h] = bf.path
    return dupes


class StorageBloatScanner:
    """Scans storage for removable bloat in parallel."""

    def __init__(self, roots: list[str] | None = None, max_files_per_root: int = 20000) -> None:
        self.roots = roots or [r for r in _bloat_roots() if os.path.exists(r)]
        self.max_files_per_root = max_files_per_root
        self.os = platform.system().lower()

    def scan(self) -> StorageBloatReport:
        all_files: list[BloatFile] = []
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {
                executor.submit(_scan_directory, root, self.max_files_per_root): root
                for root in self.roots
            }
            for future in as_completed(futures):
                try:
                    all_files.extend(future.result())
                except Exception:  # noqa: BLE001 - one root failing is non-fatal
                    pass

        # Find duplicates
        duplicates = _find_duplicates(all_files)
        all_files.extend(duplicates)

        total_size = sum(f.size for f in all_files)
        by_category: dict[str, int] = {}
        for f in all_files:
            by_category[f.category] = by_category.get(f.category, 0) + 1

        summary = (
            f"{len(all_files)} bloat file(s) found across {len(self.roots)} root(s), "
            f"{total_size / 1024 / 1024:.1f} MB total. "
            + ", ".join(f"{k}: {v}" for k, v in sorted(by_category.items()))
        )
        return StorageBloatReport(
            os=self.os,
            scanned_roots=self.roots,
            files=[asdict(f) for f in all_files],
            total_size=total_size,
            file_count=len(all_files),
            by_category=by_category,
            summary=summary,
        )
