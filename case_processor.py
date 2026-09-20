"""Secure evidence intake and forensic metadata for StealerScope."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import tempfile
from datetime import datetime, timezone
import zipfile

from stream_log_parser import StreamLogParser

TOOL_NAME = "StealerScope"
TOOL_VERSION = "0.3.0"
SUPPORTED_ARCHIVES = {".zip", ".7z", ".rar"}
DEFAULT_MAX_FILES = 50_000
DEFAULT_MAX_MEMBER_BYTES = 1024 ** 3
DEFAULT_MAX_TOTAL_BYTES = 5 * 1024 ** 3
DEFAULT_MAX_COMPRESSION_RATIO = 200


class IntakeError(ValueError):
    """Raised when evidence intake cannot be completed safely."""


def sha256_file(path: os.PathLike | str, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_relative(name: str) -> Path:
    normalized = name.replace("\\", "/")
    path = PurePosixPath(normalized)
    if not normalized or path.is_absolute() or ".." in path.parts:
        raise IntakeError(f"Unsafe archive member path: {name!r}")
    if path.parts and (":" in path.parts[0] or path.parts[0] in (".", "")):
        raise IntakeError(f"Unsafe archive member path: {name!r}")
    return Path(*path.parts)


def _check_limits(entries, max_files, max_member_bytes, max_total_bytes):
    files = [entry for entry in entries if not entry[2]]
    if len(files) > max_files:
        raise IntakeError(f"Archive contains {len(files)} files; limit is {max_files}.")
    total = 0
    for name, size, _ in files:
        _safe_relative(name)
        if size < 0 or size > max_member_bytes:
            raise IntakeError(f"Archive member exceeds size limit: {name!r}")
        total += size
        if total > max_total_bytes:
            raise IntakeError(f"Archive expanded size exceeds {max_total_bytes} bytes.")


def _copy_limited(source, destination, expected_size, max_member_bytes, remaining_total):
    written = 0
    with open(destination, "xb") as output:
        while True:
            chunk = source.read(min(1024 * 1024, max_member_bytes - written + 1))
            if not chunk:
                break
            written += len(chunk)
            if written > max_member_bytes or written > remaining_total:
                raise IntakeError("Archive expanded beyond the configured extraction limit.")
            output.write(chunk)
    if expected_size is not None and written != expected_size:
        raise IntakeError(f"Archive member size mismatch for {destination.name!r}.")
    return written


def _extract_zip(path, destination, password, limits):
    max_files, max_member, max_total, max_ratio = limits
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        entries = [(item.filename, item.file_size, item.is_dir()) for item in infos]
        _check_limits(entries, max_files, max_member, max_total)
        for item in infos:
            mode = item.external_attr >> 16
            if stat.S_ISLNK(mode):
                raise IntakeError(f"Symbolic-link archive member rejected: {item.filename!r}")
            if not item.is_dir() and item.file_size and item.compress_size == 0:
                raise IntakeError(f"Invalid compression metadata for {item.filename!r}")
            if not item.is_dir() and item.file_size / max(item.compress_size, 1) > max_ratio:
                raise IntakeError(f"Compression ratio limit exceeded: {item.filename!r}")
        total = 0
        pwd = password.encode("utf-8") if password else None
        for item in infos:
            relative = _safe_relative(item.filename)
            target = destination / relative
            if item.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            try:
                with archive.open(item, pwd=pwd) as source:
                    total += _copy_limited(source, target, item.file_size, max_member, max_total - total)
            except RuntimeError as error:
                raise IntakeError("Archive password is missing or incorrect.") from error
    return len([item for item in infos if not item.is_dir()]), total


def _extract_rar(path, destination, password, limits):
    try:
        import rarfile
    except ImportError as error:
        raise IntakeError("RAR support requires the optional 'rarfile' package and a compatible backend.") from error
    max_files, max_member, max_total, _ = limits
    with rarfile.RarFile(path) as archive:
        infos = archive.infolist()
        entries = [(item.filename, item.file_size, item.isdir()) for item in infos]
        _check_limits(entries, max_files, max_member, max_total)
        total = 0
        for item in infos:
            if getattr(item, "is_symlink", lambda: False)():
                raise IntakeError(f"Symbolic-link archive member rejected: {item.filename!r}")
            target = destination / _safe_relative(item.filename)
            if item.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            try:
                with archive.open(item, pwd=password) as source:
                    total += _copy_limited(source, target, item.file_size, max_member, max_total - total)
            except rarfile.PasswordRequired as error:
                raise IntakeError("Archive password is missing or incorrect.") from error
    return len([item for item in infos if not item.isdir()]), total


def _extract_7z(path, destination, password, limits):
    try:
        import py7zr
    except ImportError as error:
        raise IntakeError("7z support requires the optional 'py7zr' package.") from error
    max_files, max_member, max_total, _ = limits
    try:
        with py7zr.SevenZipFile(path, mode="r", password=password) as archive:
            infos = archive.list()
            entries = [(item.filename, item.uncompressed or 0, item.is_directory) for item in infos]
            _check_limits(entries, max_files, max_member, max_total)
            for item in infos:
                if getattr(item, "is_symlink", False):
                    raise IntakeError(f"Symbolic-link archive member rejected: {item.filename!r}")
            archive.extractall(path=destination)
    except getattr(py7zr.exceptions, "PasswordRequired", Exception) as error:
        raise IntakeError("Archive password is missing or incorrect.") from error
    return _validate_extracted(destination, max_files, max_member, max_total)


def _validate_extracted(root, max_files, max_member, max_total):
    count = total = 0
    root_resolved = root.resolve()
    for path in root.rglob("*"):
        if path.is_symlink():
            raise IntakeError(f"Extracted symbolic link rejected: {path.name!r}")
        if not path.is_file():
            continue
        if root_resolved not in path.resolve().parents:
            raise IntakeError("Archive extraction escaped the temporary workspace.")
        size = path.stat().st_size
        count += 1
        total += size
        if count > max_files or size > max_member or total > max_total:
            raise IntakeError("Extracted archive exceeds configured limits.")
    return count, total


def _remap_sources(value, root: Path, prefix: str):
    if isinstance(value, dict):
        for key, item in list(value.items()):
            if key == "source" and isinstance(item, str):
                try:
                    relative = Path(item).resolve().relative_to(root.resolve()).as_posix()
                except (ValueError, OSError):
                    continue
                value[key] = f"{prefix}::{relative}"
            else:
                _remap_sources(item, root, prefix)
    elif isinstance(value, list):
        for item in value:
            _remap_sources(item, root, prefix)


class CaseProcessor:
    def __init__(self, input_path, password=None, case_id="", examiner="", evidence_number="",
                 max_files=DEFAULT_MAX_FILES, max_member_bytes=DEFAULT_MAX_MEMBER_BYTES,
                 max_total_bytes=DEFAULT_MAX_TOTAL_BYTES,
                 max_compression_ratio=DEFAULT_MAX_COMPRESSION_RATIO):
        self.input_path = Path(input_path)
        self.password = password
        self.case_id = case_id
        self.examiner = examiner
        self.evidence_number = evidence_number
        self.limits = (max_files, max_member_bytes, max_total_bytes, max_compression_ratio)

    def process(self):
        if not self.input_path.exists():
            raise FileNotFoundError(f"Input does not exist: {self.input_path}")
        started = datetime.now(timezone.utc)
        source_type = "directory" if self.input_path.is_dir() else "archive"
        source_hash = None if source_type == "directory" else sha256_file(self.input_path)
        audit = [{"timestamp_utc": started.strftime("%d-%b-%Y %H:%M:%S UTC"),
                  "action": "intake_started", "input": str(self.input_path), "source_type": source_type}]
        if source_type == "directory":
            root = self.input_path
            data = StreamLogParser(root).parse_logs_stream()
            extracted_files = data["import_summary"]["files_enumerated"]
            extracted_bytes = sum(Path(item["source"]).lstat().st_size for item in data["source_files"]
                                  if item.get("entry_type") == "file"
                                  and stat.S_ISREG(Path(item["source"]).lstat().st_mode))
        else:
            extension = self.input_path.suffix.lower()
            if extension not in SUPPORTED_ARCHIVES:
                raise IntakeError(f"Unsupported archive type: {extension or '(none)'}")
            with tempfile.TemporaryDirectory(prefix="stealerscope-") as temp:
                root = Path(temp)
                if extension == ".zip":
                    extracted_files, extracted_bytes = _extract_zip(self.input_path, root, self.password, self.limits)
                elif extension == ".rar":
                    extracted_files, extracted_bytes = _extract_rar(self.input_path, root, self.password, self.limits)
                else:
                    extracted_files, extracted_bytes = _extract_7z(self.input_path, root, self.password, self.limits)
                data = StreamLogParser(root).parse_logs_stream()
                self._add_file_metadata(data, root)
                _remap_sources(data, root, self.input_path.name)
        if source_type == "directory":
            self._add_file_metadata(data, root)
        completed = datetime.now(timezone.utc)
        audit.append({"timestamp_utc": completed.strftime("%d-%b-%Y %H:%M:%S UTC"),
                      "action": "intake_completed", "files_discovered": extracted_files,
                      "bytes_discovered": extracted_bytes})
        data["case_metadata"] = {
            "case_id": self.case_id, "examiner": self.examiner,
            "evidence_number": self.evidence_number, "tool": TOOL_NAME,
            "tool_version": TOOL_VERSION, "processed_utc": completed.strftime("%d-%b-%Y %H:%M:%S UTC"),
            "input_name": self.input_path.name, "input_path": str(self.input_path),
            "input_type": source_type, "input_sha256": source_hash,
            "password_provided": bool(self.password),
            "extracted_file_count": extracted_files, "extracted_byte_count": extracted_bytes,
        }
        data["audit_log"] = audit
        return data

    @staticmethod
    def _add_file_metadata(data, root):
        root = Path(root)
        for item in data.get("source_files", []):
            if item.get("entry_type") != "file":
                continue
            path = Path(item["source"])
            try:
                file_stat = path.lstat()
            except OSError:
                continue
            if stat.S_ISREG(file_stat.st_mode):
                item["size_bytes"] = file_stat.st_size
                item["sha256"] = sha256_file(path)
                try:
                    item["relative_path"] = path.resolve().relative_to(root.resolve()).as_posix()
                except ValueError:
                    item["relative_path"] = path.name
