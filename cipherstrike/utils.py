"""Filesystem safety, path validation, output naming, and shared helpers.

This module deliberately contains no cryptography.  All functions that touch
the filesystem either validate their inputs or fail closed.
"""

from __future__ import annotations

import os
import shutil
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping

from . import APP_NAME, __version__

PROJECT_ROOT = Path(__file__).resolve().parent.parent
OUTPUTS_DIR_NAME = "outputs"
CONTAINER_SUFFIX = ".csafe"
RECOVERY_SUFFIX = ".recovery"
PASSWORD_SUFFIX = ".password.txt"
MAX_NAME_LENGTH = 120
TEMP_PREFIX = ".cipherstrike-"


class CipherStrikeError(Exception):
    """Base class for expected, user-facing CIPHER STRIKE errors."""


class ValidationError(CipherStrikeError):
    """A path, selection, or input failed validation."""


class UnsafePathError(ValidationError):
    """An operation would touch an unsafe or unexpected path."""


class OutputExistsError(CipherStrikeError):
    """An output already exists and overwriting was not authorized."""


class OperationCancelled(CipherStrikeError):
    """The user or caller cancelled the operation before publication."""


class SourceChangedError(CipherStrikeError):
    """The source changed while it was being processed."""


class CleanupError(CipherStrikeError):
    """Temporary or backup data could not be removed safely."""


class SafeArchiveError(CipherStrikeError):
    """A folder archive contains an unsafe or malformed member."""


@dataclass(frozen=True)
class FileIdentity:
    """Stable identity of one filesystem object (lstat, never followed)."""

    kind: str
    dev: int
    ino: int
    mode: int
    size: int
    mtime_ns: int

    @classmethod
    def from_stat(cls, st: os.stat_result, kind: str) -> "FileIdentity":
        return cls(
            kind=kind,
            dev=getattr(st, "st_dev", 0),
            ino=getattr(st, "st_ino", 0),
            mode=stat.S_IMODE(st.st_mode),
            size=st.st_size,
            mtime_ns=st.st_mtime_ns,
        )


@dataclass(frozen=True)
class TreeSnapshot:
    """A complete, non-following snapshot of a directory tree."""

    root: FileIdentity
    entries: Mapping[str, FileIdentity]


def _display_path(path: Path) -> str:
    return str(path)


def strip_surrounding_quotes(value: str) -> str:
    """Remove one matching pair of single or double quotes from a path."""
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    return value


def expand_user_path(raw: str) -> Path:
    """Convert user input into an absolute path without silently resolving it."""
    if not isinstance(raw, str):
        raise ValidationError("Path must be text.")
    text = strip_surrounding_quotes(raw.strip())
    if not text:
        raise ValidationError("Path cannot be empty.")
    if "\x00" in text:
        raise ValidationError("Path contains an invalid NUL character.")
    expanded = os.path.expanduser(text)
    try:
        absolute = os.path.abspath(expanded)
    except OSError as exc:
        raise ValidationError(f"Invalid path: {exc}") from exc
    return Path(absolute)


def _lstat_or_error(path: Path, label: str) -> os.stat_result:
    try:
        return path.lstat()
    except FileNotFoundError as exc:
        raise ValidationError(f"{label} does not exist: {_display_path(path)}") from exc
    except PermissionError as exc:
        raise ValidationError(
            f"Permission denied while accessing {label}: {_display_path(path)}"
        ) from exc
    except OSError as exc:
        raise ValidationError(
            f"Cannot access {label}: {_display_path(path)} ({exc.strerror or exc})"
        ) from exc


def validate_source_file(raw_path: str) -> Path:
    """Validate a regular source file, rejecting symlinks and wrong types."""
    path = expand_user_path(raw_path)
    st = _lstat_or_error(path, "Source file")
    if stat.S_ISLNK(st.st_mode):
        raise ValidationError(
            "Symbolic links are not accepted as source files. "
            "Select the real file instead."
        )
    if not stat.S_ISREG(st.st_mode):
        raise ValidationError(
            f"The selected path is not a regular file: {_display_path(path)}"
        )
    if not os.access(path, os.R_OK):
        raise ValidationError(f"Source file is not readable: {_display_path(path)}")
    return path


def validate_source_directory(raw_path: str) -> Path:
    """Validate a real source directory, rejecting symlinks and filesystem root."""
    path = expand_user_path(raw_path)
    st = _lstat_or_error(path, "Source folder")
    if stat.S_ISLNK(st.st_mode):
        raise ValidationError(
            "Symbolic links are not accepted as source folders. "
            "Select the real folder instead."
        )
    if not stat.S_ISDIR(st.st_mode):
        raise ValidationError(f"The selected path is not a folder: {_display_path(path)}")
    if path.parent == path:
        raise ValidationError("The filesystem root cannot be encrypted.")
    if not os.access(path, os.R_OK | os.X_OK):
        raise ValidationError(f"Source folder is not readable: {_display_path(path)}")
    return path


def validate_encrypted_container(raw_path: str) -> Path:
    """Validate an encrypted container path without trusting its contents."""
    path = expand_user_path(raw_path)
    st = _lstat_or_error(path, "Encrypted container")
    if stat.S_ISLNK(st.st_mode):
        raise ValidationError(
            "Symbolic links are not accepted as encrypted containers. "
            "Select the real file instead."
        )
    if not stat.S_ISREG(st.st_mode):
        raise ValidationError(
            f"The encrypted container path is not a regular file: {_display_path(path)}"
        )
    if st.st_size < 64:
        raise ValidationError(
            f"The selected file is too small to be a CIPHER STRIKE container: "
            f"{_display_path(path)}"
        )
    if not os.access(path, os.R_OK):
        raise ValidationError(
            f"Encrypted container is not readable: {_display_path(path)}"
        )
    return path


def validate_recovery_file_path(raw_path: str) -> Path:
    """Validate a Recovery Key file path."""
    path = expand_user_path(raw_path)
    st = _lstat_or_error(path, "Recovery Key file")
    if stat.S_ISLNK(st.st_mode):
        raise ValidationError(
            "Symbolic links are not accepted as Recovery Key files. "
            "Select the real file instead."
        )
    if not stat.S_ISREG(st.st_mode):
        raise ValidationError(
            f"The Recovery Key path is not a regular file: {_display_path(path)}"
        )
    if not os.access(path, os.R_OK):
        raise ValidationError(f"Recovery Key file is not readable: {_display_path(path)}")
    return path


def default_outputs_dir() -> Path:
    """Return the project-local ``outputs`` directory."""
    return PROJECT_ROOT / OUTPUTS_DIR_NAME


def ensure_outputs_dir(path: Path | None = None) -> Path:
    """Create a private outputs directory and refuse symlinked directories."""
    directory = Path(path) if path is not None else default_outputs_dir()
    try:
        if directory.exists() or directory.is_symlink():
            st = directory.lstat()
            if stat.S_ISLNK(st.st_mode):
                raise UnsafePathError(
                    f"Refusing to use a symbolic link as the outputs directory: {directory}"
                )
            if not stat.S_ISDIR(st.st_mode):
                raise ValidationError(f"Outputs path is not a directory: {directory}")
        else:
            directory.mkdir(mode=0o700, parents=True)
    except OSError as exc:
        raise ValidationError(
            f"Cannot prepare outputs directory: {directory} ({exc.strerror or exc})"
        ) from exc
    try:
        os.chmod(directory, 0o700)
    except OSError:
        pass
    return directory


def sanitize_output_name(name: str, fallback: str = "cipherstrike_output") -> str:
    """Create a single safe path component for a restored or generated file."""
    if not isinstance(name, str):
        return fallback
    cleaned_chars: list[str] = []
    for char in name:
        if char in ("/", "\\") or ord(char) < 32 or ord(char) == 127:
            cleaned_chars.append("_")
        else:
            cleaned_chars.append(char)
    cleaned = "".join(cleaned_chars)
    if not cleaned.strip() or cleaned in {".", ".."}:
        cleaned = fallback
    if len(cleaned) > MAX_NAME_LENGTH:
        suffix = Path(cleaned).suffix
        if suffix and len(suffix) < 20 and len(cleaned) > len(suffix):
            stem_budget = MAX_NAME_LENGTH - len(suffix)
            cleaned = cleaned[:stem_budget].rstrip(" .") + suffix
        else:
            cleaned = cleaned[:MAX_NAME_LENGTH].rstrip(" .")
    if not cleaned:
        cleaned = fallback
    return cleaned


def artifact_base_name(source_name: str) -> str:
    """Derive the common artifact stem (``document.txt`` -> ``document``)."""
    name = Path(source_name).name
    stem = Path(name).stem
    return sanitize_output_name(stem or name, fallback="cipherstrike_output")


def allocate_artifact_paths(
    output_dir: Path, source_name: str
) -> tuple[Path, Path, Path]:
    """Pick three non-existing artifact paths without overwriting anything."""
    base = artifact_base_name(source_name)
    for counter in range(0, 10_000):
        candidate = base if counter == 0 else f"{base}-{counter}"
        container = output_dir / f"{candidate}{CONTAINER_SUFFIX}"
        recovery = output_dir / f"{candidate}{RECOVERY_SUFFIX}"
        password = output_dir / f"{candidate}{PASSWORD_SUFFIX}"
        if not any(p.exists() or p.is_symlink() for p in (container, recovery, password)):
            return container, recovery, password
    raise OutputExistsError(
        "Could not allocate a unique output name after 10,000 attempts."
    )


def artifact_paths_for_base(output_dir: Path, base: str) -> tuple[Path, Path, Path]:
    """Return the three paths for an already allocated base name."""
    return (
        output_dir / f"{base}{CONTAINER_SUFFIX}",
        output_dir / f"{base}{RECOVERY_SUFFIX}",
        output_dir / f"{base}{PASSWORD_SUFFIX}",
    )


def make_private_staging_dir(output_dir: Path) -> Path:
    """Create a private temporary directory on the output filesystem."""
    try:
        staging = Path(tempfile.mkdtemp(prefix=TEMP_PREFIX, dir=str(output_dir)))
        os.chmod(staging, 0o700)
        return staging
    except OSError as exc:
        raise ValidationError(
            f"Cannot create a temporary working directory in {output_dir}: "
            f"{exc.strerror or exc}"
        ) from exc


def fsync_file(path: Path) -> None:
    """Flush a file to stable storage where supported."""
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def fsync_directory(path: Path) -> None:
    """Best-effort directory fsync (not available on every platform)."""
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def write_private_text(path: Path, text: str) -> None:
    """Create a new private text file (never overwriting) and flush it."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError as exc:
        raise OutputExistsError(f"Refusing to overwrite existing file: {path}") from exc
    except OSError as exc:
        raise ValidationError(
            f"Cannot create private output file: {path} ({exc.strerror or exc})"
        ) from exc
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    except Exception:
        try:
            os.unlink(path)
        except OSError:
            pass
        raise


def safe_remove_path(path: Path, *, missing_ok: bool = True) -> None:
    """Remove one path without following symbolic links.

    This is used for temporary data and overwrite backups, never for a
    user-selected source without the additional snapshot checks below.
    """
    try:
        st = path.lstat()
    except FileNotFoundError:
        if missing_ok:
            return
        raise
    except OSError as exc:
        raise CleanupError(f"Cannot inspect path for cleanup: {path}") from exc
    try:
        if stat.S_ISDIR(st.st_mode):
            shutil.rmtree(path)
        else:
            path.unlink()
    except OSError as exc:
        raise CleanupError(f"Could not remove path: {path} ({exc.strerror or exc})") from exc


def assert_safe_deletion_target(path: Path) -> None:
    """Block deletion of a few catastrophic targets by accident."""
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise ValidationError(f"Cannot resolve source before deletion: {path}") from exc
    if resolved.parent == resolved:
        raise UnsafePathError("Refusing to delete a filesystem root.")
    home = Path.home().resolve()
    if resolved == home:
        raise UnsafePathError("Refusing to delete the current user's home directory.")
    project = PROJECT_ROOT.resolve()
    if resolved == project:
        raise UnsafePathError("Refusing to delete the CIPHER STRIKE project directory.")
    outputs = default_outputs_dir().resolve()
    if resolved == outputs:
        raise UnsafePathError("Refusing to delete the outputs directory.")


def identity_for_directory(path: Path) -> FileIdentity:
    st = _lstat_or_error(path, "Directory")
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise UnsafePathError(f"Expected a real directory: {path}")
    return FileIdentity.from_stat(st, "dir")


def snapshot_tree(root: Path) -> TreeSnapshot:
    """Snapshot a tree without following links; reject links and special files."""
    root_st = _lstat_or_error(root, "Directory")
    if stat.S_ISLNK(root_st.st_mode) or not stat.S_ISDIR(root_st.st_mode):
        raise UnsafePathError(f"Expected a real directory: {root}")
    entries: dict[str, FileIdentity] = {}
    stack: list[tuple[Path, str]] = [(root, "")]
    while stack:
        current, prefix = stack.pop()
        try:
            children = sorted(os.scandir(current), key=lambda e: e.name)
        except PermissionError as exc:
            raise ValidationError(f"Permission denied while reading folder: {current}") from exc
        except OSError as exc:
            raise ValidationError(f"Cannot read folder: {current} ({exc.strerror or exc})") from exc
        for child in children:
            rel = f"{prefix}{child.name}" if not prefix else f"{prefix}/{child.name}"
            try:
                # DirEntry.stat(follow_symlinks=False) reports zero device and
                # inode values on Windows; stat the path for stable identity.
                st = os.stat(child.path, follow_symlinks=False)
            except OSError as exc:
                raise ValidationError(f"Cannot inspect folder entry: {child.path}") from exc
            if stat.S_ISLNK(st.st_mode):
                raise UnsafePathError(
                    f"Symbolic links are not supported inside source folders: {child.path}"
                )
            if stat.S_ISDIR(st.st_mode):
                entries[rel] = FileIdentity.from_stat(st, "dir")
                stack.append((Path(child.path), rel))
            elif stat.S_ISREG(st.st_mode):
                entries[rel] = FileIdentity.from_stat(st, "file")
            else:
                raise UnsafePathError(
                    f"Special filesystem objects are not supported: {child.path}"
                )
    return TreeSnapshot(
        root=FileIdentity.from_stat(root_st, "dir"),
        entries=entries,
    )


def _identity_matches(current: FileIdentity, expected: FileIdentity) -> bool:
    return current == expected


def verify_file_snapshot(path: Path, expected: FileIdentity) -> None:
    st = _lstat_or_error(path, "Source file")
    if stat.S_ISLNK(st.st_mode):
        raise SourceChangedError(f"Source file was replaced by a symbolic link: {path}")
    current = FileIdentity.from_stat(st, "file" if stat.S_ISREG(st.st_mode) else "other")
    if current != expected:
        raise SourceChangedError(
            f"Source file changed after encryption and was not deleted: {path}"
        )


def verify_tree_snapshot(path: Path, expected: TreeSnapshot) -> None:
    try:
        current = snapshot_tree(path)
    except CipherStrikeError as exc:
        raise SourceChangedError(
            f"Source folder changed after encryption and was not deleted: {path} ({exc})"
        ) from exc
    if current.root != expected.root or dict(current.entries) != dict(expected.entries):
        raise SourceChangedError(
            f"Source folder changed after encryption and was not deleted: {path}"
        )


def delete_source_checked(path: Path, snapshot: FileIdentity | TreeSnapshot) -> None:
    """Delete a source only after proving it still matches the encrypted snapshot."""
    assert_safe_deletion_target(path)
    if isinstance(snapshot, TreeSnapshot):
        verify_tree_snapshot(path, snapshot)
        try:
            shutil.rmtree(path)
        except OSError as exc:
            raise CleanupError(
                f"Failed to delete source folder: {path} ({exc.strerror or exc})"
            ) from exc
    else:
        verify_file_snapshot(path, snapshot)
        try:
            path.unlink()
        except OSError as exc:
            raise CleanupError(
                f"Failed to delete source file: {path} ({exc.strerror or exc})"
            ) from exc


def readable_list(items: Iterable[str], limit: int = 5) -> str:
    """Format a short, bounded list for user-facing messages."""
    values = list(items)
    shown = values[:limit]
    suffix = "" if len(values) <= limit else f", and {len(values) - limit} more"
    return ", ".join(shown) + suffix


def app_identity() -> tuple[str, str]:
    return APP_NAME, __version__
