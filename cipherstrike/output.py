"""Safe creation and replacement of user-requested text output files.

All filenames are single path components inside the project's ``outputs/``
directory.  Files are written to a private temporary file and published
atomically so an interrupted write cannot masquerade as a successful one.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from .utils import (
    OutputExistsError,
    ValidationError,
    ensure_outputs_dir,
    fsync_directory,
    safe_remove_path,
    strip_surrounding_quotes,
)

MAX_OUTPUT_FILENAME_LENGTH = 150
DEFAULT_TEXT_EXTENSION = ".txt"
WRITE_TEMP_PREFIX = ".cipherstrike-write-"


def validate_output_filename(
    raw: str, *, extension: str = DEFAULT_TEXT_EXTENSION
) -> str:
    """Validate one output filename and append the default extension if absent."""
    if not isinstance(raw, str):
        raise ValidationError("Output file name must be text.")
    name = strip_surrounding_quotes(raw.strip())
    if not name:
        raise ValidationError("Output file name cannot be empty.")
    if name in {".", ".."}:
        raise ValidationError("Output file name is reserved.")
    if "\x00" in name or "/" in name or "\\" in name:
        raise ValidationError(
            "Output file name must not contain path separators or NUL bytes."
        )
    if any(ord(char) < 32 or ord(char) == 127 for char in name):
        raise ValidationError("Output file name contains control characters.")
    try:
        name.encode("utf-8", "strict")
    except UnicodeEncodeError as exc:
        raise ValidationError("Output file name is not valid UTF-8.") from exc
    if not Path(name).suffix:
        name += extension
    if len(name) > MAX_OUTPUT_FILENAME_LENGTH:
        raise ValidationError(
            f"Output file name is too long (maximum {MAX_OUTPUT_FILENAME_LENGTH} characters)."
        )
    return name


def prepare_output_path(
    output_dir: Path, raw_filename: str, *, extension: str = DEFAULT_TEXT_EXTENSION
) -> Path:
    """Return an output path under ``output_dir`` without touching the file."""
    directory = ensure_outputs_dir(output_dir)
    name = validate_output_filename(raw_filename, extension=extension)
    path = directory / name
    if path.parent != directory:
        raise ValidationError("Output file must be directly inside the outputs directory.")
    return path


def write_text_atomic(path: Path, text: str, *, overwrite: bool = False) -> None:
    """Atomically create or replace a UTF-8 text file with private permissions."""
    if not isinstance(text, str):
        raise ValidationError("Output text must be a string.")
    directory = ensure_outputs_dir(path.parent)
    if path.exists() or path.is_symlink():
        if not overwrite:
            raise OutputExistsError(f"Refusing to overwrite existing output: {path}")

    temporary_path: Path | None = None
    fd = -1
    try:
        fd, temporary_name = tempfile.mkstemp(
            prefix=WRITE_TEMP_PREFIX, suffix=".tmp", dir=str(directory)
        )
        temporary_path = Path(temporary_name)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            fd = -1
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.chmod(temporary_path, 0o600)
        except OSError:
            pass

        if overwrite:
            os.replace(temporary_path, path)
        else:
            if path.exists() or path.is_symlink():
                raise OutputExistsError(f"Refusing to overwrite existing output: {path}")
            try:
                os.link(temporary_path, path)
            except FileExistsError as exc:
                raise OutputExistsError(
                    f"Refusing to overwrite existing output: {path}"
                ) from exc
            except OSError:
                # Filesystems without hard-link support: re-check immediately
                # before the rename, then publish atomically.
                if path.exists() or path.is_symlink():
                    raise OutputExistsError(
                        f"Refusing to overwrite existing output: {path}"
                    )
                os.replace(temporary_path, path)
            else:
                try:
                    temporary_path.unlink()
                except OSError:
                    # The final output is already safely linked into place;
                    # a leftover staging link is not a failed publication.
                    pass
        fsync_directory(directory)
    except OSError as exc:
        if isinstance(exc, (OutputExistsError, ValidationError)):
            raise
        raise ValidationError(
            f"Could not write output file: {path} ({exc.strerror or exc})"
        ) from exc
    finally:
        if fd != -1:
            try:
                os.close(fd)
            except OSError:
                pass
        if temporary_path is not None:
            try:
                safe_remove_path(temporary_path)
            except Exception:
                pass


def verify_text_file(path: Path, *, expected_text: str | None = None) -> str:
    """Read a UTF-8 text file back and optionally compare its contents."""
    try:
        with path.open("r", encoding="utf-8", newline="") as handle:
            text = handle.read()
    except (OSError, UnicodeDecodeError) as exc:
        raise ValidationError(f"Could not verify output file: {path}") from exc
    if expected_text is not None and text != expected_text:
        raise ValidationError(f"Output file verification failed: {path}")
    return text
