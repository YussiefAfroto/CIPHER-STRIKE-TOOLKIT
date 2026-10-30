"""File and folder decryption and safe restoration.

Decryption always happens into a private staging directory.  Nothing is
published to ``outputs/`` until the whole authenticated stream has been read,
the final manifest has been verified, and (for folders) the archive has been
extracted with explicit path and object-type validation.  Encrypted containers
are never deleted by these workflows.
"""

from __future__ import annotations

import math
import os
import stat
import tarfile
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .crypto import (
    ContainerInfo,
    DecryptionResult,
    PayloadManifest,
    RecoveryKey,
    apply_file_metadata,
    decrypt_container_file,
    read_container_hint,
    safe_mode,
)
from .utils import (
    CipherStrikeError,
    OperationCancelled,
    OutputExistsError,
    SafeArchiveError,
    ValidationError,
    ensure_outputs_dir,
    fsync_directory,
    make_private_staging_dir,
    safe_remove_path,
    sanitize_output_name,
    validate_encrypted_container,
)

OverwriteConfirmation = Callable[[Path], bool]
EXTRACT_BUFFER_SIZE = 1_048_576
MAX_TAR_NAME_BYTES = 4_096


@dataclass
class DecryptionArtifacts:
    """Result of a successful, published decryption."""

    container: Path
    output: Path
    kind: str
    info: ContainerInfo
    manifest: PayloadManifest
    method: str
    warnings: tuple[str, ...] = ()


def _same_path(first: Path, second: Path) -> bool:
    try:
        if first.exists() and second.exists() and os.path.samefile(first, second):
            return True
    except OSError:
        pass
    try:
        return first.resolve(strict=False) == second.resolve(strict=False)
    except OSError:
        return os.path.abspath(first) == os.path.abspath(second)


def _choose_destination(
    *,
    output_dir: Path,
    container: Path,
    original_name: str,
    kind: str,
    confirm_overwrite: OverwriteConfirmation | None,
) -> tuple[Path, bool]:
    fallback = f"restored-{kind}-{uuid.uuid4().hex[:8]}"
    name = sanitize_output_name(original_name, fallback=fallback)
    destination = output_dir / name
    if _same_path(destination, container):
        destination = output_dir / f"restored-{name}"
    if destination.parent != output_dir:
        raise ValidationError("Restored output path escaped the outputs directory.")
    exists = destination.exists() or destination.is_symlink()
    overwrite = False
    if exists:
        if confirm_overwrite is None:
            raise OutputExistsError(
                f"An output already exists and overwrite was not confirmed: {destination}"
            )
        if not confirm_overwrite(destination):
            raise OperationCancelled(
                f"Existing output preserved; decryption was not published: {destination}"
            )
        overwrite = True
    return destination, overwrite


def _publish_file(
    staged: Path, destination: Path, *, overwrite: bool
) -> None:
    if destination.is_dir() and not destination.is_symlink():
        raise OutputExistsError(
            f"Refusing to replace an existing directory with a decrypted file: {destination}"
        )
    if overwrite:
        try:
            os.replace(staged, destination)
            return
        except OSError as exc:
            raise CipherStrikeError(
                f"Could not publish decrypted file: {destination} ({exc.strerror or exc})"
            ) from exc
    if destination.exists() or destination.is_symlink():
        raise OutputExistsError(f"Refusing to overwrite existing output: {destination}")
    try:
        os.link(staged, destination)
    except FileExistsError as exc:
        raise OutputExistsError(f"Refusing to overwrite existing output: {destination}") from exc
    except OSError:
        if destination.exists() or destination.is_symlink():
            raise OutputExistsError(f"Refusing to overwrite existing output: {destination}")
        try:
            os.replace(staged, destination)
        except OSError as exc:
            raise CipherStrikeError(
                f"Could not publish decrypted file: {destination} ({exc.strerror or exc})"
            ) from exc
        return
    try:
        staged.unlink()
    except OSError as exc:
        raise CipherStrikeError(
            f"Published output but could not remove its staging link: {staged}"
        ) from exc


def _publish_directory(
    staged: Path, destination: Path, *, overwrite: bool
) -> str | None:
    """Publish a directory, preserving the old tree until the swap succeeds."""
    backup: Path | None = None
    existed = destination.exists() or destination.is_symlink()
    if existed and not overwrite:
        raise OutputExistsError(f"Refusing to overwrite existing output: {destination}")
    if existed:
        backup = destination.parent / f".cipherstrike-backup-{uuid.uuid4().hex}"
        try:
            os.replace(destination, backup)
        except OSError as exc:
            raise CipherStrikeError(
                f"Could not move existing output aside: {destination} "
                f"({exc.strerror or exc})"
            ) from exc
    try:
        if destination.exists() or destination.is_symlink():
            raise CipherStrikeError(
                f"An output appeared while publishing; refusing to overwrite: {destination}"
            )
        os.replace(staged, destination)
    except Exception:
        if backup is not None and not (
            destination.exists() or destination.is_symlink()
        ):
            try:
                os.replace(backup, destination)
            except OSError:
                pass
        raise
    warning: str | None = None
    if backup is not None:
        try:
            safe_remove_path(backup)
        except CipherStrikeError as exc:
            warning = (
                "The previous output was moved aside but could not be removed: "
                f"{backup} ({exc})"
            )
    return warning


def _validate_member_name(name: str) -> str:
    if not isinstance(name, str) or not name:
        raise SafeArchiveError("Archive contains an empty member name.")
    if "\x00" in name or "\\" in name:
        raise SafeArchiveError("Archive contains a forbidden member name.")
    try:
        if len(name.encode("utf-8", "strict")) > MAX_TAR_NAME_BYTES:
            raise SafeArchiveError("Archive contains an excessively long member name.")
    except UnicodeEncodeError as exc:
        raise SafeArchiveError("Archive contains a non-UTF-8 member name.") from exc
    if name.startswith("/"):
        raise SafeArchiveError("Archive contains an absolute path.")
    trimmed = name.rstrip("/")
    if not trimmed:
        raise SafeArchiveError("Archive contains an invalid member path.")
    parts = trimmed.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise SafeArchiveError("Archive contains a path traversal sequence.")
    return "/".join(parts)


def _validate_member(member: tarfile.TarInfo) -> str:
    normalized = _validate_member_name(member.name)
    if not (member.isreg() or member.isdir()):
        raise SafeArchiveError(
            f"Archive contains an unsupported object type for: {normalized}"
        )
    if member.isreg() and member.size < 0:
        raise SafeArchiveError("Archive contains a file with an invalid size.")
    try:
        valid_time = math.isfinite(float(member.mtime))
    except (TypeError, ValueError, OverflowError):
        valid_time = False
    if not valid_time:
        raise SafeArchiveError("Archive contains an invalid timestamp.")
    return normalized


def _ensure_directory(path: Path, root: Path) -> None:
    try:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    except OSError as exc:
        raise SafeArchiveError(
            f"Could not create restored directory: {path} ({exc.strerror or exc})"
        ) from exc
    try:
        st = path.lstat()
    except OSError as exc:
        raise SafeArchiveError(f"Could not inspect restored directory: {path}") from exc
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise SafeArchiveError(f"Unsafe directory encountered during extraction: {path}")
    try:
        path.resolve(strict=True).relative_to(root.resolve(strict=True))
    except (OSError, ValueError) as exc:
        raise SafeArchiveError("Restored path escaped the extraction root.") from exc


def _apply_timestamp(path: Path, mtime: float) -> None:
    if not math.isfinite(float(mtime)):
        return
    try:
        ns = int(float(mtime) * 1_000_000_000)
        try:
            os.utime(path, ns=(ns, ns), follow_symlinks=False)
        except NotImplementedError:
            # Some platforms do not support follow_symlinks for utime.  The
            # extraction root contains only real files and directories.
            os.utime(path, ns=(ns, ns))
    except (OSError, OverflowError, ValueError, NotImplementedError):
        pass


def safe_extract_tar(
    archive_path: Path,
    destination_root: Path,
    *,
    root_mode: int = 0o700,
    root_mtime_ns: int | None = None,
) -> None:
    """Extract a TAR into a new directory with strict path/type validation.

    Only regular files and directories are accepted.  Absolute paths, empty or
    dot components, ``..`` traversal, backslashes, NUL bytes, duplicate paths,
    symlinks, hard links, devices, and FIFOs are rejected.  Setuid/setgid/sticky
    bits are stripped.  Ownership is not restored.
    """
    if destination_root.exists() or destination_root.is_symlink():
        raise SafeArchiveError(
            f"Extraction destination must not already exist: {destination_root}"
        )
    try:
        destination_root.mkdir(mode=0o700, parents=True)
    except OSError as exc:
        raise SafeArchiveError(
            f"Could not create extraction directory: {destination_root}"
        ) from exc
    root_resolved = destination_root.resolve(strict=True)
    seen: set[str] = set()
    directory_metadata: dict[Path, tuple[int, float]] = {}

    try:
        with tarfile.open(archive_path, "r:", encoding="utf-8", errorlevel=2) as archive:
            for member in archive:
                normalized = _validate_member(member)
                if normalized in seen:
                    raise SafeArchiveError(
                        f"Archive contains a duplicate path: {normalized}"
                    )
                seen.add(normalized)
                target = destination_root.joinpath(*normalized.split("/"))
                try:
                    target.resolve(strict=False).relative_to(root_resolved)
                except (OSError, ValueError) as exc:
                    raise SafeArchiveError("Archive path escapes the extraction root.") from exc
                parent = target.parent
                _ensure_directory(parent, destination_root)
                if member.isdir():
                    _ensure_directory(target, destination_root)
                    directory_metadata[target] = (
                        safe_mode(member.mode),
                        float(member.mtime),
                    )
                    continue
                if target.exists() or target.is_symlink():
                    raise SafeArchiveError(
                        f"Archive member conflicts with an existing path: {normalized}"
                    )
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                try:
                    fd = os.open(target, flags, 0o600)
                except OSError as exc:
                    raise SafeArchiveError(
                        f"Could not create restored file: {target} ({exc.strerror or exc})"
                    ) from exc
                written = 0
                try:
                    source = archive.extractfile(member)
                    if source is None:
                        raise SafeArchiveError(
                            f"Could not read archive member: {normalized}"
                        )
                    with os.fdopen(fd, "wb", closefd=True) as output, source:
                        fd = -1
                        while True:
                            chunk = source.read(EXTRACT_BUFFER_SIZE)
                            if not chunk:
                                break
                            output.write(chunk)
                            written += len(chunk)
                        output.flush()
                        os.fsync(output.fileno())
                except OSError as exc:
                    raise SafeArchiveError(
                        f"Failed while extracting archive member: {normalized}"
                    ) from exc
                finally:
                    if fd != -1:
                        try:
                            os.close(fd)
                        except OSError:
                            pass
                if written != member.size:
                    raise SafeArchiveError(
                        f"Archive member size mismatch for: {normalized}"
                    )
                try:
                    os.chmod(target, safe_mode(member.mode))
                except OSError:
                    pass
                _apply_timestamp(target, member.mtime)
    except tarfile.TarError as exc:
        raise SafeArchiveError(f"Invalid or corrupted folder archive: {exc}") from exc
    except OSError as exc:
        raise SafeArchiveError(
            f"Failed while extracting folder archive: {exc.strerror or exc}"
        ) from exc

    # Directory modes are applied last so read-only directories do not block
    # creation of children.  Deepest paths first, then the restored root.
    for path in sorted(directory_metadata, key=lambda item: len(item.parts), reverse=True):
        mode, mtime = directory_metadata[path]
        try:
            os.chmod(path, mode)
        except OSError:
            pass
        _apply_timestamp(path, mtime)
    try:
        os.chmod(destination_root, safe_mode(root_mode))
    except OSError:
        pass
    if root_mtime_ns is not None:
        try:
            try:
                os.utime(
                    destination_root,
                    ns=(root_mtime_ns, root_mtime_ns),
                    follow_symlinks=False,
                )
            except NotImplementedError:
                os.utime(destination_root, ns=(root_mtime_ns, root_mtime_ns))
        except OSError:
            pass


def _decrypt_to_file(
    container: Path, destination: Path, *, password: str | None, recovery_key: RecoveryKey | None
) -> DecryptionResult:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(destination, flags, 0o600)
    except OSError as exc:
        raise CipherStrikeError(
            f"Cannot create temporary plaintext file: {exc.strerror or exc}"
        ) from exc
    try:
        with os.fdopen(fd, "w+b", closefd=True) as handle:
            result = decrypt_container_file(
                container,
                handle,
                password=password,
                recovery_key=recovery_key,
                expected_kind="file",
            )
            handle.flush()
            os.fsync(handle.fileno())
        return result
    except OSError as exc:
        raise CipherStrikeError(
            f"Failed while writing temporary plaintext: {exc.strerror or exc}"
        ) from exc


def _decrypt_to_archive(
    container: Path, destination: Path, *, password: str | None, recovery_key: RecoveryKey | None
) -> DecryptionResult:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(destination, flags, 0o600)
    except OSError as exc:
        raise CipherStrikeError(
            f"Cannot create temporary archive file: {exc.strerror or exc}"
        ) from exc
    try:
        with os.fdopen(fd, "w+b", closefd=True) as handle:
            result = decrypt_container_file(
                container,
                handle,
                password=password,
                recovery_key=recovery_key,
                expected_kind="folder",
            )
            handle.flush()
            os.fsync(handle.fileno())
        return result
    except OSError as exc:
        raise CipherStrikeError(
            f"Failed while writing temporary folder archive: {exc.strerror or exc}"
        ) from exc


def decrypt_file_container(
    container: Path,
    output_dir: Path,
    *,
    password: str | None = None,
    recovery_key: RecoveryKey | None = None,
    confirm_overwrite: OverwriteConfirmation | None = None,
) -> DecryptionArtifacts:
    """Decrypt a file container and publish one plaintext file."""
    if (password is None) == (recovery_key is None):
        raise ValidationError("Select exactly one recovery method.")
    container = validate_encrypted_container(str(container))
    output_dir = ensure_outputs_dir(output_dir)
    staging = make_private_staging_dir(output_dir)
    staged_plaintext = staging / "plaintext.part"
    try:
        result = _decrypt_to_file(
            container,
            staged_plaintext,
            password=password,
            recovery_key=recovery_key,
        )
        if result.info.kind != "file":
            raise CipherStrikeError("The selected container is not a file container.")
        apply_file_metadata(staged_plaintext, result.info)
        destination, overwrite = _choose_destination(
            output_dir=output_dir,
            container=container,
            original_name=result.info.original_name,
            kind="file",
            confirm_overwrite=confirm_overwrite,
        )
        _publish_file(staged_plaintext, destination, overwrite=overwrite)
        fsync_directory(output_dir)
        return DecryptionArtifacts(
            container=container,
            output=destination,
            kind="file",
            info=result.info,
            manifest=result.manifest,
            method="password" if password is not None else "recovery-key",
        )
    finally:
        try:
            safe_remove_path(staging)
        except CipherStrikeError:
            pass


def decrypt_folder_container(
    container: Path,
    output_dir: Path,
    *,
    password: str | None = None,
    recovery_key: RecoveryKey | None = None,
    confirm_overwrite: OverwriteConfirmation | None = None,
) -> DecryptionArtifacts:
    """Decrypt a folder container and restore its complete directory tree."""
    if (password is None) == (recovery_key is None):
        raise ValidationError("Select exactly one recovery method.")
    container = validate_encrypted_container(str(container))
    output_dir = ensure_outputs_dir(output_dir)
    staging = make_private_staging_dir(output_dir)
    staged_archive = staging / "archive.part"
    extracted = staging / "restored"
    warnings: list[str] = []
    try:
        result = _decrypt_to_archive(
            container,
            staged_archive,
            password=password,
            recovery_key=recovery_key,
        )
        if result.info.kind != "folder":
            raise CipherStrikeError("The selected container is not a folder container.")
        destination, overwrite = _choose_destination(
            output_dir=output_dir,
            container=container,
            original_name=result.info.original_name,
            kind="folder",
            confirm_overwrite=confirm_overwrite,
        )
        safe_extract_tar(
            staged_archive,
            extracted,
            root_mode=result.info.source_mode,
            root_mtime_ns=result.info.source_mtime_ns,
        )
        warning = _publish_directory(extracted, destination, overwrite=overwrite)
        if warning:
            warnings.append(warning)
        fsync_directory(output_dir)
        return DecryptionArtifacts(
            container=container,
            output=destination,
            kind="folder",
            info=result.info,
            manifest=result.manifest,
            method="password" if password is not None else "recovery-key",
            warnings=tuple(warnings),
        )
    finally:
        try:
            safe_remove_path(staging)
        except CipherStrikeError:
            pass


def container_kind_hint(container: Path) -> str:
    """Return an unauthenticated kind for UI validation only.

    The result is never trusted for output naming or publication.
    """
    return read_container_hint(container).kind
