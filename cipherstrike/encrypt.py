"""File and folder encryption workflows.

The workflows never delete their source.  Deletion is a separate, explicit
operation performed by the CLI only after successful verification and user
confirmation.  All artifacts are built in a private staging directory, fully
verified through both recovery methods, and only then published to
``outputs/`` without overwriting existing files.
"""

from __future__ import annotations

import os
import stat
import tarfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from .crypto import (
    DEFAULT_CHUNK_SIZE,
    ContainerInfo,
    ContainerWriter,
    KdfParams,
    RecoveryKey,
    generate_credentials,
    safe_mode,
    verify_both_recovery_methods,
)
from .utils import (
    CipherStrikeError,
    FileIdentity,
    SourceChangedError,
    TreeSnapshot,
    ValidationError,
    allocate_artifact_paths,
    delete_source_checked,
    ensure_outputs_dir,
    fsync_directory,
    fsync_file,
    make_private_staging_dir,
    readable_list,
    safe_remove_path,
    sanitize_output_name,
    validate_source_directory,
    validate_source_file,
    write_private_text,
)

PAYLOAD_SUFFIX = ".part"
RECOVERY_STAGE_NAME = "recovery.part"
PASSWORD_STAGE_NAME = "password.part"
COPY_BUFFER_SIZE = 1_048_576
MAX_UNSUPPORTED_REPORTED = 5


@dataclass(frozen=True)
class FolderEntry:
    """A validated regular file or directory below a source root."""

    path: Path
    arcname: str
    kind: str
    identity: FileIdentity
    mtime: float


@dataclass
class EncryptionArtifacts:
    """Paths and recovery information for one completed encryption."""

    source: Path
    source_snapshot: FileIdentity | TreeSnapshot
    container: Path
    recovery_file: Path
    password_file: Path
    password: str = field(repr=False)
    recovery_key: RecoveryKey = field(repr=False)
    info: ContainerInfo

    @property
    def kind(self) -> str:
        return "folder" if isinstance(self.source_snapshot, TreeSnapshot) else "file"


def _open_source_file(path: Path, expected: FileIdentity, *, label: str = "source file") -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ValidationError(
            f"Cannot open {label}: {path} ({exc.strerror or exc})"
        ) from exc
    try:
        current = FileIdentity.from_stat(os.fstat(fd), "file")
    except OSError:
        os.close(fd)
        raise
    if current != expected:
        os.close(fd)
        raise SourceChangedError(f"{label.capitalize()} changed before it could be read: {path}")
    return fd


def _entry_name_is_supported(name: str) -> bool:
    if not name or name in {".", ".."}:
        return False
    if "\x00" in name or "/" in name or "\\" in name:
        return False
    if any(ord(char) < 32 or ord(char) == 127 for char in name):
        return False
    try:
        name.encode("utf-8", "strict")
    except UnicodeEncodeError:
        return False
    return True


def scan_folder(root: Path) -> tuple[FileIdentity, dict[str, FolderEntry]]:
    """Recursively inspect a source folder without following any symbolic link.

    Symlinks, sockets, devices, FIFOs, and names that cannot be represented
    safely are rejected rather than skipped silently.
    """
    root_st = root.lstat()
    if stat.S_ISLNK(root_st.st_mode) or not stat.S_ISDIR(root_st.st_mode):
        raise ValidationError(f"Source is not a real directory: {root}")
    root_identity = FileIdentity.from_stat(root_st, "dir")
    entries: dict[str, FolderEntry] = {}
    unsupported: list[str] = []
    stack: list[tuple[Path, str]] = [(root, "")]
    while stack:
        current, prefix = stack.pop()
        try:
            children = sorted(os.scandir(current), key=lambda item: item.name)
        except PermissionError as exc:
            raise ValidationError(f"Permission denied while reading folder: {current}") from exc
        except OSError as exc:
            raise ValidationError(
                f"Cannot read folder: {current} ({exc.strerror or exc})"
            ) from exc
        for child in children:
            name = child.name
            relative = f"{prefix}/{name}" if prefix else name
            if not _entry_name_is_supported(name) or not all(
                _entry_name_is_supported(part) for part in relative.split("/")
            ):
                unsupported.append(str(child.path))
                if child.is_dir(follow_symlinks=False):
                    pass
                continue
            try:
                # os.stat on the path (rather than DirEntry.stat) populates
                # device/inode fields reliably on Windows as well as Linux.
                st = os.stat(child.path, follow_symlinks=False)
            except OSError as exc:
                raise ValidationError(
                    f"Cannot inspect folder entry: {child.path} ({exc.strerror or exc})"
                ) from exc
            if stat.S_ISLNK(st.st_mode):
                unsupported.append(str(child.path))
                continue
            if stat.S_ISDIR(st.st_mode):
                entry = FolderEntry(
                    path=Path(child.path),
                    arcname=relative,
                    kind="dir",
                    identity=FileIdentity.from_stat(st, "dir"),
                    mtime=st.st_mtime,
                )
                entries[relative] = entry
                stack.append((Path(child.path), relative))
            elif stat.S_ISREG(st.st_mode):
                entries[relative] = FolderEntry(
                    path=Path(child.path),
                    arcname=relative,
                    kind="file",
                    identity=FileIdentity.from_stat(st, "file"),
                    mtime=st.st_mtime,
                )
            else:
                unsupported.append(str(child.path))
    if unsupported:
        raise ValidationError(
            "The folder contains symbolic links, special files, or names that cannot "
            "be represented safely. Encryption was stopped; no entries were skipped: "
            + readable_list(unsupported, MAX_UNSUPPORTED_REPORTED)
        )
    return root_identity, entries


def _snapshot_from_scan(
    root_identity: FileIdentity, entries: dict[str, FolderEntry]
) -> TreeSnapshot:
    return TreeSnapshot(
        root=root_identity,
        entries={name: entry.identity for name, entry in entries.items()},
    )


def _read_password_file(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise CipherStrikeError(f"Cannot read generated password file: {path}") from exc


def build_password_file_text(
    *, password: str, container_name: str, info: ContainerInfo
) -> str:
    """Render the private password text file (the Recovery Key is separate)."""
    return (
        "CIPHER STRIKE - GENERATED PASSWORD\n"
        "==================================\n"
        f"Encrypted artifact: {container_name}\n"
        f"Created (UTC): {info.created_utc}\n"
        f"Container type: {info.kind}\n"
        "\n"
        f"Generated Password: {password}\n"
        "\n"
        "WARNING:\n"
        "- This file and the password are highly sensitive.\n"
        "- Store the password and Recovery Key separately from this machine when possible.\n"
        "- Anyone with this password can decrypt the associated container.\n"
        "- If both this password and the Recovery Key are lost, recovery is impossible.\n"
    )


def _stream_file_to_writer(source: Path, identity: FileIdentity, writer: ContainerWriter) -> None:
    fd = _open_source_file(source, identity)
    try:
        with os.fdopen(fd, "rb", closefd=True) as handle:
            while True:
                chunk = handle.read(COPY_BUFFER_SIZE)
                if not chunk:
                    break
                writer.write(chunk)
            try:
                after = FileIdentity.from_stat(os.fstat(handle.fileno()), "file")
            except OSError as exc:
                raise CipherStrikeError(f"Cannot re-inspect source file: {source}") from exc
            if after != identity:
                raise SourceChangedError(
                    f"Source file changed while it was being encrypted: {source}"
                )
    except OSError as exc:
        raise CipherStrikeError(
            f"Failed while reading source file: {source} ({exc.strerror or exc})"
        ) from exc


def _publish_file_no_overwrite(staged: Path, destination: Path) -> None:
    """Publish a completed file without ever replacing an existing path."""
    if destination.exists() or destination.is_symlink():
        raise CipherStrikeError(
            f"Refusing to overwrite an existing output that appeared during the operation: "
            f"{destination}"
        )
    try:
        os.link(staged, destination)
    except FileExistsError as exc:
        raise CipherStrikeError(
            f"Refusing to overwrite an existing output: {destination}"
        ) from exc
    except OSError:
        # Some filesystems do not support hard links.  Re-check immediately
        # before renaming; the outputs directory is private to the user.
        if destination.exists() or destination.is_symlink():
            raise CipherStrikeError(
                f"Refusing to overwrite an existing output: {destination}"
            )
        try:
            os.replace(staged, destination)
        except OSError as exc:
            raise CipherStrikeError(
                f"Could not publish output file: {destination} ({exc.strerror or exc})"
            ) from exc
        return
    try:
        staged.unlink()
    except OSError as exc:
        raise CipherStrikeError(
            f"Published output but could not remove staging link: {staged}"
        ) from exc


def _publish_artifacts(
    *,
    staged_container: Path,
    staged_recovery: Path,
    staged_password: Path,
    container: Path,
    recovery_file: Path,
    password_file: Path,
    output_dir: Path,
) -> None:
    """Publish all three artifacts or roll back anything already published."""
    published: list[Path] = []
    try:
        _publish_file_no_overwrite(staged_container, container)
        published.append(container)
        _publish_file_no_overwrite(staged_recovery, recovery_file)
        published.append(recovery_file)
        _publish_file_no_overwrite(staged_password, password_file)
        published.append(password_file)
        fsync_directory(output_dir)
    except Exception:
        for path in reversed(published):
            try:
                safe_remove_path(path)
            except CipherStrikeError:
                pass
        raise


def _verify_staged(
    *,
    container: Path,
    password: str,
    recovery_key: RecoveryKey,
    kind: str,
    expected_sha256: str,
    expected_size: int,
) -> None:
    with_password, with_recovery = verify_both_recovery_methods(
        container,
        password=password,
        recovery_key=recovery_key,
        expected_kind=kind,
    )
    for result in (with_password, with_recovery):
        if result.info.kind != kind:
            raise CipherStrikeError("Verification returned an unexpected container type.")
        if result.computed_sha256 != expected_sha256:
            raise CipherStrikeError("Verification failed: payload digest mismatch.")
        if result.computed_size != expected_size:
            raise CipherStrikeError("Verification failed: payload size mismatch.")


def _stage_recovery_and_password(
    *,
    staging: Path,
    recovery_key: RecoveryKey,
    password: str,
    container_name: str,
    info: ContainerInfo,
) -> tuple[Path, Path]:
    recovery_path = staging / RECOVERY_STAGE_NAME
    password_path = staging / PASSWORD_STAGE_NAME
    write_private_text(recovery_path, recovery_key.to_text(container_name))
    write_private_text(
        password_path,
        build_password_file_text(
            password=password,
            container_name=container_name,
            info=info,
        ),
    )
    try:
        recovered = RecoveryKey.load(recovery_path)
    except CipherStrikeError as exc:
        raise CipherStrikeError("Generated Recovery Key file failed verification.") from exc
    if recovered.recovery_id != recovery_key.recovery_id or recovered.secret != recovery_key.secret:
        raise CipherStrikeError("Generated Recovery Key file failed verification.")
    if password not in _read_password_file(password_path):
        raise CipherStrikeError("Generated password file failed verification.")
    return recovery_path, password_path


def _finish_encryption(
    *,
    source: Path,
    snapshot: FileIdentity | TreeSnapshot,
    staging: Path,
    staged_container: Path,
    container: Path,
    recovery_file: Path,
    password_file: Path,
    password: str,
    recovery_key: RecoveryKey,
    info: ContainerInfo,
    payload_sha256: str,
    payload_size: int,
    output_dir: Path,
) -> EncryptionArtifacts:
    try:
        _verify_staged(
            container=staged_container,
            password=password,
            recovery_key=recovery_key,
            kind=info.kind,
            expected_sha256=payload_sha256,
            expected_size=payload_size,
        )
        staged_recovery, staged_password = _stage_recovery_and_password(
            staging=staging,
            recovery_key=recovery_key,
            password=password,
            container_name=container.name,
            info=info,
        )
        _publish_artifacts(
            staged_container=staged_container,
            staged_recovery=staged_recovery,
            staged_password=staged_password,
            container=container,
            recovery_file=recovery_file,
            password_file=password_file,
            output_dir=output_dir,
        )
    finally:
        try:
            safe_remove_path(staging)
        except CipherStrikeError:
            pass
    return EncryptionArtifacts(
        source=source,
        source_snapshot=snapshot,
        container=container,
        recovery_file=recovery_file,
        password_file=password_file,
        password=password,
        recovery_key=recovery_key,
        info=info,
    )


def encrypt_file(
    source: Path,
    output_dir: Path,
    *,
    params: KdfParams | None = None,
    chunk_size: int | None = None,
) -> EncryptionArtifacts:
    """Encrypt one regular file into a verified authenticated container."""
    source = validate_source_file(str(source))
    output_dir = ensure_outputs_dir(output_dir)
    source_st = source.lstat()
    if stat.S_ISLNK(source_st.st_mode) or not stat.S_ISREG(source_st.st_mode):
        raise ValidationError("Source must remain a regular file before encryption.")
    identity = FileIdentity.from_stat(source_st, "file")
    container, recovery_file, password_file = allocate_artifact_paths(
        output_dir, source.name
    )
    credentials = generate_credentials()
    staging = make_private_staging_dir(output_dir)
    staged_container = staging / f"container{PAYLOAD_SUFFIX}"
    fd = -1
    writer: ContainerWriter | None = None
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(staged_container, flags, 0o600)
        handle = os.fdopen(fd, "w+b", closefd=True)
        fd = -1
        with handle:
            writer = ContainerWriter(
                handle,
                kind="file",
                original_name=source.name,
                password=credentials.password,
                recovery_key=credentials.recovery_key,
                source_mode=safe_mode(source_st.st_mode),
                source_mtime_ns=source_st.st_mtime_ns,
                params=params,
                chunk_size=chunk_size or DEFAULT_CHUNK_SIZE,
            )
            _stream_file_to_writer(source, identity, writer)
            writer.close()
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.chmod(staged_container, 0o600)
        except OSError:
            pass
        fsync_file(staged_container)
        current = FileIdentity.from_stat(source.lstat(), "file")
        if current != identity:
            raise SourceChangedError(
                f"Source file changed during encryption; original preserved: {source}"
            )
        if writer.payload_size != source_st.st_size:
            raise SourceChangedError(
                f"Source file size changed during encryption; original preserved: {source}"
            )
        return _finish_encryption(
            source=source,
            snapshot=identity,
            staging=staging,
            staged_container=staged_container,
            container=container,
            recovery_file=recovery_file,
            password_file=password_file,
            password=credentials.password,
            recovery_key=credentials.recovery_key,
            info=writer.info,
            payload_sha256=writer.payload_sha256,
            payload_size=writer.payload_size,
            output_dir=output_dir,
        )
    except FileExistsError as exc:
        raise CipherStrikeError("A staging file unexpectedly already exists.") from exc
    except OSError as exc:
        raise CipherStrikeError(
            f"Encryption failed while accessing the filesystem: {exc.strerror or exc}"
        ) from exc
    except Exception:
        if fd != -1:
            try:
                os.close(fd)
            except OSError:
                pass
        raise
    finally:
        # If _finish_encryption was reached it already cleaned staging.
        try:
            if staging.exists():
                safe_remove_path(staging)
        except CipherStrikeError:
            pass


def _tar_info_for_entry(entry: FolderEntry) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name=entry.arcname)
    info.mode = safe_mode(entry.identity.mode)
    info.mtime = entry.mtime
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    if entry.kind == "dir":
        info.type = tarfile.DIRTYPE
        info.size = 0
    else:
        info.type = tarfile.REGTYPE
        info.size = entry.identity.size
    return info


def _add_folder_entries_to_tar(
    entries: Iterable[FolderEntry], tar: tarfile.TarFile
) -> None:
    for entry in entries:
        tar_info = _tar_info_for_entry(entry)
        if entry.kind == "dir":
            tar.addfile(tar_info)
            continue
        fd = _open_source_file(entry.path, entry.identity, label="folder file")
        try:
            with os.fdopen(fd, "rb", closefd=True) as handle:
                after = FileIdentity.from_stat(os.fstat(handle.fileno()), "file")
                if after != entry.identity:
                    raise SourceChangedError(
                        f"File changed while the folder was being encrypted: {entry.path}"
                    )
                tar.addfile(tar_info, handle)
                final = FileIdentity.from_stat(os.fstat(handle.fileno()), "file")
                if final != entry.identity:
                    raise SourceChangedError(
                        f"File changed while the folder was being encrypted: {entry.path}"
                    )
        except OSError as exc:
            raise CipherStrikeError(
                f"Failed while reading folder file: {entry.path} "
                f"({exc.strerror or exc})"
            ) from exc


def encrypt_folder(
    source: Path,
    output_dir: Path,
    *,
    params: KdfParams | None = None,
    chunk_size: int | None = None,
) -> EncryptionArtifacts:
    """Encrypt a complete folder into one authenticated TAR-based container."""
    source = validate_source_directory(str(source))
    output_dir = ensure_outputs_dir(output_dir)
    root_identity, entries = scan_folder(source)
    snapshot = _snapshot_from_scan(root_identity, entries)
    if not _entry_name_is_supported(source.name):
        raise ValidationError(
            "The selected folder name contains characters that cannot be stored safely."
        )
    container, recovery_file, password_file = allocate_artifact_paths(
        output_dir, source.name
    )
    credentials = generate_credentials()
    staging = make_private_staging_dir(output_dir)
    staged_container = staging / f"container{PAYLOAD_SUFFIX}"
    fd = -1
    writer: ContainerWriter | None = None
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(staged_container, flags, 0o600)
        handle = os.fdopen(fd, "w+b", closefd=True)
        fd = -1
        with handle:
            writer = ContainerWriter(
                handle,
                kind="folder",
                original_name=source.name,
                password=credentials.password,
                recovery_key=credentials.recovery_key,
                source_mode=root_identity.mode,
                source_mtime_ns=root_identity.mtime_ns,
                params=params,
                chunk_size=chunk_size or DEFAULT_CHUNK_SIZE,
            )
            ordered = sorted(entries.values(), key=lambda item: item.arcname)
            try:
                with tarfile.open(
                    fileobj=writer,
                    mode="w|",
                    format=tarfile.PAX_FORMAT,
                    encoding="utf-8",
                ) as tar:
                    _add_folder_entries_to_tar(ordered, tar)
            except tarfile.TarError as exc:
                raise CipherStrikeError(f"Failed to build folder archive: {exc}") from exc
            writer.close()
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.chmod(staged_container, 0o600)
        except OSError:
            pass
        fsync_file(staged_container)

        after_root, after_entries = scan_folder(source)
        if after_root != root_identity or {
            name: entry.identity for name, entry in after_entries.items()
        } != {name: entry.identity for name, entry in entries.items()}:
            raise SourceChangedError(
                f"Source folder changed during encryption; original preserved: {source}"
            )
        return _finish_encryption(
            source=source,
            snapshot=snapshot,
            staging=staging,
            staged_container=staged_container,
            container=container,
            recovery_file=recovery_file,
            password_file=password_file,
            password=credentials.password,
            recovery_key=credentials.recovery_key,
            info=writer.info,
            payload_sha256=writer.payload_sha256,
            payload_size=writer.payload_size,
            output_dir=output_dir,
        )
    except FileExistsError as exc:
        raise CipherStrikeError("A staging file unexpectedly already exists.") from exc
    except OSError as exc:
        raise CipherStrikeError(
            f"Folder encryption failed while accessing the filesystem: "
            f"{exc.strerror or exc}"
        ) from exc
    finally:
        if fd != -1:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            if staging.exists():
                safe_remove_path(staging)
        except CipherStrikeError:
            pass


def delete_source_after_confirmation(
    source: Path, snapshot: FileIdentity | TreeSnapshot, confirmation: str
) -> bool:
    """Delete only after the caller supplies the exact explicit confirmation.

    The function exists so the confirmation policy is testable outside the
    interactive UI.  It re-validates the source snapshot immediately before
    deletion.
    """
    if confirmation != "DELETE":
        return False
    delete_source_checked(source, snapshot)
    return True
