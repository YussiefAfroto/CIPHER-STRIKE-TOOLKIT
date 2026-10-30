"""Cryptographic format, file/folder round-trip, and failure-mode tests."""

from __future__ import annotations

import io
import json
import os
import shutil
import stat
import struct
import tarfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from cipherstrike.crypto import (
    MAGIC,
    AuthenticationError,
    CryptoError,
    InvalidContainerError,
    KdfParams,
    RecoveryKey,
    RecoveryKeyError,
    generate_password,
    read_container_hint,
    verify_both_recovery_methods,
)
from cipherstrike.decrypt import (
    decrypt_file_container,
    decrypt_folder_container,
    safe_extract_tar,
)
from cipherstrike.encrypt import (
    delete_source_after_confirmation,
    encrypt_file,
    encrypt_folder,
)
from cipherstrike.utils import (
    OutputExistsError,
    SafeArchiveError,
    SourceChangedError,
    ValidationError,
)


def _write_source(path: Path, data: bytes) -> Path:
    path.write_bytes(data)
    return path


def _header_end(data: bytes) -> int:
    assert data.startswith(MAGIC)
    header_len = struct.unpack(">I", data[len(MAGIC) + 2 : len(MAGIC) + 6])[0]
    return len(MAGIC) + 6 + header_len + 32


def _new_output(tmp_path: Path, name: str = "restored") -> Path:
    path = tmp_path / name
    path.mkdir()
    return path


def test_password_has_all_required_categories() -> None:
    for _ in range(50):
        password = generate_password()
        assert len(password) == 32
        assert any(char.isupper() for char in password)
        assert any(char.islower() for char in password)
        assert any(char.isdigit() for char in password)
        assert any(not char.isalnum() for char in password)


def test_password_file_does_not_contain_recovery_secret(
    tmp_path: Path, fast_params: KdfParams
) -> None:
    source = _write_source(tmp_path / "secret.txt", b"not really secret")
    artifacts = encrypt_file(source, tmp_path / "outputs", params=fast_params)
    password_text = artifacts.password_file.read_text(encoding="utf-8")
    assert artifacts.password in password_text
    import base64

    encoded_recovery = base64.b64encode(artifacts.recovery_key.secret).decode("ascii")
    assert encoded_recovery not in password_text


def test_file_roundtrip_with_password(tmp_path: Path, fast_params: KdfParams) -> None:
    data = (b"CIPHER STRIKE payload\n" * 4096) + os.urandom(257)
    source = _write_source(tmp_path / "document.bin", data)
    artifacts = encrypt_file(source, tmp_path / "outputs", params=fast_params)
    assert artifacts.container.exists()
    assert artifacts.recovery_file.exists()
    assert artifacts.password_file.exists()
    assert artifacts.password_file.read_text(encoding="utf-8").count(artifacts.password) == 1
    assert artifacts.password not in artifacts.recovery_file.read_text(encoding="utf-8")

    restored_dir = _new_output(tmp_path)
    result = decrypt_file_container(
        artifacts.container, restored_dir, password=artifacts.password
    )
    assert result.output.read_bytes() == data
    assert result.info.original_name == "document.bin"
    assert artifacts.container.read_bytes().find(b"CIPHER STRIKE payload") == -1


def test_file_roundtrip_with_recovery_key_file(
    tmp_path: Path, fast_params: KdfParams
) -> None:
    data = os.urandom(70_000)
    source = _write_source(tmp_path / "archive.dat", data)
    artifacts = encrypt_file(source, tmp_path / "outputs", params=fast_params)
    key = RecoveryKey.load(artifacts.recovery_file)
    restored_dir = _new_output(tmp_path)
    result = decrypt_file_container(artifacts.container, restored_dir, recovery_key=key)
    assert result.output.read_bytes() == data
    assert result.method == "recovery-key"


def test_empty_file_roundtrip(tmp_path: Path, fast_params: KdfParams) -> None:
    source = _write_source(tmp_path / "empty.bin", b"")
    artifacts = encrypt_file(source, tmp_path / "outputs", params=fast_params)
    restored_dir = _new_output(tmp_path)
    result = decrypt_file_container(
        artifacts.container, restored_dir, password=artifacts.password
    )
    assert result.output.read_bytes() == b""


def test_multi_chunk_file_roundtrip(tmp_path: Path, fast_params: KdfParams) -> None:
    data = os.urandom(360_000)
    source = _write_source(tmp_path / "large.bin", data)
    artifacts = encrypt_file(
        source, tmp_path / "outputs", params=fast_params, chunk_size=4096
    )
    restored_dir = _new_output(tmp_path)
    result = decrypt_file_container(
        artifacts.container, restored_dir, password=artifacts.password
    )
    assert result.output.read_bytes() == data
    assert result.manifest.chunks > 80


def test_same_plaintext_produces_different_containers(
    tmp_path: Path, fast_params: KdfParams
) -> None:
    source = _write_source(tmp_path / "same.bin", b"the same bytes" * 100)
    first = encrypt_file(source, tmp_path / "outputs", params=fast_params)
    second = encrypt_file(source, tmp_path / "outputs", params=fast_params)
    assert first.container != second.container
    assert first.password != second.password
    assert first.recovery_key != second.recovery_key
    assert first.container.read_bytes() != second.container.read_bytes()


def test_wrong_password_fails_and_leaves_no_plaintext(
    tmp_path: Path, fast_params: KdfParams
) -> None:
    source = _write_source(tmp_path / "guard.txt", b"authenticated only")
    artifacts = encrypt_file(source, tmp_path / "outputs", params=fast_params)
    out = _new_output(tmp_path)
    with pytest.raises(AuthenticationError):
        decrypt_file_container(artifacts.container, out, password="wrong-password")
    assert list(out.iterdir()) == []
    assert source.exists()
    assert artifacts.container.exists()


def test_wrong_recovery_key_fails(tmp_path: Path, fast_params: KdfParams) -> None:
    source = _write_source(tmp_path / "guard.txt", b"authenticated only")
    artifacts = encrypt_file(source, tmp_path / "outputs", params=fast_params)
    out = _new_output(tmp_path)
    with pytest.raises(RecoveryKeyError):
        decrypt_file_container(
            artifacts.container, out, recovery_key=RecoveryKey.generate()
        )
    assert list(out.iterdir()) == []


def test_modified_ciphertext_is_detected(tmp_path: Path, fast_params: KdfParams) -> None:
    source = _write_source(tmp_path / "tamper.txt", b"tamper evident" * 1000)
    artifacts = encrypt_file(source, tmp_path / "outputs", params=fast_params)
    data = bytearray(artifacts.container.read_bytes())
    body = _header_end(data)
    data[body + 5] ^= 0x01
    tampered = tmp_path / "tampered.csafe"
    tampered.write_bytes(data)
    out = _new_output(tmp_path)
    with pytest.raises(CryptoError):
        decrypt_file_container(tampered, out, password=artifacts.password)
    assert list(out.iterdir()) == []


def test_truncated_container_is_detected(tmp_path: Path, fast_params: KdfParams) -> None:
    source = _write_source(tmp_path / "truncate.txt", b"truncate me" * 500)
    artifacts = encrypt_file(source, tmp_path / "outputs", params=fast_params)
    data = artifacts.container.read_bytes()
    truncated = tmp_path / "truncated.csafe"
    truncated.write_bytes(data[:-17])
    out = _new_output(tmp_path)
    with pytest.raises(CryptoError):
        decrypt_file_container(truncated, out, password=artifacts.password)
    assert list(out.iterdir()) == []


def test_modified_header_is_detected(tmp_path: Path, fast_params: KdfParams) -> None:
    source = _write_source(tmp_path / "header.txt", b"header authentication")
    artifacts = encrypt_file(source, tmp_path / "outputs", params=fast_params)
    data = bytearray(artifacts.container.read_bytes())
    start = len(MAGIC) + 6
    header_len = struct.unpack(">I", data[len(MAGIC) + 2 : len(MAGIC) + 6])[0]
    header = json.loads(data[start : start + header_len].decode("utf-8"))
    original = header["original_name"]
    header["original_name"] = ("X" if original[0] != "X" else "Y") + original[1:]
    replacement = json.dumps(
        header, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    assert len(replacement) == header_len
    data[start : start + header_len] = replacement
    tampered = tmp_path / "header-tampered.csafe"
    tampered.write_bytes(data)
    out = _new_output(tmp_path)
    with pytest.raises(InvalidContainerError):
        decrypt_file_container(tampered, out, password=artifacts.password)
    assert list(out.iterdir()) == []


def test_corrupt_recovery_key_file_is_rejected(
    tmp_path: Path, fast_params: KdfParams
) -> None:
    source = _write_source(tmp_path / "recovery.txt", b"recovery")
    artifacts = encrypt_file(source, tmp_path / "outputs", params=fast_params)
    text = artifacts.recovery_file.read_text(encoding="utf-8")
    corrupt = tmp_path / "corrupt.recovery"
    corrupt.write_text(
        text.replace("RECOVERY SECRET: ", "RECOVERY SECRET: A", 1), encoding="utf-8"
    )
    with pytest.raises(RecoveryKeyError):
        RecoveryKey.load(corrupt)


def test_unrelated_recovery_key_file_is_rejected(
    tmp_path: Path, fast_params: KdfParams
) -> None:
    source = _write_source(tmp_path / "recovery.txt", b"recovery")
    artifacts = encrypt_file(source, tmp_path / "outputs", params=fast_params)
    unrelated_path = tmp_path / "unrelated.recovery"
    unrelated_path.write_text(RecoveryKey.generate().to_text(), encoding="utf-8")
    unrelated = RecoveryKey.load(unrelated_path)
    out = _new_output(tmp_path)
    with pytest.raises(RecoveryKeyError):
        decrypt_file_container(artifacts.container, out, recovery_key=unrelated)
    assert list(out.iterdir()) == []


def test_folder_nested_roundtrip_and_structure(
    tmp_path: Path, fast_params: KdfParams
) -> None:
    source = tmp_path / "Project"
    (source / "images").mkdir(parents=True)
    (source / "notes" / "nested").mkdir(parents=True)
    (source / "empty").mkdir()
    files = {
        "report.pdf": b"%PDF-1.4\n" + os.urandom(10_000),
        "images/photo.jpg": os.urandom(120_000),
        "notes/notes.txt": "ملاحظات سرية\n".encode("utf-8"),
        "notes/nested/data.bin": bytes(range(256)) * 10,
    }
    for relative, data in files.items():
        target = source / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    if os.name != "nt":
        os.chmod(source / "notes" / "notes.txt", 0o640)

    artifacts = encrypt_folder(
        source, tmp_path / "outputs", params=fast_params, chunk_size=8192
    )
    raw_container = artifacts.container.read_bytes()
    assert b"photo.jpg" not in raw_container
    assert "ملاحظات سرية".encode("utf-8") not in raw_container
    restored_dir = _new_output(tmp_path)
    result = decrypt_folder_container(
        artifacts.container,
        restored_dir,
        recovery_key=RecoveryKey.load(artifacts.recovery_file),
    )
    assert result.output.name == "Project"
    assert (result.output / "empty").is_dir()
    for relative, data in files.items():
        assert (result.output / relative).read_bytes() == data
    assert not (result.output / "notes" / "nested" / ".." / "escape").exists()
    if os.name != "nt":
        assert stat.S_IMODE((result.output / "notes" / "notes.txt").stat().st_mode) == 0o640


def test_folder_encryption_rejects_symlink(
    tmp_path: Path, fast_params: KdfParams
) -> None:
    source = tmp_path / "linked"
    source.mkdir()
    (source / "real.txt").write_text("real", encoding="utf-8")
    try:
        os.symlink(source / "real.txt", source / "link.txt")
    except (OSError, NotImplementedError):
        pytest.skip("Symbolic links are not available in this environment.")
    outputs = tmp_path / "outputs"
    with pytest.raises(ValidationError):
        encrypt_folder(source, outputs, params=fast_params)
    assert list(outputs.iterdir()) == []


def test_tar_path_traversal_is_rejected(tmp_path: Path) -> None:
    archive_path = tmp_path / "evil.tar"
    with tarfile.open(archive_path, "w") as archive:
        info = tarfile.TarInfo(name="../escaped.txt")
        info.size = 4
        archive.addfile(info, io.BytesIO(b"evil"))
    extraction = tmp_path / "extract"
    with pytest.raises(SafeArchiveError):
        safe_extract_tar(archive_path, extraction)
    assert not (tmp_path / "escaped.txt").exists()


def test_tar_symlink_member_is_rejected(tmp_path: Path) -> None:
    archive_path = tmp_path / "symlink.tar"
    with tarfile.open(archive_path, "w") as archive:
        info = tarfile.TarInfo(name="link")
        info.type = tarfile.SYMTYPE
        info.linkname = "/etc/passwd"
        archive.addfile(info)
    with pytest.raises(SafeArchiveError):
        safe_extract_tar(archive_path, tmp_path / "extract")
    assert not (tmp_path / "extract" / "link").exists()


def test_tar_absolute_path_is_rejected(tmp_path: Path) -> None:
    archive_path = tmp_path / "absolute.tar"
    with tarfile.open(archive_path, "w") as archive:
        info = tarfile.TarInfo(name="/tmp/absolute-escape")
        info.size = 1
        archive.addfile(info, io.BytesIO(b"x"))
    with pytest.raises(SafeArchiveError):
        safe_extract_tar(archive_path, tmp_path / "extract")


def test_wrong_container_kind_is_rejected(
    tmp_path: Path, fast_params: KdfParams
) -> None:
    source = tmp_path / "FolderAsFile"
    source.mkdir()
    (source / "a.txt").write_text("a", encoding="utf-8")
    artifacts = encrypt_folder(source, tmp_path / "outputs", params=fast_params)
    assert read_container_hint(artifacts.container).kind == "folder"
    out = _new_output(tmp_path)
    with pytest.raises(CryptoError):
        decrypt_file_container(artifacts.container, out, password=artifacts.password)
    assert list(out.iterdir()) == []


def test_output_names_are_unique(tmp_path: Path, fast_params: KdfParams) -> None:
    source = _write_source(tmp_path / "same.txt", b"same")
    first = encrypt_file(source, tmp_path / "outputs", params=fast_params)
    second = encrypt_file(source, tmp_path / "outputs", params=fast_params)
    assert first.container.name == "same.csafe"
    assert second.container.name == "same-1.csafe"
    assert first.container.exists() and second.container.exists()
    assert first.password_file.exists() and second.password_file.exists()


def test_decryption_does_not_overwrite_without_confirmation(
    tmp_path: Path, fast_params: KdfParams
) -> None:
    data = b"do not overwrite me"
    source = _write_source(tmp_path / "report.txt", data)
    artifacts = encrypt_file(source, tmp_path / "outputs", params=fast_params)
    out = tmp_path / "restored"
    out.mkdir()
    first = decrypt_file_container(artifacts.container, out, password=artifacts.password)
    original_bytes = first.output.read_bytes()
    with pytest.raises(OutputExistsError):
        decrypt_file_container(artifacts.container, out, password=artifacts.password)
    assert first.output.read_bytes() == original_bytes

    replaced = decrypt_file_container(
        artifacts.container,
        out,
        password=artifacts.password,
        confirm_overwrite=lambda _path: True,
    )
    assert replaced.output.read_bytes() == data
    assert artifacts.container.exists()


def test_folder_decryption_requires_overwrite_confirmation(
    tmp_path: Path, fast_params: KdfParams
) -> None:
    source = tmp_path / "RepeatFolder"
    source.mkdir()
    (source / "file.txt").write_text("folder overwrite check", encoding="utf-8")
    artifacts = encrypt_folder(source, tmp_path / "outputs", params=fast_params)
    out = tmp_path / "restored"
    out.mkdir()
    first = decrypt_folder_container(artifacts.container, out, password=artifacts.password)
    marker = first.output / "existing-marker.txt"
    marker.write_text("keep", encoding="utf-8")
    with pytest.raises(OutputExistsError):
        decrypt_folder_container(artifacts.container, out, password=artifacts.password)
    assert marker.read_text(encoding="utf-8") == "keep"

    replaced = decrypt_folder_container(
        artifacts.container,
        out,
        password=artifacts.password,
        confirm_overwrite=lambda _path: True,
    )
    assert not (replaced.output / "existing-marker.txt").exists()
    assert (replaced.output / "file.txt").read_text(encoding="utf-8") == "folder overwrite check"
    assert artifacts.container.exists()


def test_declining_deletion_preserves_source(
    tmp_path: Path, fast_params: KdfParams
) -> None:
    source = _write_source(tmp_path / "keep.txt", b"keep me")
    artifacts = encrypt_file(source, tmp_path / "outputs", params=fast_params)
    assert (
        delete_source_after_confirmation(
            artifacts.source, artifacts.source_snapshot, "no"
        )
        is False
    )
    assert source.exists()
    assert artifacts.container.exists()


def test_explicit_deletion_removes_only_source(
    tmp_path: Path, fast_params: KdfParams
) -> None:
    source = _write_source(tmp_path / "delete.txt", b"delete me")
    neighbor = _write_source(tmp_path / "neighbor.txt", b"keep neighbor")
    artifacts = encrypt_file(source, tmp_path / "outputs", params=fast_params)
    assert delete_source_after_confirmation(
        artifacts.source, artifacts.source_snapshot, "DELETE"
    )
    assert not source.exists()
    assert neighbor.exists()
    assert artifacts.container.exists()


def test_changed_source_is_not_deleted(
    tmp_path: Path, fast_params: KdfParams
) -> None:
    source = _write_source(tmp_path / "changing.txt", b"original")
    artifacts = encrypt_file(source, tmp_path / "outputs", params=fast_params)
    source.write_bytes(b"changed after encryption")
    with pytest.raises(SourceChangedError):
        delete_source_after_confirmation(
            artifacts.source, artifacts.source_snapshot, "DELETE"
        )
    assert source.exists()


def test_failed_verification_does_not_publish_or_delete(
    tmp_path: Path, fast_params: KdfParams, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = _write_source(tmp_path / "verify.txt", b"verify me")
    outputs = tmp_path / "outputs"

    def fail_verification(*_args, **_kwargs):
        raise CryptoError("simulated verification failure")

    monkeypatch.setattr(
        "cipherstrike.encrypt.verify_both_recovery_methods", fail_verification
    )
    with pytest.raises(CryptoError):
        encrypt_file(source, outputs, params=fast_params)
    assert source.exists()
    assert list(outputs.iterdir()) == []


def test_interrupted_encryption_cleans_staging(
    tmp_path: Path, fast_params: KdfParams, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = _write_source(tmp_path / "interrupt.txt", b"interrupt me")
    outputs = tmp_path / "outputs"

    def interrupt(*_args, **_kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr("cipherstrike.encrypt._stream_file_to_writer", interrupt)
    with pytest.raises(KeyboardInterrupt):
        encrypt_file(source, outputs, params=fast_params)
    assert source.exists()
    assert list(outputs.iterdir()) == []


def test_folder_source_deletion_uses_tree_snapshot(
    tmp_path: Path, fast_params: KdfParams
) -> None:
    source = tmp_path / "DeleteFolder"
    source.mkdir()
    (source / "a.txt").write_text("a", encoding="utf-8")
    neighbor = tmp_path / "neighbor.txt"
    neighbor.write_text("neighbor", encoding="utf-8")
    artifacts = encrypt_folder(source, tmp_path / "outputs", params=fast_params)
    assert delete_source_after_confirmation(
        artifacts.source, artifacts.source_snapshot, "DELETE"
    )
    assert not source.exists()
    assert neighbor.exists()
    assert artifacts.container.exists()


def test_both_recovery_methods_verify_same_payload(
    tmp_path: Path, fast_params: KdfParams
) -> None:
    source = _write_source(tmp_path / "both.txt", b"both methods" * 100)
    artifacts = encrypt_file(source, tmp_path / "outputs", params=fast_params)
    with_password, with_recovery = verify_both_recovery_methods(
        artifacts.container,
        password=artifacts.password,
        recovery_key=artifacts.recovery_key,
        expected_kind="file",
    )
    assert with_password.manifest == with_recovery.manifest
    assert with_password.computed_sha256 == with_recovery.computed_sha256


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits required")
def test_sensitive_files_have_private_permissions(
    tmp_path: Path, fast_params: KdfParams
) -> None:
    source = _write_source(tmp_path / "private.txt", b"private")
    outputs = tmp_path / "outputs"
    artifacts = encrypt_file(source, outputs, params=fast_params)
    for path in (artifacts.password_file, artifacts.recovery_file, artifacts.container):
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(outputs.stat().st_mode) == 0o700


def test_header_contains_no_plaintext_dek(tmp_path: Path, fast_params: KdfParams) -> None:
    source = _write_source(tmp_path / "header-inspect.txt", b"x")
    artifacts = encrypt_file(source, tmp_path / "outputs", params=fast_params)
    raw = artifacts.container.read_bytes()
    start = len(MAGIC) + 6
    header_len = struct.unpack(">I", raw[len(MAGIC) + 2 : len(MAGIC) + 6])[0]
    header = json.loads(raw[start : start + header_len].decode("utf-8"))
    assert "dek" not in header
    assert set(header["slots"]) == {"password", "recovery"}
    assert "wrapped_dek" in header["slots"]["password"]
    assert "wrapped_dek" in header["slots"]["recovery"]
