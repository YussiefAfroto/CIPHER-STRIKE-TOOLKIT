"""Path validation, safe output naming, and snapshot tests."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from cipherstrike.utils import (
    SourceChangedError,
    UnsafePathError,
    ValidationError,
    allocate_artifact_paths,
    delete_source_checked,
    sanitize_output_name,
    snapshot_tree,
    validate_encrypted_container,
    validate_source_directory,
    validate_source_file,
)


def test_missing_and_wrong_type_paths_are_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValidationError):
        validate_source_file(str(tmp_path / "missing.txt"))
    directory = tmp_path / "folder"
    directory.mkdir()
    with pytest.raises(ValidationError):
        validate_source_file(str(directory))
    file_path = tmp_path / "file.txt"
    file_path.write_text("x", encoding="utf-8")
    with pytest.raises(ValidationError):
        validate_source_directory(str(file_path))
    with pytest.raises(ValidationError):
        validate_source_directory(str(tmp_path / "missing-folder"))


def test_symlink_source_is_rejected(tmp_path: Path) -> None:
    target = tmp_path / "target.txt"
    target.write_text("target", encoding="utf-8")
    link = tmp_path / "link.txt"
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError):
        pytest.skip("Symbolic links are not available in this environment.")
    with pytest.raises(ValidationError):
        validate_source_file(str(link))
    with pytest.raises(ValidationError):
        validate_source_directory(str(link))


def test_container_validation_rejects_tiny_and_directory_paths(tmp_path: Path) -> None:
    tiny = tmp_path / "tiny.csafe"
    tiny.write_bytes(b"x")
    with pytest.raises(ValidationError):
        validate_encrypted_container(str(tiny))
    directory = tmp_path / "dir"
    directory.mkdir()
    with pytest.raises(ValidationError):
        validate_encrypted_container(str(directory))


def test_sanitize_output_name_removes_separators() -> None:
    assert "/" not in sanitize_output_name("../../etc/passwd")
    assert "\\" not in sanitize_output_name("..\\..\\windows\\system32")
    assert sanitize_output_name("..") == "cipherstrike_output"
    assert sanitize_output_name("") == "cipherstrike_output"
    assert "\x00" not in sanitize_output_name("bad\x00name")


def test_artifact_names_do_not_overwrite(tmp_path: Path) -> None:
    first = allocate_artifact_paths(tmp_path, "report.pdf")
    first[0].write_bytes(b"one")
    second = allocate_artifact_paths(tmp_path, "report.pdf")
    assert second[0] != first[0]
    assert second[1] != first[1]
    assert second[2] != first[2]


def test_tree_snapshot_detects_changes(tmp_path: Path) -> None:
    root = tmp_path / "tree"
    root.mkdir()
    (root / "a.txt").write_text("a", encoding="utf-8")
    snapshot = snapshot_tree(root)
    (root / "b.txt").write_text("b", encoding="utf-8")
    with pytest.raises(SourceChangedError):
        delete_source_checked(root, snapshot)
    assert root.exists()


def test_snapshot_rejects_symlink_without_following(tmp_path: Path) -> None:
    root = tmp_path / "tree"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("outside", encoding="utf-8")
    try:
        os.symlink(outside, root / "link")
    except (OSError, NotImplementedError):
        pytest.skip("Symbolic links are not available in this environment.")
    with pytest.raises(UnsafePathError):
        snapshot_tree(root)


def test_delete_exact_file_snapshot(tmp_path: Path) -> None:
    source = tmp_path / "delete.txt"
    source.write_text("delete", encoding="utf-8")
    from cipherstrike.utils import FileIdentity

    identity = FileIdentity.from_stat(source.lstat(), "file")
    delete_source_checked(source, identity)
    assert not source.exists()


def test_refuses_to_delete_outputs_directory(tmp_path: Path) -> None:
    from cipherstrike.utils import FileIdentity, default_outputs_dir

    outputs = default_outputs_dir()
    outputs.mkdir(exist_ok=True)
    identity = FileIdentity.from_stat(outputs.lstat(), "dir")
    with pytest.raises(UnsafePathError):
        delete_source_checked(outputs, identity)
    assert outputs.exists()
