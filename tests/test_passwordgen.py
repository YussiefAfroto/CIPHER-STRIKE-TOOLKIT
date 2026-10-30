"""Strong password generation, validation, and private file-saving tests."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from cipherstrike.passwordgen import (
    PasswordOptions,
    generate_strong_password,
    parse_password_length,
    save_password_file,
)
from cipherstrike.utils import OutputExistsError, ValidationError


def _all_categories(length: int) -> PasswordOptions:
    return PasswordOptions(
        length=length,
        uppercase=True,
        lowercase=True,
        numbers=True,
        specials=True,
    )


@pytest.mark.parametrize("raw, expected", [("1", 1), ("8", 8), ("64", 64), (" 12 ", 12)])
def test_password_length_accepts_valid_integers(raw: str, expected: int) -> None:
    assert parse_password_length(raw) == expected


@pytest.mark.parametrize(
    "raw", ["", "0", "65", "-1", "abc", "1.5", "+1", "１２"]
)
def test_password_length_rejects_invalid_values(raw: str) -> None:
    with pytest.raises(ValidationError):
        parse_password_length(raw)


def test_password_options_require_a_category() -> None:
    with pytest.raises(ValidationError):
        PasswordOptions(length=8)


def test_generated_password_has_exact_length_and_all_enabled_categories() -> None:
    for length in (4, 5, 12, 32, 64):
        password = generate_strong_password(_all_categories(length))
        assert len(password) == length
        assert any(char.isupper() for char in password)
        assert any(char.islower() for char in password)
        assert any(char.isdigit() for char in password)
        assert any(not char.isalnum() for char in password)
        assert all(33 <= ord(char) <= 126 for char in password)


def test_generation_uses_secrets_choice(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[int] = []
    real_choice = __import__("secrets").choice

    def counting_choice(sequence):
        calls.append(len(sequence))
        return real_choice(sequence)

    monkeypatch.setattr("cipherstrike.passwordgen.secrets.choice", counting_choice)
    password = generate_strong_password(
        PasswordOptions(10, True, True, True, True)
    )
    assert len(password) == 10
    assert len(calls) == 10


def test_generated_password_uses_only_enabled_categories() -> None:
    options = PasswordOptions(length=40, uppercase=True, lowercase=False, numbers=True, specials=False)
    for _ in range(20):
        password = generate_strong_password(options)
        assert len(password) == 40
        assert all(char.isupper() or char.isdigit() for char in password)


def test_short_password_does_not_pretend_to_guarantee_all_categories() -> None:
    for _ in range(20):
        password = generate_strong_password(_all_categories(2))
        assert len(password) == 2


def test_save_password_file_appends_txt_and_verifies(tmp_path: Path) -> None:
    options = PasswordOptions(12, True, True, True, True)
    password = generate_strong_password(options)
    outputs = tmp_path / "outputs"
    path = save_password_file(
        password,
        options,
        output_dir=outputs,
        filename="my secret",
    )
    assert path == outputs / "my secret.txt"
    assert path.exists()
    text = path.read_text(encoding="utf-8")
    assert f"Generated Password: {password}" in text
    assert text.endswith("\n")
    if os.name != "nt":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_password_file_never_overwrites_without_permission(tmp_path: Path) -> None:
    options = PasswordOptions(10, True, True, True, True)
    first = generate_strong_password(options)
    second = generate_strong_password(options)
    outputs = tmp_path / "outputs"
    path = save_password_file(first, options, output_dir=outputs, filename="pass")
    original = path.read_text(encoding="utf-8")
    with pytest.raises(OutputExistsError):
        save_password_file(second, options, output_dir=outputs, filename="pass")
    assert path.read_text(encoding="utf-8") == original


def test_password_file_overwrite_requires_explicit_flag(tmp_path: Path) -> None:
    options = PasswordOptions(10, True, True, True, True)
    first = generate_strong_password(options)
    second = generate_strong_password(options)
    outputs = tmp_path / "outputs"
    path = save_password_file(first, options, output_dir=outputs, filename="pass")
    save_password_file(
        second, options, output_dir=outputs, filename="pass", overwrite=True
    )
    assert f"Generated Password: {second}" in path.read_text(encoding="utf-8")


def test_password_output_filename_rejects_path_traversal(tmp_path: Path) -> None:
    options = PasswordOptions(8, True, True, True, True)
    password = generate_strong_password(options)
    outputs = tmp_path / "outputs"
    with pytest.raises(ValidationError):
        save_password_file(
            password, options, output_dir=outputs, filename="../escaped"
        )
    assert not (tmp_path / "escaped.txt").exists()


def test_password_file_write_failure_propagates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    options = PasswordOptions(8, True, True, True, True)
    password = generate_strong_password(options)

    def fail_write(*_args, **_kwargs):
        raise ValidationError("simulated disk failure")

    monkeypatch.setattr("cipherstrike.passwordgen.write_text_atomic", fail_write)
    with pytest.raises(ValidationError):
        save_password_file(
            password, options, output_dir=tmp_path / "outputs", filename="fail"
        )
    assert not (tmp_path / "outputs" / "fail.txt").exists()
