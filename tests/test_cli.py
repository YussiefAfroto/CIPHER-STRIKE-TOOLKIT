"""End-to-end CLI navigation and generator flow tests."""

from __future__ import annotations

import importlib.util
import io
import re
from pathlib import Path

import pytest

from cipherstrike.passwordgen import PasswordOptions
from cipherstrike.ui import UI
from cipherstrike.utils import ValidationError
from cipherstrike.wordlist import LabProfile, WordlistOptions


def _load_cli_module():
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location(
        "cipherstrike_cli_generator_test", root / "cipherstrike.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _ui(inputs: list[str]) -> tuple[UI, io.StringIO]:
    output = io.StringIO()
    iterator = iter(inputs)
    ui = UI(
        stream=output,
        error_stream=io.StringIO(),
        input_fn=lambda _prompt: next(iterator),
        force_color=False,
    )
    return ui, output


def test_password_generator_menu_zero_returns() -> None:
    cli = _load_cli_module()
    ui, output = _ui(["0"])
    cli.password_generator_screen(ui)
    assert "WELCOME TO PASSWORD GENERATOR" in output.getvalue()


def test_encryption_screen_path_zero_returns_to_encryption_menu() -> None:
    cli = _load_cli_module()
    ui, output = _ui(["1", "0", "0"])
    cli.encryption_screen(ui)
    rendered = output.getvalue()
    assert rendered.count("WELCOME TO ENCRYPT FILES") == 2


def test_decryption_screen_menu_zero_returns() -> None:
    cli = _load_cli_module()
    ui, output = _ui(["0"])
    cli.decryption_screen(ui)
    assert "WELCOME TO DECRYPT FILES" in output.getvalue()


def test_recovery_menu_zero_returns_to_decryption_menu() -> None:
    cli = _load_cli_module()
    ui, _output = _ui(["0"])
    assert cli._decrypt_with_chosen_method(ui, Path("unused.csafe"), folder=False) is False


def test_decryption_recovery_zero_redraws_decryption_menu(
    tmp_path: Path, fast_params
) -> None:
    from cipherstrike.encrypt import encrypt_file

    cli = _load_cli_module()
    source = tmp_path / "container-source.txt"
    source.write_text("navigation", encoding="utf-8")
    artifacts = encrypt_file(source, tmp_path / "outputs", params=fast_params)
    ui, output = _ui(["1", str(artifacts.container), "0", "0"])
    cli.decryption_screen(ui)
    rendered = output.getvalue()
    assert rendered.count("WELCOME TO DECRYPT FILES") == 2
    assert "DECRYPTION COMPLETED SUCCESSFULLY" not in rendered


def test_strong_password_flow_saves_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cli = _load_cli_module()
    outputs = tmp_path / "outputs"
    monkeypatch.setattr(cli, "default_outputs_dir", lambda: outputs)
    ui, output = _ui(["16", "y", "y", "y", "y", "y", "generated"])
    cli.strong_password_flow(ui)
    rendered = output.getvalue()
    assert "STRONG PASSWORD GENERATED SUCCESSFULLY" in rendered
    assert "PASSWORD SAVED SUCCESSFULLY" in rendered
    path = outputs / "generated.txt"
    assert path.exists()
    text = path.read_text(encoding="utf-8")
    password = re.search(r"Generated Password: (.+)", text)
    assert password is not None
    assert len(password.group(1)) == 16


def test_strong_password_flow_declines_overwrite(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cli = _load_cli_module()
    outputs = tmp_path / "outputs"
    outputs.mkdir()
    existing = outputs / "existing.txt"
    existing.write_text("keep me", encoding="utf-8")
    monkeypatch.setattr(cli, "default_outputs_dir", lambda: outputs)
    ui, output = _ui(["8", "y", "y", "y", "y", "y", "existing", "n"])
    cli.strong_password_flow(ui)
    assert existing.read_text(encoding="utf-8") == "keep me"
    assert "Existing file preserved" in output.getvalue()
    assert "PASSWORD SAVED SUCCESSFULLY" not in output.getvalue()


def test_strong_password_flow_declines_save(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cli = _load_cli_module()
    outputs = tmp_path / "outputs"
    monkeypatch.setattr(cli, "default_outputs_dir", lambda: outputs)
    ui, output = _ui(["8", "y", "n", "n", "n", "n"])
    cli.strong_password_flow(ui)
    assert "not saved" in output.getvalue()
    assert not outputs.exists()


def test_strong_password_save_error_is_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cli = _load_cli_module()
    monkeypatch.setattr(cli, "default_outputs_dir", lambda: tmp_path / "outputs")
    monkeypatch.setattr(
        cli, "_prompt_password_options", lambda _ui: PasswordOptions(8, True, True, True, True)
    )
    monkeypatch.setattr(cli, "generate_strong_password", lambda _options: "Aa1!Bb2@")
    monkeypatch.setattr(cli, "_prompt_save_name_password", lambda _ui: "fail")
    monkeypatch.setattr(
        cli,
        "save_password_file",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ValidationError("simulated failure")),
    )
    ui, output = _ui(["y"])
    cli.strong_password_flow(ui)
    rendered = output.getvalue()
    assert "Could not save password" in rendered
    assert "PASSWORD SAVED SUCCESSFULLY" not in rendered


def test_wordlist_flow_end_to_end_uses_verified_file_count(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cli = _load_cli_module()
    outputs = tmp_path / "outputs"
    monkeypatch.setattr(cli, "default_outputs_dir", lambda: outputs)
    inputs = [
        "Alice",             # first name
        "Smith",             # surname
        "Ally",              # nickname
        "01011990",          # birthdate
        "",                  # partner name
        "",                  # partner nickname
        "",                  # partner birthdate
        "",                  # child name
        "",                  # child nickname
        "",                  # child birthdate
        "Rex",               # pet
        "Acme",              # company
        "n",                 # add keywords
        "",                  # phone
        "lab@example.test",  # email
        "alice_lab",         # username
        "",                  # city
        "",                  # country
        "2024",              # important year
        "_,-",               # custom separators
        "y",                 # special characters
        "n",                 # random numbers
        "n",                 # leet
        "y",                 # custom separators option
        "8",                 # minimum length
        "16",                # maximum length
        "synthetic",         # output file
    ]
    ui, output = _ui(inputs)
    cli.target_wordlist_flow(ui)
    rendered = output.getvalue()
    assert "[+] WORDLIST GENERATED SUCCESSFULLY" in rendered
    path = outputs / "synthetic.txt"
    assert path.exists()
    lines = path.read_text(encoding="utf-8").splitlines()
    assert lines
    assert len(lines) == len(set(lines))
    assert all(8 <= len(line) <= 16 for line in lines)
    assert all("[+]" not in line for line in lines)
    match = re.search(r"UNIQUE CANDIDATES WRITTEN: (\d+)", rendered)
    assert match is not None
    assert int(match.group(1)) == len(lines)


def test_wordlist_flow_write_error_is_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cli = _load_cli_module()
    output_path = tmp_path / "outputs" / "failed.txt"
    monkeypatch.setattr(
        cli,
        "_collect_lab_profile",
        lambda _ui: LabProfile(first_name="Alice", surname="Smith"),
    )
    monkeypatch.setattr(cli, "_prompt_wordlist_options", lambda _ui: WordlistOptions())
    monkeypatch.setattr(cli, "_prompt_wordlist_filename", lambda _ui: (output_path, False))
    monkeypatch.setattr(cli, "generate_candidates", lambda *_args: {"Candidate123"})
    monkeypatch.setattr(
        cli,
        "write_wordlist_file",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ValidationError("simulated failure")),
    )
    ui, output = _ui([])
    cli.target_wordlist_flow(ui)
    rendered = output.getvalue()
    assert "Could not write wordlist" in rendered
    assert "WORDLIST GENERATED SUCCESSFULLY" not in rendered


def test_wordlist_flow_empty_result_does_not_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cli = _load_cli_module()
    output_path = tmp_path / "outputs" / "empty.txt"
    monkeypatch.setattr(
        cli,
        "_collect_lab_profile",
        lambda _ui: LabProfile(first_name="Al"),
    )
    monkeypatch.setattr(cli, "_prompt_wordlist_options", lambda _ui: WordlistOptions())
    monkeypatch.setattr(cli, "_prompt_wordlist_filename", lambda _ui: (output_path, False))
    ui, output = _ui([])
    cli.target_wordlist_flow(ui)
    assert "NO CANDIDATES MATCHED" in output.getvalue()
    assert not output_path.exists()
