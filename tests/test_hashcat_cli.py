"""Hashcat CLI flow, navigation, and result-reporting tests."""

from __future__ import annotations

import io
from pathlib import Path

import pytest

from cipherstrike import hashcli
from cipherstrike.hashcat import (
    AttemptResult,
    HashcatBackendError,
    HashcatCancelled,
    HashcatNotFoundError,
    UnsupportedHashModeError,
)
from cipherstrike.hashcat_modes import get_hash_type
from cipherstrike.ui import UI


class DummyEngine:
    version = "v8.0.0"

    def __init__(self, results: list[AttemptResult]) -> None:
        self._results = iter(results)
        self.checked = []

    def check_ready(self, spec) -> None:
        self.checked.append(spec.key)

    def run_attempt(self, spec, hash_line, wordlist, *, status_callback=None):
        if status_callback is not None:
            status_callback("Status...........: Running")
        return next(self._results)


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


def _files(tmp_path: Path, lines: list[str] | None = None) -> tuple[Path, Path]:
    spec = get_hash_type("md5")
    hash_file = tmp_path / "hash file.txt"
    hash_file.write_text((lines or [spec.example])[0] + "\n", encoding="utf-8")
    if lines and len(lines) > 1:
        hash_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    wordlist = tmp_path / "word list.txt"
    wordlist.write_text("wrong\nhashcat\n", encoding="utf-8")
    return hash_file, wordlist


def _install_engine(monkeypatch: pytest.MonkeyPatch, engine) -> None:
    monkeypatch.setattr(
        hashcli.HashcatEngine, "discover", classmethod(lambda cls: engine)
    )


def test_hash_recovery_menu_navigation() -> None:
    ui, output = _ui(["0"])
    hashcli.hash_recovery_screen(ui)
    rendered = output.getvalue()
    assert "CRACK PASSWORD HASH" in rendered
    assert "[1] Raw Hashes" in rendered
    assert "[2] Password Storage" in rendered
    assert "[3] Windows Authentication" in rendered
    assert "[4] Application Hashes" in rendered
    assert "[5] Auto Detect Hash Type" in rendered
    assert "[0] Back" in rendered


def test_raw_and_storage_menus_return_on_zero() -> None:
    ui, output = _ui(["0", "0"])
    hashcli.raw_hashes_screen(ui)
    hashcli.password_storage_screen(ui)
    rendered = output.getvalue()
    assert "RAW HASHES" in rendered
    assert "PASSWORD STORAGE" in rendered


def test_windows_and_application_menus_return_on_zero() -> None:
    ui, output = _ui(["0", "0"])
    hashcli.windows_authentication_screen(ui)
    hashcli.application_hashes_screen(ui)
    rendered = output.getvalue()
    assert "WINDOWS AUTHENTICATION" in rendered
    assert "APPLICATION HASHES" in rendered
    assert "Kerberos 5" in rendered
    assert "LDAP Password Hashes" in rendered


def test_explicit_recovery_found_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    hash_file, wordlist = _files(tmp_path)
    engine = DummyEngine([AttemptResult(status="found", password="hashcat", returncode=0)])
    _install_engine(monkeypatch, engine)
    ui, output = _ui([str(hash_file), str(wordlist)])
    hashcli._recover(ui, get_hash_type("md5"))
    rendered = output.getvalue()
    assert "Selected hash type: MD5" in rendered
    assert "[+] PASSWORD FOUND: hashcat" in rendered
    assert f"Hash: {get_hash_type('md5').example}" in rendered
    assert "Recovered: 1 of 1" in rendered


def test_explicit_recovery_not_found_messages(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    hash_file, wordlist = _files(tmp_path)
    engine = DummyEngine([AttemptResult(status="not_found", returncode=1)])
    _install_engine(monkeypatch, engine)
    ui, output = _ui([str(hash_file), str(wordlist)])
    hashcli._recover(ui, get_hash_type("md5"))
    rendered = output.getvalue()
    assert "[-] PASSWORD NOT FOUND" in rendered
    assert "[-] No password in the supplied wordlist matched the hash." in rendered


def test_missing_hash_file_message_and_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    hash_file, wordlist = _files(tmp_path)
    engine = DummyEngine([AttemptResult(status="found", password="hashcat", returncode=0)])
    _install_engine(monkeypatch, engine)
    ui, output = _ui([str(tmp_path / "missing.txt"), str(hash_file), str(wordlist)])
    hashcli._recover(ui, get_hash_type("md5"))
    rendered = output.getvalue()
    assert "[!] ERROR: Hash file not found." in rendered
    assert "[!] Please check the file path and try again." in rendered
    assert "[+] PASSWORD FOUND: hashcat" in rendered


def test_missing_wordlist_message_and_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    hash_file, wordlist = _files(tmp_path)
    engine = DummyEngine([AttemptResult(status="found", password="hashcat", returncode=0)])
    _install_engine(monkeypatch, engine)
    ui, output = _ui(
        [str(hash_file), str(tmp_path / "missing-wordlist.txt"), str(wordlist)]
    )
    hashcli._recover(ui, get_hash_type("md5"))
    rendered = output.getvalue()
    assert "[!] ERROR: Wordlist file not found." in rendered
    assert "[!] Please enter a valid wordlist path." in rendered


def test_empty_hash_and_empty_wordlist_messages(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    hash_file, wordlist = _files(tmp_path)
    empty_hash = tmp_path / "empty-hash.txt"
    empty_hash.write_bytes(b"")
    empty_wordlist = tmp_path / "empty-wordlist.txt"
    empty_wordlist.write_bytes(b"")
    engine = DummyEngine([AttemptResult(status="found", password="hashcat", returncode=0)])
    _install_engine(monkeypatch, engine)
    ui, output = _ui(
        [
            str(empty_hash),
            str(hash_file),
            str(empty_wordlist),
            str(wordlist),
        ]
    )
    hashcli._recover(ui, get_hash_type("md5"))
    rendered = output.getvalue()
    assert "[!] ERROR: Hash file is empty." in rendered
    assert "[!] ERROR: Wordlist file is empty." in rendered


def test_invalid_hash_format_message(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    hash_file = tmp_path / "invalid.txt"
    hash_file.write_text("not-a-valid-md5\n", encoding="utf-8")
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("hashcat\n", encoding="utf-8")
    engine = DummyEngine([])
    _install_engine(monkeypatch, engine)
    ui, output = _ui([str(hash_file), str(wordlist)])
    hashcli._recover(ui, get_hash_type("md5"))
    rendered = output.getvalue()
    assert "[!] ERROR: Invalid or unsupported hash format." in rendered
    assert "[!] Please verify the selected hash type and input file." in rendered


def test_hashcat_missing_message(monkeypatch: pytest.MonkeyPatch) -> None:
    def missing(cls):
        raise HashcatNotFoundError("missing")

    monkeypatch.setattr(hashcli.HashcatEngine, "discover", classmethod(missing))
    ui, output = _ui([])
    hashcli._recover(ui, get_hash_type("md5"))
    rendered = output.getvalue()
    assert "[!] ERROR: Hashcat was not found." in rendered
    assert "[!] Install Hashcat from https://hashcat.net/hashcat/" in rendered


def test_unsupported_mode_message(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class UnsupportedEngine(DummyEngine):
        def check_ready(self, spec):
            raise UnsupportedHashModeError("mode missing")

    _install_engine(monkeypatch, UnsupportedEngine([]))
    ui, output = _ui([])
    hashcli._recover(ui, get_hash_type("django_pbkdf2_sha256"))
    rendered = output.getvalue()
    assert "does not support this mode" in rendered
    assert "mode missing" in rendered


def test_backend_error_message(monkeypatch: pytest.MonkeyPatch) -> None:
    class BackendFail(DummyEngine):
        def check_ready(self, spec):
            raise HashcatBackendError("no usable backend")

    _install_engine(monkeypatch, BackendFail([]))
    ui, output = _ui([])
    hashcli._recover(ui, get_hash_type("md5"))
    rendered = output.getvalue()
    assert "could not initialize a supported device/backend" in rendered
    assert "no usable backend" in rendered


def test_cancelled_search_is_not_reported_as_not_found(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    hash_file, wordlist = _files(tmp_path)
    engine = DummyEngine([AttemptResult(status="cancelled", returncode=2)])
    _install_engine(monkeypatch, engine)
    ui, output = _ui([str(hash_file), str(wordlist)])
    hashcli._recover(ui, get_hash_type("md5"))
    rendered = output.getvalue()
    assert "[!] RECOVERY CANCELLED" in rendered
    assert "PASSWORD NOT FOUND" not in rendered
    assert "No definitive no-match" in rendered


def test_failed_search_is_not_reported_as_not_found(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    hash_file, wordlist = _files(tmp_path)
    engine = DummyEngine(
        [AttemptResult(status="failed", returncode=3, diagnostic="ERROR: backend failed")]
    )
    _install_engine(monkeypatch, engine)
    ui, output = _ui([str(hash_file), str(wordlist)])
    hashcli._recover(ui, get_hash_type("md5"))
    rendered = output.getvalue()
    assert "Hashcat did not complete the recovery attempt" in rendered
    assert "PASSWORD NOT FOUND" not in rendered


def test_multiple_hashes_association_and_summary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = "8743b52063cd84097a65d1633f5c74f5"
    second = "5f4dcc3b5aa765d61d8327deb882cf99"
    hash_file, wordlist = _files(tmp_path, [first, second])
    engine = DummyEngine(
        [
            AttemptResult(status="found", password="first-pass", returncode=0),
            AttemptResult(status="not_found", returncode=1),
        ]
    )
    _install_engine(monkeypatch, engine)
    ui, output = _ui([str(hash_file), str(wordlist)])
    hashcli._recover(ui, get_hash_type("md5"))
    rendered = output.getvalue()
    assert "[+] PASSWORD FOUND: first-pass" in rendered
    assert f"Hash: {first}" in rendered
    assert "Recovered: 1 of 2" in rendered
    assert "Unresolved: 1" in rendered


def test_auto_detect_ambiguous_file_presents_candidates(
    tmp_path: Path,
) -> None:
    hash_file = tmp_path / "ambiguous.txt"
    hash_file.write_text(get_hash_type("md5").example + "\n", encoding="utf-8")
    ui, output = _ui([str(hash_file), "0"])
    hashcli.auto_detect_screen(ui)
    rendered = output.getvalue()
    assert "MULTIPLE HASH TYPES DETECTED" in rendered
    assert "MD5" in rendered
    assert "NTLM" in rendered


def test_auto_detect_selected_candidate_proceeds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    hash_file = tmp_path / "ambiguous.txt"
    hash_file.write_text(get_hash_type("md5").example + "\n", encoding="utf-8")
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("hashcat\n", encoding="utf-8")
    engine = DummyEngine([AttemptResult(status="found", password="hashcat", returncode=0)])
    _install_engine(monkeypatch, engine)
    ui, output = _ui([str(hash_file), "1", str(wordlist)])
    hashcli.auto_detect_screen(ui)
    rendered = output.getvalue()
    assert "Selected hash type: MD5" in rendered
    assert "[+] PASSWORD FOUND: hashcat" in rendered


def test_auto_detect_mixed_file_is_rejected(tmp_path: Path) -> None:
    hash_file = tmp_path / "mixed.txt"
    hash_file.write_text(
        get_hash_type("md5").example + "\n" + get_hash_type("sha1").example + "\n",
        encoding="utf-8",
    )
    ui, output = _ui([str(hash_file)])
    hashcli.auto_detect_screen(ui)
    assert "Mixed hash types were detected" in output.getvalue()


def test_hashcat_cancelled_exception_is_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    hash_file, wordlist = _files(tmp_path)

    class CancelEngine(DummyEngine):
        def run_attempt(self, *args, **kwargs):
            raise HashcatCancelled("cancelled")

    _install_engine(monkeypatch, CancelEngine([]))
    ui, output = _ui([str(hash_file), str(wordlist)])
    hashcli._recover(ui, get_hash_type("md5"))
    rendered = output.getvalue()
    assert "[!] RECOVERY CANCELLED" in rendered
    assert "PASSWORD NOT FOUND" not in rendered
