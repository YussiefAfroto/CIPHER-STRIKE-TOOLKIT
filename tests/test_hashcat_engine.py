"""Hashcat process integration tests using controlled fake processes."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from cipherstrike.hashcat import (
    AttemptResult,
    HashcatBackendError,
    HashcatCancelled,
    HashcatEngine,
    UnsupportedHashModeError,
    build_command,
    decode_outfile_plain,
    parse_mode_table,
    parse_outfile,
)
from cipherstrike.hashcat_modes import get_hash_type


def test_parse_mode_table() -> None:
    text = """
- [ Options ] -
  0 | not-a-mode | something
- [ Hash Modes ] -
      # | Name                                                       | Category
  ======+============================================================+======================================
      0 | MD5                                                        | Raw Hash
   3200 | bcrypt $2*$, Blowfish (Unix)                               | Password Hash
  40024 | PBKDF2-HMAC-SHA256                                        | Password Hash
- [ Brain Client Features ] -
      1 | Send hashed passwords
"""
    assert parse_mode_table(text) == {
        0: "MD5",
        3200: "bcrypt $2*$, Blowfish (Unix)",
        40024: "PBKDF2-HMAC-SHA256",
    }


def test_discover_parses_version_and_modes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "cipherstrike.hashcat.resolve_hashcat_executable",
        lambda _explicit=None: Path("C:/Program Files/Hashcat/hashcat.exe"),
    )

    def fake_capture(args, *, timeout):
        assert args[0].endswith("hashcat.exe")
        if "--version" in args:
            return subprocess.CompletedProcess(args, 0, stdout="v8.0.0\n", stderr="")
        return subprocess.CompletedProcess(
            args,
            0,
            stdout=(
                "- [ Hash Modes ] -\n"
                "  0 | MD5 | Raw Hash\n"
                "  3200 | bcrypt $2*$ | Password Hash\n"
            ),
            stderr="",
        )

    monkeypatch.setattr(HashcatEngine, "_capture", staticmethod(fake_capture))
    engine = HashcatEngine.discover()
    assert engine.version == "v8.0.0"
    assert engine.modes[3200].startswith("bcrypt")


def test_build_command_uses_argument_list_without_shell(tmp_path: Path) -> None:
    spec = get_hash_type("md5")
    command = build_command(
        Path(r"C:\Program Files\Hashcat\hashcat.exe"),
        spec,
        tmp_path / "hash file.txt",
        tmp_path / "word list.txt",
        tmp_path / "out file.txt",
        tmp_path / "hashcat.pot",
    )
    assert command[0].endswith("hashcat.exe")
    assert command[1:3] == ["-m", "0"]
    assert command[3:5] == ["-a", "0"]
    assert "--outfile-format" in command
    assert command[command.index("--outfile-format") + 1] == "2"
    assert str(tmp_path / "hash file.txt") in command
    assert str(tmp_path / "word list.txt") in command
    assert all(isinstance(part, str) for part in command)


def test_decode_outfile_hex_plaintext() -> None:
    assert decode_outfile_plain("$HEX[68617368636174]") == "hashcat"
    with pytest.raises(Exception):
        decode_outfile_plain("$HEX[zzzz]")


def test_parse_outfile_plain_and_empty_password(tmp_path: Path) -> None:
    path = tmp_path / "out.txt"
    path.write_bytes(b"hashcat\n")
    assert parse_outfile(path) == "hashcat"
    path.write_bytes(b"\n")
    assert parse_outfile(path) == ""
    path.write_bytes(b"")
    assert parse_outfile(path) is None


def test_every_registered_mode_hint_matches_a_synthetic_catalog() -> None:
    from cipherstrike.hashcat_modes import HASH_TYPES

    catalog = {spec.mode: spec.mode_name_hint for spec in HASH_TYPES}
    engine = HashcatEngine(Path("fake"), "v8.0.0", catalog, backend_checked=True)
    for spec in HASH_TYPES:
        engine.verify_mode(spec)


def test_resolve_executable_honors_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from cipherstrike.hashcat import resolve_hashcat_executable

    executable = tmp_path / "hashcat custom.exe"
    executable.write_bytes(b"not a real binary")
    monkeypatch.setenv("CIPHERSTRIKE_HASHCAT", str(executable))
    assert resolve_hashcat_executable() == executable


def test_verify_mode_rejects_missing_or_mismatched_mode() -> None:
    spec = get_hash_type("md5")
    engine = HashcatEngine(Path("fake"), "v8.0.0", {0: "MD5"}, backend_checked=True)
    engine.verify_mode(spec)

    missing = HashcatEngine(Path("fake"), "v8.0.0", {1: "Other"}, backend_checked=True)
    with pytest.raises(UnsupportedHashModeError):
        missing.verify_mode(spec)

    mismatched = HashcatEngine(
        Path("fake"), "v8.0.0", {0: "Something Else"}, backend_checked=True
    )
    with pytest.raises(UnsupportedHashModeError):
        mismatched.verify_mode(spec)


def test_backend_check_detects_no_devices(monkeypatch: pytest.MonkeyPatch) -> None:
    engine = HashcatEngine(Path("fake"), "v8.0.0", {0: "MD5"})

    def fake_capture(args, *, timeout):
        return subprocess.CompletedProcess(
            args, 0, stdout="", stderr="No devices found. Please install OpenCL."
        )

    monkeypatch.setattr(HashcatEngine, "_capture", staticmethod(fake_capture))
    with pytest.raises(HashcatBackendError):
        engine.check_backends()


class FakeStdout:
    def __init__(self, lines: list[str], *, interrupt: bool = False) -> None:
        self._iterator = iter(lines)
        self._interrupt = interrupt
        self.closed = False

    def __iter__(self):
        return self

    def __next__(self):
        if self._interrupt:
            raise KeyboardInterrupt
        return next(self._iterator)

    def close(self) -> None:
        self.closed = True


class FakeProcess:
    def __init__(
        self,
        lines: list[str],
        returncode: int,
        *,
        interrupt: bool = False,
    ) -> None:
        self.stdout = FakeStdout(lines, interrupt=interrupt)
        self.returncode = returncode
        self.terminated = False
        self.killed = False

    def wait(self, timeout=None):
        return self.returncode

    def terminate(self) -> None:
        self.terminated = True

    def kill(self) -> None:
        self.killed = True


def _patch_popen(
    monkeypatch: pytest.MonkeyPatch,
    *,
    lines: list[str],
    returncode: int,
    outfile_text: str | None = None,
    interrupt: bool = False,
) -> list[list[str]]:
    calls: list[list[str]] = []

    def fake_popen(command, **kwargs):
        calls.append(list(command))
        if outfile_text is not None:
            outfile = Path(command[command.index("--outfile") + 1])
            outfile.write_text(outfile_text, encoding="utf-8")
        return FakeProcess(lines, returncode, interrupt=interrupt)

    monkeypatch.setattr("cipherstrike.hashcat.subprocess.Popen", fake_popen)
    return calls


def test_run_attempt_reports_found_only_from_outfile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _patch_popen(
        monkeypatch,
        lines=["Status...........: Cracked\n", "Recovered........: 1/1\n"],
        returncode=0,
        outfile_text="hashcat\n",
    )
    engine = HashcatEngine(Path("fake"), "v8.0.0", {0: "MD5"}, backend_checked=True)
    wordlist = tmp_path / "word list.txt"
    wordlist.write_text("hashcat\n", encoding="utf-8")
    result = engine.run_attempt(get_hash_type("md5"), "8743b52063cd84097a65d1633f5c74f5", wordlist)
    assert result.status == "found"
    assert result.password == "hashcat"
    assert calls and calls[0][1:3] == ["-m", "0"]


def test_run_attempt_reports_not_found_only_on_exhausted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_popen(
        monkeypatch,
        lines=["Status...........: Exhausted\n"],
        returncode=1,
    )
    engine = HashcatEngine(Path("fake"), "v8.0.0", {0: "MD5"}, backend_checked=True)
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("wrong\n", encoding="utf-8")
    result = engine.run_attempt(get_hash_type("md5"), "8743b52063cd84097a65d1633f5c74f5", wordlist)
    assert result.status == "not_found"
    assert result.password is None


def test_run_attempt_reports_failed_process_without_false_no_match(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_popen(
        monkeypatch,
        lines=["ERROR: No devices found\n"],
        returncode=3,
    )
    engine = HashcatEngine(Path("fake"), "v8.0.0", {0: "MD5"}, backend_checked=True)
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("wrong\n", encoding="utf-8")
    result = engine.run_attempt(get_hash_type("md5"), "8743b52063cd84097a65d1633f5c74f5", wordlist)
    assert result.status == "failed"
    assert "no-match" not in result.diagnostic.lower()


def test_returncode_one_with_error_is_not_reported_as_no_match(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_popen(
        monkeypatch,
        lines=["ERROR: backend failed\n"],
        returncode=1,
    )
    engine = HashcatEngine(Path("fake"), "v8.0.0", {0: "MD5"}, backend_checked=True)
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("wrong\n", encoding="utf-8")
    result = engine.run_attempt(
        get_hash_type("md5"), "8743b52063cd84097a65d1633f5c74f5", wordlist
    )
    assert result.status == "failed"


def test_run_attempt_cancellation_terminates_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_popen(
        monkeypatch,
        lines=[],
        returncode=0,
        interrupt=True,
    )
    engine = HashcatEngine(Path("fake"), "v8.0.0", {0: "MD5"}, backend_checked=True)
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("wrong\n", encoding="utf-8")
    with pytest.raises(HashcatCancelled):
        engine.run_attempt(
            get_hash_type("md5"), "8743b52063cd84097a65d1633f5c74f5", wordlist
        )
