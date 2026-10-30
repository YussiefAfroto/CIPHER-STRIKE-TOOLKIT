"""Real Hashcat integration tests.

These tests execute the installed official engine.  When Hashcat is absent or
no supported backend is available they are skipped rather than reported as
passed.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from cipherstrike.hashcat import (
    HashcatBackendError,
    HashcatEngine,
    HashcatNotFoundError,
)
from cipherstrike.hashcat_modes import get_hash_type, validate_hash_file, validate_wordlist


HASHCAT_EXECUTABLE = shutil.which("hashcat") or shutil.which("hashcat.exe")
HASHCAT_AVAILABLE = HASHCAT_EXECUTABLE is not None


@pytest.mark.skipif(
    not HASHCAT_AVAILABLE,
    reason=(
        "Hashcat is not installed on this machine. Install it from "
        "https://hashcat.net/hashcat/ to run real recovery tests."
    ),
)
def test_real_md5_recovery_and_no_match(tmp_path: Path) -> None:
    engine = HashcatEngine.discover()
    spec = get_hash_type("md5")
    try:
        engine.check_ready(spec)
    except HashcatBackendError as exc:
        pytest.skip(f"Hashcat has no usable backend on this machine: {exc}")

    hash_file = tmp_path / "hash.txt"
    hash_file.write_text(spec.example + "\n", encoding="utf-8")
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("definitely-wrong\nhashcat\n", encoding="utf-8")
    lines = validate_hash_file(hash_file, spec)
    validate_wordlist(wordlist)

    result = engine.run_attempt(spec, lines[0], wordlist)
    assert result.status == "found"
    assert result.password == "hashcat"

    wrong_wordlist = tmp_path / "wrong.txt"
    wrong_wordlist.write_text("not-the-password\n", encoding="utf-8")
    validate_wordlist(wrong_wordlist)
    no_match = engine.run_attempt(spec, lines[0], wrong_wordlist)
    assert no_match.status == "not_found"
    assert no_match.password is None
