"""Hash-mode registry, syntax validation, and auto-detection tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from cipherstrike.hashcat_modes import (
    HASH_TYPES,
    EmptyHashFileError,
    EmptyWordlistError,
    HashFileNotFoundError,
    InvalidHashFormatError,
    MixedHashTypesError,
    UnsupportedHashDetectionError,
    WordlistNotFoundError,
    detect_candidates,
    detect_hash_file,
    get_hash_type,
    read_hash_lines,
    validate_hash_file,
    validate_wordlist,
)


EXPECTED_MODES = {
    "md5": 0,
    "sha1": 100,
    "sha224": 1300,
    "sha256": 1400,
    "sha384": 10800,
    "sha512": 1700,
    "sha3_224": 17300,
    "sha3_256": 17400,
    "sha3_384": 17500,
    "sha3_512": 17600,
    "ripemd160": 6000,
    "blake2b512": 600,
    "blake2b256": 34800,
    "blake2s256": 31000,
    "bcrypt": 3200,
    "pbkdf2_sha256": 40024,
    "pbkdf2_md5": 40031,
    "pbkdf2_sha1": 40032,
    "pbkdf2_sha512": 40034,
    "scrypt": 8900,
    "scryptcrypt": 36300,
    "argon2id": 34000,
    "phpass": 400,
    "yescrypt": 36100,
    "ntlm": 1000,
    "netntlmv1": 5500,
    "netntlmv2": 5600,
    "krb5_asreq_23": 7500,
    "krb5_tgs_23": 13100,
    "krb5_asrep_23": 18200,
    "krb5_tgs_17": 19600,
    "krb5_tgs_18": 19700,
    "krb5_asrep_17": 32100,
    "krb5_asrep_18": 32200,
    "wordpress_phpass": 400,
    "django_pbkdf2_sha256": 40022,
    "mysql323": 200,
    "mysql41": 300,
    "mysql_a": 7401,
    "postgresql": 12,
    "mssql2000": 131,
    "mssql2005": 132,
    "mssql2012": 1731,
    "mssql2025": 36601,
    "cisco_ios1": 500,
    "cisco_type4": 5700,
    "cisco_ios9": 9300,
    "ldap_sha": 101,
    "ldap_ssha": 111,
    "ldap_ssha256": 1411,
    "ldap_ssha512": 1711,
}


def test_all_registered_examples_validate() -> None:
    assert len(HASH_TYPES) == len(EXPECTED_MODES)
    for spec in HASH_TYPES:
        spec.validator(spec.example)
        with pytest.raises(InvalidHashFormatError):
            spec.validator(spec.example + "!")


def test_every_registered_type_validates_through_a_hash_file(tmp_path: Path) -> None:
    for index, spec in enumerate(HASH_TYPES):
        path = tmp_path / f"hash-{index}.txt"
        path.write_text(spec.example + "\n", encoding="utf-8")
        assert validate_hash_file(path, spec) == [spec.example]


def test_mode_mapping_matches_official_hashcat_8_table() -> None:
    assert {spec.key: spec.mode for spec in HASH_TYPES} == EXPECTED_MODES


def test_every_hash_type_has_nonempty_syntax_and_name_hint() -> None:
    for spec in HASH_TYPES:
        assert spec.label
        assert spec.mode_name_hint
        assert spec.syntax
        assert spec.category in {"raw", "storage", "windows", "application"}


def test_official_examples_detect_their_registered_type() -> None:
    for spec in HASH_TYPES:
        if not spec.detect:
            continue
        detected = {candidate.key for candidate in detect_candidates(spec.example)}
        assert spec.key in detected


def test_ambiguous_lengths_return_multiple_candidates() -> None:
    md5 = get_hash_type("md5").example
    sha1 = get_hash_type("sha1").example
    sha256 = get_hash_type("sha256").example
    assert {spec.key for spec in detect_candidates(md5)} == {"md5", "ntlm"}
    assert {spec.key for spec in detect_candidates(sha1)} == {
        "sha1",
        "ripemd160",
        "mysql41",
    }
    assert {spec.key for spec in detect_candidates(sha256)} == {"sha256", "sha3_256"}


def test_prefixed_formats_are_not_guessed_from_length_alone() -> None:
    bcrypt = get_hash_type("bcrypt").example
    assert [spec.key for spec in detect_candidates(bcrypt)] == ["bcrypt"]
    django = get_hash_type("django_pbkdf2_sha256").example
    assert [spec.key for spec in detect_candidates(django)] == [
        "django_pbkdf2_sha256"
    ]
    blake = get_hash_type("blake2b256").example
    assert {spec.key for spec in detect_candidates(blake)} == {
        "blake2b256",
        "blake2s256",
    }


def test_hash_file_validation_with_spaces_in_path(tmp_path: Path) -> None:
    path = tmp_path / "hash file with spaces.txt"
    path.write_text(get_hash_type("md5").example + "\n", encoding="utf-8")
    lines = validate_hash_file(path, get_hash_type("md5"))
    assert lines == [get_hash_type("md5").example]


def test_bom_and_blank_lines_are_handled(tmp_path: Path) -> None:
    path = tmp_path / "bom.txt"
    path.write_bytes(b"\xef\xbb\xbf" + get_hash_type("md5").example.encode() + b"\n\n")
    assert read_hash_lines(path) == [get_hash_type("md5").example]


def test_missing_and_empty_hash_files_are_distinct(tmp_path: Path) -> None:
    with pytest.raises(HashFileNotFoundError):
        read_hash_lines(tmp_path / "missing.txt")
    empty = tmp_path / "empty.txt"
    empty.write_bytes(b"")
    with pytest.raises(EmptyHashFileError):
        read_hash_lines(empty)
    blanks = tmp_path / "blanks.txt"
    blanks.write_text("\n   \n", encoding="utf-8")
    with pytest.raises(EmptyHashFileError):
        read_hash_lines(blanks)


def test_invalid_hash_reports_line_number(tmp_path: Path) -> None:
    path = tmp_path / "hashes.txt"
    path.write_text(
        get_hash_type("md5").example + "\nnot-a-hash\n", encoding="utf-8"
    )
    with pytest.raises(InvalidHashFormatError) as excinfo:
        validate_hash_file(path, get_hash_type("md5"))
    assert "line 2" in str(excinfo.value).lower()


def test_missing_and_empty_wordlists_are_distinct(tmp_path: Path) -> None:
    with pytest.raises(WordlistNotFoundError):
        validate_wordlist(tmp_path / "missing.txt")
    empty = tmp_path / "empty.txt"
    empty.write_bytes(b"")
    with pytest.raises(EmptyWordlistError):
        validate_wordlist(empty)
    valid = tmp_path / "words with spaces.txt"
    valid.write_text("hashcat\nwrong\n", encoding="utf-8")
    validate_wordlist(valid)


def test_mixed_hash_file_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "mixed.txt"
    path.write_text(
        get_hash_type("md5").example + "\n" + get_hash_type("sha1").example + "\n",
        encoding="utf-8",
    )
    with pytest.raises(MixedHashTypesError):
        detect_hash_file(path)


def test_unsupported_hash_line_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "unknown.txt"
    path.write_text("this-is-not-a-supported-hash\n", encoding="utf-8")
    with pytest.raises(UnsupportedHashDetectionError):
        detect_hash_file(path)


def test_single_format_multi_hash_detection(tmp_path: Path) -> None:
    path = tmp_path / "many.txt"
    path.write_text(
        get_hash_type("md5").example + "\n" + get_hash_type("ntlm").example + "\n",
        encoding="utf-8",
    )
    candidates, count = detect_hash_file(path)
    assert {spec.key for spec in candidates} == {"md5", "ntlm"}
    assert count == 2
