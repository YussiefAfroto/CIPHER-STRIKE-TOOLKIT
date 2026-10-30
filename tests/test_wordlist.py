"""Wordlist validation, generation, filtering, and file-verification tests."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from cipherstrike.utils import OutputExistsError, ValidationError
from cipherstrike.wordlist import (
    EmptyWordlistError,
    LabProfile,
    WordlistOptions,
    generate_candidates,
    parse_keywords,
    parse_output_length,
    parse_separators,
    validate_birthdate,
    validate_email,
    validate_important_year,
    validate_phone,
    validate_text_field,
    validate_username,
    resolve_wordlist_path,
    verify_wordlist_file,
    write_wordlist_file,
)


def _profile(**overrides) -> LabProfile:
    values = dict(first_name="Alice", surname="Smith")
    values.update(overrides)
    return LabProfile(**values)


def test_structured_field_validation() -> None:
    assert validate_birthdate("29022000", "birthdate") == "29022000"
    with pytest.raises(ValidationError):
        validate_birthdate("31021999", "birthdate")
    with pytest.raises(ValidationError):
        validate_birthdate("01012050", "birthdate")
    with pytest.raises(ValidationError):
        validate_birthdate("1011990", "birthdate")
    assert validate_phone("+20 100 123 4567") == "+20 100 123 4567"
    with pytest.raises(ValidationError):
        validate_phone("call-me")
    assert validate_email("lab@example.test") == "lab@example.test"
    with pytest.raises(ValidationError):
        validate_email("not-an-email")
    assert validate_username("lab_user-1") == "lab_user-1"
    with pytest.raises(ValidationError):
        validate_username("bad user")
    assert validate_important_year("2024") == "2024"
    with pytest.raises(ValidationError):
        validate_important_year("24")


def test_text_fields_are_optional_and_not_invented() -> None:
    assert validate_text_field("", field_label="surname") == ""
    assert validate_text_field("  Synthetic  Lab  ", field_label="company") == "Synthetic Lab"
    with pytest.raises(ValidationError):
        validate_text_field("bad/name", field_label="nickname")


def test_keywords_and_separators_are_trimmed_and_deduped() -> None:
    assert parse_keywords(" alpha, beta ,alpha,  ") == ("alpha", "beta")
    assert parse_separators("_, .,_, -") == ("_", ".", "-")
    with pytest.raises(ValidationError):
        parse_separators("a")
    with pytest.raises(ValidationError):
        parse_separators("_, ., - , # , @ , !")


def test_profile_blank_fields_do_not_become_words() -> None:
    profile = _profile(nickname="", company_name="", keywords=())
    candidates = generate_candidates(profile, WordlistOptions(min_length=8, max_length=32))
    assert "" not in candidates
    assert all(candidate.strip() for candidate in candidates)
    assert "alicesmith" in candidates
    assert "alice" not in candidates  # below the minimum length


def test_generation_uses_only_supplied_profile_values() -> None:
    profile = _profile(nickname="Ally", company_name="Acme")
    candidates = generate_candidates(profile, WordlistOptions(min_length=8, max_length=32))
    assert "alicesmith" in candidates
    assert "aliceally" in candidates
    assert not any("bob" in candidate.lower() for candidate in candidates)


def test_custom_separators_are_opt_in() -> None:
    profile = _profile(custom_separators=("_", "."))
    without = generate_candidates(
        profile,
        WordlistOptions(custom_separators=False, min_length=8, max_length=32),
    )
    with_separators = generate_candidates(
        profile,
        WordlistOptions(custom_separators=True, min_length=8, max_length=32),
    )
    assert "alice_smith" not in without
    assert "alice_smith" in with_separators
    assert "alice.smith" in with_separators


def test_enabled_separators_without_values_do_not_invent_defaults() -> None:
    profile = _profile()
    candidates = generate_candidates(
        profile,
        WordlistOptions(custom_separators=True, min_length=8, max_length=32),
    )
    assert "alice_smith" not in candidates
    assert "alice.smith" not in candidates


def test_special_characters_are_opt_in() -> None:
    profile = _profile()
    plain = generate_candidates(profile, WordlistOptions(min_length=8, max_length=32))
    special = generate_candidates(
        profile,
        WordlistOptions(special_chars=True, min_length=8, max_length=32),
    )
    assert "alicesmith!" not in plain
    assert "alicesmith!" in special


def test_numeric_suffixes_are_opt_in() -> None:
    profile = _profile()
    plain = generate_candidates(profile, WordlistOptions(min_length=8, max_length=32))
    numeric = generate_candidates(
        profile,
        WordlistOptions(random_numbers=True, min_length=8, max_length=32),
    )
    assert "alicesmith0" not in plain
    assert "alicesmith0" in numeric
    assert "alicesmith99" in numeric


def test_leet_mode_is_opt_in_and_transforms_candidates() -> None:
    profile = _profile()
    plain = generate_candidates(profile, WordlistOptions(min_length=8, max_length=32))
    leet = generate_candidates(
        profile,
        WordlistOptions(leet_mode=True, min_length=8, max_length=32),
    )
    assert "4l1c35m17h" not in plain
    assert "4l1c35m17h" in leet


def test_year_suffixes_come_from_supplied_dates() -> None:
    profile = _profile(birthdate="01011990", important_year="2024")
    candidates = generate_candidates(profile, WordlistOptions(min_length=8, max_length=32))
    assert "alicesmith1990" in candidates
    assert "alicesmith2024" in candidates


def test_min_max_filter_is_applied_to_every_candidate() -> None:
    candidates = generate_candidates(
        _profile(), WordlistOptions(min_length=10, max_length=12)
    )
    assert candidates
    assert all(10 <= len(candidate) <= 12 for candidate in candidates)


def test_empty_result_is_returned_honestly() -> None:
    profile = LabProfile(first_name="Al")
    assert generate_candidates(profile, WordlistOptions(min_length=8, max_length=32)) == set()


def test_profile_without_source_data_is_rejected() -> None:
    with pytest.raises(EmptyWordlistError):
        generate_candidates(LabProfile(), WordlistOptions())


def test_candidate_count_depends_on_profile_and_options() -> None:
    small = generate_candidates(
        LabProfile(first_name="Alice", surname="Smith"),
        WordlistOptions(min_length=8, max_length=32),
    )
    larger = generate_candidates(
        LabProfile(first_name="Alice", surname="Smith", nickname="Ally", pet_name="Rex"),
        WordlistOptions(special_chars=True, random_numbers=True, min_length=8, max_length=32),
    )
    assert len(larger) > len(small)


def test_output_length_validation() -> None:
    assert parse_output_length("8", label="Minimum output length") == 8
    assert parse_output_length("32", label="Maximum output length") == 32
    for value in ("7", "33", "abc", "", "0"):
        with pytest.raises(ValidationError):
            parse_output_length(value, label="Output length")
    with pytest.raises(ValidationError):
        WordlistOptions(min_length=20, max_length=10)


def test_wordlist_file_is_one_candidate_per_line_and_count_is_verified(
    tmp_path: Path,
) -> None:
    candidates = {"Alpha1234", "Bravo5678", "Charlie9012"}
    outputs = tmp_path / "outputs"
    path = resolve_wordlist_path(outputs, "synthetic")
    assert path == outputs / "synthetic.txt"
    count = write_wordlist_file(candidates, path)
    assert count == 3
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    assert lines == sorted(candidates, key=lambda item: (item.casefold(), item))
    assert all(line and not line.startswith("[") for line in lines)
    assert path.read_text(encoding="utf-8").endswith("\n")
    if os.name != "nt":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_saved_file_count_matches_actual_generation(tmp_path: Path) -> None:
    profile = _profile(nickname="Ally", birthdate="01011990")
    candidates = generate_candidates(
        profile, WordlistOptions(min_length=8, max_length=20)
    )
    path = resolve_wordlist_path(tmp_path / "outputs", "actual")
    count = write_wordlist_file(candidates, path)
    assert count == len(candidates)
    assert verify_wordlist_file(path, expected=candidates) == len(candidates)


def test_existing_wordlist_requires_overwrite_flag(tmp_path: Path) -> None:
    path = resolve_wordlist_path(tmp_path / "outputs", "list")
    write_wordlist_file({"FirstCandidate"}, path)
    with pytest.raises(OutputExistsError):
        write_wordlist_file({"SecondCandidate"}, path)
    assert path.read_text(encoding="utf-8") == "FirstCandidate\n"
    write_wordlist_file({"SecondCandidate"}, path, overwrite=True)
    assert path.read_text(encoding="utf-8") == "SecondCandidate\n"


def test_duplicate_or_blank_saved_lines_are_rejected(tmp_path: Path) -> None:
    path = tmp_path / "bad.txt"
    path.write_text("alpha\nbeta\nalpha\n", encoding="utf-8")
    with pytest.raises(ValidationError):
        verify_wordlist_file(path)
    path.write_text("alpha\n\nbeta\n", encoding="utf-8")
    with pytest.raises(ValidationError):
        verify_wordlist_file(path)


def test_wordlist_write_failure_propagates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail_write(*_args, **_kwargs):
        raise ValidationError("simulated disk failure")

    monkeypatch.setattr("cipherstrike.wordlist.write_text_atomic", fail_write)
    path = resolve_wordlist_path(tmp_path / "outputs", "fail")
    with pytest.raises(ValidationError):
        write_wordlist_file({"Candidate123"}, path)
    assert not path.exists()
