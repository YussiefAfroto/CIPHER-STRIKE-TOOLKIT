"""Synthetic lab-profile validation and target-wordlist candidate generation.

The engine is intentionally separate from the cryptographic password
generator.  It derives candidates only from supplied synthetic lab-profile
values, enabled keywords, and documented transformations.  It does not use a
name database or invent unrelated people, brands, hobbies, websites, or random
profile words.

Design boundaries (documented in README):
* case variants (original, lowercase, title case, uppercase, compact forms);
* ordered two-field combinations, with optional custom separators;
* date forms and birth/important-year suffixes;
* a bounded 0-99 numeric suffix set when RANDOM NUMBERS? is enabled;
* one special-character suffix from ``!@#$%^&*`` when enabled;
* Leet substitutions for a, i, e, t, o, s, g, z when enabled;
* exact deduplication and min/max length filtering.

Unlike CUPP, this implementation does not build all two- and three-component
date cartesian products or hold multiple giant intermediate lists.  Its output
count is whatever the supplied profile and enabled rules actually produce.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from datetime import date
from pathlib import Path

from .output import prepare_output_path, write_text_atomic
from .utils import CipherStrikeError, ValidationError

MIN_OUTPUT_LENGTH = 8
MAX_OUTPUT_LENGTH = 32
MIN_PROFILE_YEAR = 1900
MAX_IMPORTANT_YEAR = 2100
MAX_TEXT_FIELD_LENGTH = 64
MAX_KEYWORDS = 20
MAX_KEYWORD_LENGTH = 32
MAX_SEPARATORS = 5
MAX_SEPARATOR_LENGTH = 3

SPECIAL_SUFFIXES = tuple("!@#$%^&*")
NUMERIC_SUFFIXES = tuple(str(number) for number in range(100))
LEET_TRANSLATION = str.maketrans(
    {
        "a": "4",
        "i": "1",
        "e": "3",
        "t": "7",
        "o": "0",
        "s": "5",
        "g": "9",
        "z": "2",
    }
)

ASCII_DIGITS_RE = re.compile(r"^[0-9]+$")
PHONE_RE = re.compile(r"^\+?[0-9() .-]+$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,31}$")


class EmptyWordlistError(CipherStrikeError):
    """No candidates survived generation and filtering."""


@dataclass(frozen=True)
class LabProfile:
    """Synthetic lab-profile fields.  Blank optional fields remain blank."""

    first_name: str = ""
    surname: str = ""
    nickname: str = ""
    birthdate: str = ""
    partner_name: str = ""
    partner_nickname: str = ""
    partner_birthdate: str = ""
    child_name: str = ""
    child_nickname: str = ""
    child_birthdate: str = ""
    pet_name: str = ""
    company_name: str = ""
    keywords: tuple[str, ...] = ()
    phone: str = ""
    email: str = ""
    username: str = ""
    city: str = ""
    country: str = ""
    important_year: str = ""
    custom_separators: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        text_fields = (
            "first_name",
            "surname",
            "nickname",
            "partner_name",
            "partner_nickname",
            "child_name",
            "child_nickname",
            "pet_name",
            "company_name",
            "city",
            "country",
        )
        for field_name in text_fields:
            value = validate_text_field(
                getattr(self, field_name), field_label=field_name.replace("_", " ")
            )
            object.__setattr__(self, field_name, value)
        object.__setattr__(
            self, "birthdate", validate_birthdate(self.birthdate, "birthdate")
        )
        object.__setattr__(
            self,
            "partner_birthdate",
            validate_birthdate(self.partner_birthdate, "partner birthdate"),
        )
        object.__setattr__(
            self,
            "child_birthdate",
            validate_birthdate(self.child_birthdate, "child birthdate"),
        )
        object.__setattr__(self, "phone", validate_phone(self.phone))
        object.__setattr__(self, "email", validate_email(self.email))
        object.__setattr__(self, "username", validate_username(self.username))
        object.__setattr__(
            self, "important_year", validate_important_year(self.important_year)
        )
        keywords = tuple(validate_keyword(word) for word in self.keywords if word.strip())
        if len(keywords) > MAX_KEYWORDS:
            raise ValidationError(f"At most {MAX_KEYWORDS} keywords may be supplied.")
        object.__setattr__(self, "keywords", tuple(dict.fromkeys(keywords)))
        separators = tuple(
            validate_separator(separator)
            for separator in self.custom_separators
            if separator.strip()
        )
        if len(separators) > MAX_SEPARATORS:
            raise ValidationError(
                f"At most {MAX_SEPARATORS} custom separators may be supplied."
            )
        object.__setattr__(self, "custom_separators", tuple(dict.fromkeys(separators)))

    def has_source_data(self) -> bool:
        return any(
            (
                self.first_name,
                self.surname,
                self.nickname,
                self.birthdate,
                self.partner_name,
                self.partner_nickname,
                self.partner_birthdate,
                self.child_name,
                self.child_nickname,
                self.child_birthdate,
                self.pet_name,
                self.company_name,
                self.keywords,
                self.phone,
                self.email,
                self.username,
                self.city,
                self.country,
                self.important_year,
            )
        )


@dataclass(frozen=True)
class WordlistOptions:
    """Enabled transformations and final output length range."""

    special_chars: bool = False
    random_numbers: bool = False
    leet_mode: bool = False
    custom_separators: bool = False
    min_length: int = MIN_OUTPUT_LENGTH
    max_length: int = MAX_OUTPUT_LENGTH

    def __post_init__(self) -> None:
        if not isinstance(self.min_length, int) or not isinstance(self.max_length, int):
            raise ValidationError("Minimum and maximum output lengths must be integers.")
        if not MIN_OUTPUT_LENGTH <= self.min_length <= MAX_OUTPUT_LENGTH:
            raise ValidationError(
                f"Minimum output length must be between {MIN_OUTPUT_LENGTH} and "
                f"{MAX_OUTPUT_LENGTH}."
            )
        if not MIN_OUTPUT_LENGTH <= self.max_length <= MAX_OUTPUT_LENGTH:
            raise ValidationError(
                f"Maximum output length must be between {MIN_OUTPUT_LENGTH} and "
                f"{MAX_OUTPUT_LENGTH}."
            )
        if self.min_length > self.max_length:
            raise ValidationError(
                "Minimum output length cannot be greater than maximum output length."
            )


def _parse_ascii_integer(raw: str, label: str) -> int:
    if not isinstance(raw, str):
        raise ValidationError(f"{label} must be a whole number.")
    value = raw.strip()
    if not value or not ASCII_DIGITS_RE.fullmatch(value):
        raise ValidationError(f"{label} must be a whole number.")
    return int(value, 10)


def parse_output_length(raw: str, *, label: str) -> int:
    """Validate one interactive min/max output length answer."""
    value = _parse_ascii_integer(raw, label)
    if not MIN_OUTPUT_LENGTH <= value <= MAX_OUTPUT_LENGTH:
        raise ValidationError(
            f"{label} must be between {MIN_OUTPUT_LENGTH} and {MAX_OUTPUT_LENGTH}."
        )
    return value


def validate_text_field(
    raw: str, *, field_label: str = "field", allow_blank: bool = True
) -> str:
    """Normalize a printable profile text field without inventing a value."""
    if raw is None:
        raw = ""
    if not isinstance(raw, str):
        raise ValidationError(f"{field_label.capitalize()} must be text.")
    try:
        text = unicodedata.normalize("NFC", raw.strip())
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"{field_label.capitalize()} is not valid text.") from exc
    if not text:
        if allow_blank:
            return ""
        raise ValidationError(f"{field_label.capitalize()} cannot be empty.")
    if len(text) > MAX_TEXT_FIELD_LENGTH:
        raise ValidationError(
            f"{field_label.capitalize()} is too long "
            f"(maximum {MAX_TEXT_FIELD_LENGTH} characters)."
        )
    if "\x00" in text or "/" in text or "\\" in text:
        raise ValidationError(
            f"{field_label.capitalize()} must not contain path separators or NUL bytes."
        )
    if any(ord(char) < 32 or ord(char) == 127 for char in text):
        raise ValidationError(
            f"{field_label.capitalize()} contains control characters."
        )
    if not text.isprintable():
        raise ValidationError(f"{field_label.capitalize()} contains unprintable characters.")
    return " ".join(text.split())


def validate_birthdate(raw: str, label: str = "birthdate") -> str:
    """Validate an optional DDMMYYYY date; blank remains blank."""
    if raw is None:
        raw = ""
    if not isinstance(raw, str):
        raise ValidationError(f"{label.capitalize()} must be text.")
    text = raw.strip()
    if not text:
        return ""
    if not ASCII_DIGITS_RE.fullmatch(text) or len(text) != 8:
        raise ValidationError(
            f"{label.capitalize()} must use DDMMYYYY with exactly eight digits."
        )
    try:
        parsed = date(int(text[4:]), int(text[2:4]), int(text[:2]))
    except ValueError as exc:
        raise ValidationError(f"{label.capitalize()} is not a valid calendar date.") from exc
    current_year = date.today().year
    if not MIN_PROFILE_YEAR <= parsed.year <= current_year:
        raise ValidationError(
            f"{label.capitalize()} year must be between {MIN_PROFILE_YEAR} "
            f"and {current_year}."
        )
    return text


def validate_important_year(raw: str) -> str:
    if raw is None:
        raw = ""
    if not isinstance(raw, str):
        raise ValidationError("Important year must be text.")
    value = raw.strip()
    if not value:
        return ""
    if not ASCII_DIGITS_RE.fullmatch(value) or len(value) != 4:
        raise ValidationError("Important year must contain exactly four digits.")
    year = int(value, 10)
    if not MIN_PROFILE_YEAR <= year <= MAX_IMPORTANT_YEAR:
        raise ValidationError(
            f"Important year must be between {MIN_PROFILE_YEAR} and {MAX_IMPORTANT_YEAR}."
        )
    return value


def validate_phone(raw: str) -> str:
    if raw is None:
        raw = ""
    if not isinstance(raw, str):
        raise ValidationError("Phone number must be text.")
    value = raw.strip()
    if not value:
        return ""
    if len(value) > 24 or not PHONE_RE.fullmatch(value):
        raise ValidationError(
            "Phone number may contain only digits, spaces, +, -, parentheses, or dots."
        )
    digits = re.sub(r"[^0-9]", "", value)
    if not 7 <= len(digits) <= 15:
        raise ValidationError("Phone number must contain between 7 and 15 digits.")
    return value


def validate_email(raw: str) -> str:
    if raw is None:
        raw = ""
    if not isinstance(raw, str):
        raise ValidationError("Email address must be text.")
    value = raw.strip()
    if not value:
        return ""
    if len(value) > 254 or not EMAIL_RE.fullmatch(value):
        raise ValidationError("Email address is not in a valid address@domain.tld form.")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValidationError("Email address contains control characters.")
    return value


def validate_username(raw: str) -> str:
    if raw is None:
        raw = ""
    if not isinstance(raw, str):
        raise ValidationError("Username must be text.")
    value = raw.strip()
    if not value:
        return ""
    if not USERNAME_RE.fullmatch(value):
        raise ValidationError(
            "Username must be 3-32 characters, start with a letter or digit, "
            "and contain only letters, digits, dot, underscore, or hyphen."
        )
    return value


def validate_keyword(raw: str) -> str:
    value = validate_text_field(raw, field_label="keyword", allow_blank=False)
    if len(value) > MAX_KEYWORD_LENGTH:
        raise ValidationError(
            f"Each keyword must be at most {MAX_KEYWORD_LENGTH} characters."
        )
    if "," in value:
        raise ValidationError("Keywords must be separated with commas, not contain them.")
    return value


def parse_keywords(raw: str) -> tuple[str, ...]:
    """Parse comma-separated keywords, trimming surrounding whitespace."""
    if raw is None:
        raw = ""
    if not isinstance(raw, str):
        raise ValidationError("Keywords must be text.")
    words = [word.strip() for word in raw.split(",") if word.strip()]
    if len(words) > MAX_KEYWORDS:
        raise ValidationError(f"At most {MAX_KEYWORDS} keywords may be supplied.")
    validated = [validate_keyword(word) for word in words]
    return tuple(dict.fromkeys(validated))


def validate_separator(raw: str) -> str:
    if not isinstance(raw, str):
        raise ValidationError("Custom separators must be text.")
    value = raw.strip()
    if not value:
        raise ValidationError("Custom separators cannot be empty.")
    if len(value) > MAX_SEPARATOR_LENGTH:
        raise ValidationError(
            f"Each custom separator must be at most {MAX_SEPARATOR_LENGTH} characters."
        )
    if any(char.isalnum() or char.isspace() for char in value):
        raise ValidationError(
            "Custom separators must be punctuation and must not contain "
            "letters, digits, or whitespace."
        )
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValidationError("Custom separators contain control characters.")
    return value


def parse_separators(raw: str) -> tuple[str, ...]:
    """Parse comma-separated separators, trimming surrounding whitespace."""
    if raw is None:
        raw = ""
    if not isinstance(raw, str):
        raise ValidationError("Custom separators must be text.")
    separators = [part.strip() for part in raw.split(",") if part.strip()]
    if len(separators) > MAX_SEPARATORS:
        raise ValidationError(f"At most {MAX_SEPARATORS} custom separators may be used.")
    validated = [validate_separator(separator) for separator in separators]
    return tuple(dict.fromkeys(validated))


def _text_variants(value: str) -> set[str]:
    if not value:
        return set()
    normalized = " ".join(value.split())
    compact = "".join(normalized.split())
    variants = {
        normalized,
        normalized.lower(),
        normalized.title(),
        normalized.upper(),
        compact,
        compact.lower(),
        compact.title(),
    }
    return {variant for variant in variants if variant}


def _date_tokens(value: str) -> set[str]:
    if not value:
        return set()
    day, month, year = value[:2], value[2:4], value[4:]
    short_year = year[2:]
    return {
        value,
        f"{day}{month}{short_year}",
        year,
        short_year,
        f"{day}{month}",
        f"{month}{day}",
        f"{year}{month}{day}",
    }


def _year_suffixes(profile: LabProfile) -> set[str]:
    years: set[str] = set()
    for birthdate in (
        profile.birthdate,
        profile.partner_birthdate,
        profile.child_birthdate,
    ):
        if birthdate:
            years.add(birthdate[4:])
            years.add(birthdate[6:])
    if profile.important_year:
        years.add(profile.important_year)
        years.add(profile.important_year[2:])
    return {year for year in years if year}


def _compact_term(value: str) -> str:
    return "".join(value.split()).lower()


def _source_variants(profile: LabProfile) -> set[str]:
    terms: set[str] = set()
    text_values = (
        profile.first_name,
        profile.surname,
        profile.nickname,
        profile.partner_name,
        profile.partner_nickname,
        profile.child_name,
        profile.child_nickname,
        profile.pet_name,
        profile.company_name,
        profile.username,
        profile.city,
        profile.country,
        *profile.keywords,
    )
    for value in text_values:
        terms.update(_text_variants(value))

    if profile.email:
        terms.update(_text_variants(profile.email))
        local_part = profile.email.split("@", 1)[0]
        terms.update(_text_variants(local_part))

    if profile.phone:
        digits = re.sub(r"[^0-9]", "", profile.phone)
        if digits:
            terms.add(digits)
            if len(digits) > 10:
                terms.add(digits[-10:])
            if len(digits) > 7:
                terms.add(digits[-7:])

    for birthdate in (
        profile.birthdate,
        profile.partner_birthdate,
        profile.child_birthdate,
    ):
        terms.update(_date_tokens(birthdate))
    if profile.important_year:
        terms.add(profile.important_year)
        terms.add(profile.important_year[2:])
    return {term for term in terms if term}


def _combination_terms(profile: LabProfile) -> tuple[str, ...]:
    """Return identity terms used for two-part name combinations.

    Dates, phone numbers, e-mail addresses, locations, and keywords are emitted
    as their own candidates and are not crossed with every other value.  This
    bounded combination policy is intentional: blindly taking a Cartesian
    product of all profile values causes enormous intermediate lists without
    producing meaningfully better candidates.
    """
    values: list[str] = []
    for value in (
        profile.first_name,
        profile.surname,
        profile.nickname,
        profile.partner_name,
        profile.partner_nickname,
        profile.child_name,
        profile.child_nickname,
        profile.pet_name,
        profile.company_name,
        profile.username,
    ):
        if value:
            values.append(_compact_term(value))
    return tuple(dict.fromkeys(value for value in values if value))


def _custom_separator_values(
    profile: LabProfile, options: WordlistOptions
) -> tuple[str, ...]:
    if not options.custom_separators:
        return ()
    # No separator values are invented.  The interactive flow asks for values
    # if the user enables this option without having supplied them.
    return profile.custom_separators


def _build_seed_candidates(profile: LabProfile, options: WordlistOptions) -> set[str]:
    candidates = _source_variants(profile)
    separators = ("",) + _custom_separator_values(profile, options)
    combination_terms = _combination_terms(profile)
    for first in combination_terms:
        for second in combination_terms:
            if first == second:
                continue
            for separator in separators:
                combined = f"{first}{separator}{second}"
                if len(combined) > options.max_length:
                    continue
                candidates.add(combined)
                titled = combined.title()
                if titled != combined:
                    candidates.add(titled)
    return candidates


def _apply_suffixes(
    candidates: set[str],
    suffixes: tuple[str, ...],
    *,
    separators: tuple[str, ...] = (),
    maximum_length: int,
) -> set[str]:
    expanded: set[str] = set()
    for candidate in candidates:
        for suffix in suffixes:
            value = f"{candidate}{suffix}"
            if len(value) <= maximum_length:
                expanded.add(value)
            for separator in separators:
                value = f"{candidate}{separator}{suffix}"
                if len(value) <= maximum_length:
                    expanded.add(value)
    return expanded


def filter_candidates(
    candidates: set[str], min_length: int, max_length: int
) -> set[str]:
    """Apply final length filtering and basic line-safety checks."""
    return {
        candidate
        for candidate in candidates
        if min_length <= len(candidate) <= max_length
        and candidate
        and "\n" not in candidate
        and "\r" not in candidate
        and "\x00" not in candidate
    }


def generate_candidates(
    profile: LabProfile, options: WordlistOptions
) -> set[str]:
    """Generate the actual deduplicated candidate set for one profile."""
    if not profile.has_source_data():
        raise EmptyWordlistError(
            "At least one profile field, date, or keyword is required to generate a wordlist."
        )
    seed = _build_seed_candidates(profile, options)
    candidates = set(seed)
    separators = _custom_separator_values(profile, options)
    years = _year_suffixes(profile)

    # Apply optional suffix families independently to the same seed set.  This
    # avoids a cross-product such as every numeric suffix times every special
    # character, which would inflate the intermediate list without adding a
    # meaningfully different candidate family.
    if years:
        candidates |= _apply_suffixes(
            seed,
            tuple(sorted(years)),
            separators=separators,
            maximum_length=options.max_length,
        )
    if options.random_numbers:
        candidates |= _apply_suffixes(
            seed,
            NUMERIC_SUFFIXES,
            maximum_length=options.max_length,
        )
    if options.special_chars:
        candidates |= _apply_suffixes(
            seed,
            SPECIAL_SUFFIXES,
            maximum_length=options.max_length,
        )
    if options.leet_mode:
        leet_variants = {
            translated
            for candidate in candidates
            for translated in (candidate.translate(LEET_TRANSLATION),)
            if translated != candidate
        }
        candidates |= leet_variants
    return filter_candidates(candidates, options.min_length, options.max_length)


def write_wordlist_file(
    candidates: set[str], path: Path, *, overwrite: bool = False
) -> int:
    """Write one candidate per line, verify the file, and return the actual count."""
    if not candidates:
        raise EmptyWordlistError("No candidates matched the requested length range.")
    lines = sorted(candidates, key=lambda item: (item.casefold(), item))
    text = "\n".join(lines) + "\n"
    write_text_atomic(path, text, overwrite=overwrite)
    return verify_wordlist_file(path, expected=candidates)


def verify_wordlist_file(path: Path, *, expected: set[str] | None = None) -> int:
    """Read the saved file and verify one unique nonempty candidate per line."""
    try:
        with path.open("r", encoding="utf-8", newline="") as handle:
            raw = handle.read()
    except (OSError, UnicodeDecodeError) as exc:
        raise ValidationError(f"Could not verify wordlist file: {path}") from exc
    if "\x00" in raw:
        raise ValidationError("Wordlist file contains NUL bytes.")
    if "\r" in raw:
        raise ValidationError("Wordlist file does not use consistent newline characters.")
    lines = raw.splitlines()
    if any(not line for line in lines):
        raise ValidationError("Wordlist file contains an empty line.")
    if len(lines) != len(set(lines)):
        raise ValidationError("Wordlist file contains duplicate candidates.")
    if expected is not None and set(lines) != expected:
        raise ValidationError("Wordlist file contents do not match generated candidates.")
    return len(lines)


def resolve_wordlist_path(output_dir: Path, raw_filename: str) -> Path:
    """Resolve the requested wordlist filename inside ``outputs/``."""
    return prepare_output_path(output_dir, raw_filename, extension=".txt")
