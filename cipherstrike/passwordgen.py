"""Cryptographically strong password generation for CIPHER STRIKE.

This module is independent of the profile-based wordlist generator.  It uses
the standard-library ``secrets`` module exclusively and never falls back to
``random``.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
from pathlib import Path

from .output import prepare_output_path, verify_text_file, write_text_atomic
from .utils import CipherStrikeError, ValidationError

UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
LOWERCASE = "abcdefghijklmnopqrstuvwxyz"
DIGITS = "0123456789"
SPECIALS = "!@#$%^&*()-_=+[]{};:,.?"
MAX_PASSWORD_LENGTH = 64
MIN_PASSWORD_LENGTH = 1
ASCII_DIGITS_RE = re.compile(r"^[0-9]+$")


class PasswordGenerationError(CipherStrikeError):
    """Password generation or verification failed."""


@dataclass(frozen=True)
class PasswordOptions:
    """Requested length and enabled character categories."""

    length: int
    uppercase: bool = False
    lowercase: bool = False
    numbers: bool = False
    specials: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.length, int) or not (
            MIN_PASSWORD_LENGTH <= self.length <= MAX_PASSWORD_LENGTH
        ):
            raise ValidationError(
                f"Password length must be an integer between {MIN_PASSWORD_LENGTH} "
                f"and {MAX_PASSWORD_LENGTH}."
            )
        if not any((self.uppercase, self.lowercase, self.numbers, self.specials)):
            raise ValidationError("At least one character category must be selected.")

    @property
    def categories(self) -> tuple[str, ...]:
        labels: list[str] = []
        if self.uppercase:
            labels.append("uppercase")
        if self.lowercase:
            labels.append("lowercase")
        if self.numbers:
            labels.append("numbers")
        if self.specials:
            labels.append("special characters")
        return tuple(labels)

    def enabled_sets(self) -> list[str]:
        groups: list[str] = []
        if self.uppercase:
            groups.append(UPPERCASE)
        if self.lowercase:
            groups.append(LOWERCASE)
        if self.numbers:
            groups.append(DIGITS)
        if self.specials:
            groups.append(SPECIALS)
        return groups


def parse_password_length(raw: str) -> int:
    """Validate the interactive length answer."""
    if not isinstance(raw, str):
        raise ValidationError(
            f"Password length must be an integer between {MIN_PASSWORD_LENGTH} "
            f"and {MAX_PASSWORD_LENGTH}."
        )
    value = raw.strip()
    if not value or not ASCII_DIGITS_RE.fullmatch(value):
        raise ValidationError(
            f"Password length must be an integer between {MIN_PASSWORD_LENGTH} "
            f"and {MAX_PASSWORD_LENGTH}."
        )
    length = int(value, 10)
    if not MIN_PASSWORD_LENGTH <= length <= MAX_PASSWORD_LENGTH:
        raise ValidationError(
            f"Password length must be an integer between {MIN_PASSWORD_LENGTH} "
            f"and {MAX_PASSWORD_LENGTH}."
        )
    return length


def generate_strong_password(options: PasswordOptions) -> str:
    """Generate exactly ``options.length`` characters from enabled categories.

    If the requested length is at least the number of enabled categories, at
    least one character from every enabled category is guaranteed.
    """
    groups = options.enabled_sets()
    if not groups:
        raise PasswordGenerationError("No character categories were selected.")
    length = options.length
    pool = "".join(groups)
    characters: list[str] = []

    if length >= len(groups):
        characters.extend(secrets.choice(group) for group in groups)
    while len(characters) < length:
        characters.append(secrets.choice(pool))

    secrets.SystemRandom().shuffle(characters)
    password = "".join(characters)

    if len(password) != length:
        raise PasswordGenerationError("Generated password length did not match the request.")
    if length >= len(groups):
        for group in groups:
            if not any(char in group for char in password):
                raise PasswordGenerationError(
                    "Generated password failed its character-category checks."
                )
    return password


def password_file_text(password: str, options: PasswordOptions) -> str:
    """Create the human-readable private password text file."""
    categories = ", ".join(options.categories)
    return (
        "CIPHER STRIKE - GENERATED STRONG PASSWORD\n"
        "=========================================\n"
        f"Generated Password: {password}\n"
        f"Length: {options.length}\n"
        f"Character categories: {categories}\n"
        "\n"
        "WARNING:\n"
        "- This file contains a plaintext password.\n"
        "- Store it securely and do not share it unnecessarily.\n"
        "- CIPHER STRIKE cannot recover this password if it is lost.\n"
    )


def save_password_file(
    password: str,
    options: PasswordOptions,
    *,
    output_dir: Path,
    filename: str,
    overwrite: bool = False,
) -> Path:
    """Write and verify a password text file inside ``outputs/``."""
    if not password:
        raise PasswordGenerationError("Cannot save an empty password.")
    path = prepare_output_path(output_dir, filename, extension=".txt")
    text = password_file_text(password, options)
    write_text_atomic(path, text, overwrite=overwrite)
    verified = verify_text_file(path, expected_text=text)
    if f"Generated Password: {password}" not in verified:
        raise PasswordGenerationError(
            f"Password file verification failed; no success was reported: {path}"
        )
    return path
