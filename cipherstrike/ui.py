"""Terminal presentation, menus, strict choice validation, and status screens.

Colours are plain ANSI escape sequences so the application has no UI-framework
dependency.  They are disabled automatically for redirected output, dumb
terminals, and ``NO_COLOR``; a readable uncoloured layout remains.  Set
``CIPHERSTRIKE_COLOR=always`` to force colour in a compatible terminal.
"""

from __future__ import annotations

import getpass
import os
import shutil
import sys
from pathlib import Path
from typing import Callable, Iterable, TextIO

from . import APP_NAME, __version__
from .encrypt import EncryptionArtifacts
from .decrypt import DecryptionArtifacts

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RED = "\033[91m"
WHITE = "\033[97m"

FULL_BANNER = r"""
   ██████╗██╗██████╗ ██╗  ██╗███████╗██████╗
  ██╔════╝██║██╔══██╗██║  ██║██╔════╝██╔══██╗
  ██║     ██║██████╔╝███████║█████╗  ██████╔╝
  ██║     ██║██╔═══╝ ██╔══██║██╔══╝  ██╔══██╗
  ╚██████╗██║██║     ██║  ██║███████╗██║  ██║
   ╚═════╝╚═╝╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝

   ███████╗████████╗██████╗ ██╗██╗  ██╗███████╗
   ██╔════╝╚══██╔══╝██╔══██╗██║██║ ██╔╝██╔════╝
   ███████╗   ██║   ██████╔╝██║█████╔╝ █████╗
   ╚════██║   ██║   ██╔══██╗██║██╔═██╗ ██╔══╝
   ███████║   ██║   ██║  ██║██║██║  ██╗███████╗
   ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝
""".strip("\n")

COMPACT_BANNER = r"""
╔══════════════════════════════════════════════╗
║          C I P H E R   S T R I K E           ║
║       SECURE FILE & FOLDER ENCRYPTION        ║
╚══════════════════════════════════════════════╝
""".strip("\n")

MAIN_MENU: tuple[tuple[str, str], ...] = (
    ("1", "ENCRYPT FILES/FOLDER"),
    ("2", "DECRYPT FILES/FOLDER"),
    ("3", "CRACK PASSWORD HASH"),
    ("4", "PASSWORD GENERATOR"),
)

TWO_CHOICE_ERROR = "Invalid selection. Please choose 1 or 2."
MENU_CHOICE_ERROR = "Invalid selection. Please choose 0, 1, or 2."
MAIN_CHOICE_ERROR = "Invalid selection. Please choose a number between 1 and 4."


def _stream_is_tty(stream: TextIO) -> bool:
    try:
        return bool(stream.isatty())
    except (AttributeError, OSError):
        return False


def color_enabled(stream: TextIO) -> bool:
    setting = os.environ.get("CIPHERSTRIKE_COLOR", "").strip().lower()
    if setting == "always":
        return True
    if setting == "never":
        return False
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("TERM", "").lower() == "dumb":
        return False
    return _stream_is_tty(stream)


class UI:
    """Small, testable terminal UI."""

    def __init__(
        self,
        *,
        stream: TextIO | None = None,
        error_stream: TextIO | None = None,
        input_fn: Callable[[str], str] | None = None,
        secret_fn: Callable[[str], str] | None = None,
        force_color: bool | None = None,
    ) -> None:
        self.stream = stream or sys.stdout
        self.error_stream = error_stream or sys.stderr
        self._input = input_fn or input
        self._secret = secret_fn or getpass.getpass
        self.colors = color_enabled(self.stream) if force_color is None else force_color

    # -- low-level output -------------------------------------------------

    def paint(self, text: str, color: str = "", *, bold: bool = False) -> str:
        if not self.colors:
            return text
        prefix = (BOLD if bold else "") + color
        return f"{prefix}{text}{RESET}"

    def write(self, text: str = "", *, end: str = "\n") -> None:
        self.stream.write(f"{text}{end}")
        self.stream.flush()

    def line(self, text: str = "") -> None:
        self.write(text)

    def info(self, text: str) -> None:
        self.write(self.paint(text, CYAN))

    def success(self, text: str) -> None:
        self.write(self.paint(text, GREEN, bold=True))

    def warning(self, text: str) -> None:
        self.write(self.paint(text, YELLOW, bold=True))

    def error(self, text: str) -> None:
        self.write(self.paint(f"[ERROR] {text}", RED, bold=True))

    def dim(self, text: str) -> None:
        self.write(self.paint(text, DIM if self.colors else ""))

    def terminal_width(self) -> int:
        try:
            return shutil.get_terminal_size((100, 24)).columns
        except OSError:
            return 100

    def banner(self) -> None:
        art = COMPACT_BANNER if self.terminal_width() < 60 else FULL_BANNER
        for line in art.splitlines():
            self.write(self.paint(line, GREEN, bold=True))
        self.write(
            self.paint(
                f"{APP_NAME}  //  SECURE FILE & FOLDER ENCRYPTION  //  v{__version__}",
                CYAN,
                bold=True,
            )
        )
        self.write(self.paint("─" * min(self.terminal_width(), 72), GREEN))

    # -- prompts ----------------------------------------------------------

    def ask(self, prompt: str, *, secret: bool = False) -> str:
        # Keep the ANSI colour active while the terminal echoes the user's
        # input, then reset it.  With colours disabled this is plain text.
        if self.colors:
            self.stream.write(f"{BOLD}{CYAN}{prompt}")
        else:
            self.stream.write(prompt)
        self.stream.flush()
        try:
            if secret:
                return self._secret("")
            return self._input("")
        except EOFError as exc:
            raise KeyboardInterrupt from exc
        finally:
            if self.colors:
                self.stream.write(RESET)
                self.stream.flush()

    def choose(
        self,
        valid: Iterable[str],
        *,
        prompt: str = "Select an option:",
        error: str = TWO_CHOICE_ERROR,
    ) -> str:
        accepted = {str(value) for value in valid}
        while True:
            raw = self.ask(prompt)
            value = raw.strip()
            if value in accepted:
                return value
            self.error(error)

    def main_choice(self) -> str:
        return self.choose(
            {"1", "2", "3", "4"},
            prompt="Select an option:",
            error=MAIN_CHOICE_ERROR,
        )

    def binary_choice(self, prompt: str = "Select an option:") -> str:
        return self.choose({"1", "2"}, prompt=prompt, error=TWO_CHOICE_ERROR)

    def navigation_choice(self, prompt: str = "Select an option:") -> str:
        """A 1/2 choice that also accepts 0 for going back."""
        return self.choose({"0", "1", "2"}, prompt=prompt, error=MENU_CHOICE_ERROR)

    def ask_yes_no(self, prompt: str, *, default: bool = False) -> bool:
        """Strict Y/N prompt; Enter selects the documented default."""
        while True:
            answer = self.ask(prompt).strip().lower()
            if answer == "":
                return default
            if answer == "y":
                return True
            if answer == "n":
                return False
            self.error("Invalid selection. Please enter Y, N, or press Enter.")

    def confirm_overwrite(self, path: Path) -> bool:
        self.warning(f"An output already exists: {path}")
        while True:
            raw = self.ask("Overwrite the existing output? [y/N]:").strip().lower()
            if raw in {"y", "yes"}:
                return True
            if raw in {"", "n", "no"}:
                return False
            self.error("Invalid selection. Please choose y or n.")

    def confirm_delete(self, source: Path) -> str:
        self.warning(f"Original source: {source}")
        self.warning(
            "Deleting a source is irreversible. Read the warning above before continuing."
        )
        self.info(
            "Type DELETE (uppercase) to remove the original, or press Enter to keep it."
        )
        return self.ask("Confirmation:").strip()

    # -- screens ----------------------------------------------------------

    def main_menu(self) -> None:
        self.banner()
        self.info("SECURE FILE & FOLDER ENCRYPTION")
        self.write()
        for number, label in MAIN_MENU:
            self.write(self.paint(f"[{number}] {label}", YELLOW, bold=True))
        self.write()
        self.dim("Press Ctrl+C to exit.")
        self.write()

    def encrypt_menu(self) -> None:
        self.banner()
        self.success("WELCOME TO ENCRYPT FILES")
        self.write()
        self.write(self.paint("[1] ENCRYPT FILE", YELLOW, bold=True))
        self.write(self.paint("[2] ENCRYPT FOLDER", YELLOW, bold=True))
        self.write(self.paint("[0] BACK TO MAIN MENU", YELLOW, bold=True))
        self.write()

    def decrypt_menu(self) -> None:
        self.banner()
        self.success("WELCOME TO DECRYPT FILES")
        self.write()
        self.write(self.paint("[1] DECRYPT FILE", YELLOW, bold=True))
        self.write(self.paint("[2] DECRYPT FOLDER", YELLOW, bold=True))
        self.write(self.paint("[0] BACK TO MAIN MENU", YELLOW, bold=True))
        self.write()

    def recovery_menu(self) -> None:
        self.banner()
        self.write()
        self.write(self.paint("[1] DECRYPT WITH PASSWORD", YELLOW, bold=True))
        self.write(self.paint("[2] DECRYPT WITH RECOVERY KEY", YELLOW, bold=True))
        self.write(self.paint("[0] BACK TO DECRYPTION MENU", YELLOW, bold=True))
        self.write()

    def hash_menu(
        self,
        title: str,
        options: Iterable[tuple[str, str]],
        *,
        back_label: str = "Back",
    ) -> None:
        self.banner()
        self.success(title)
        self.write()
        for number, label in options:
            self.write(self.paint(f"[{number}] {label}", YELLOW, bold=True))
        self.write(self.paint(f"[0] {back_label}", YELLOW, bold=True))
        self.write()

    def hash_recovery_menu(self) -> None:
        self.hash_menu(
            "CRACK PASSWORD HASH",
            (
                ("1", "Raw Hashes"),
                ("2", "Password Storage"),
                ("3", "Windows Authentication"),
                ("4", "Application Hashes"),
                ("5", "Auto Detect Hash Type"),
            ),
        )

    def select_hash_option(self, maximum: int, *, prompt: str = "SELECT:") -> str:
        if maximum < 0:
            raise ValueError("maximum must be non-negative")
        return self.choose(
            {str(number) for number in range(0, maximum + 1)},
            prompt=prompt,
            error=f"Invalid selection. Please choose 0-{maximum}.",
        )

    def show_hash_selected(self, label: str) -> None:
        self.banner()
        self.write(self.paint(f"Selected hash type: {label}", GREEN, bold=True))
        self.write()

    def show_hash_error(self, lines: Iterable[str]) -> None:
        self.banner()
        for line in lines:
            self.write(self.paint(line, RED, bold=True))
        self.write()

    def show_hashcat_missing(self) -> None:
        self.show_hash_error(
            (
                "[!] ERROR: Hashcat was not found.",
                "[!] Install Hashcat from https://hashcat.net/hashcat/",
            )
        )

    def show_invalid_hash(self, detail: str | None = None) -> None:
        lines = [
            "[!] ERROR: Invalid or unsupported hash format.",
            "[!] Please verify the selected hash type and input file.",
        ]
        if detail:
            lines.append(f"[!] {detail}")
        self.show_hash_error(lines)

    def show_hash_results(
        self,
        *,
        findings: list[tuple[str, str]],
        total: int,
        unresolved: int,
        cancelled: bool = False,
    ) -> None:
        self.banner()
        if findings:
            for hash_value, password in findings:
                self.success(f"[+] PASSWORD FOUND: {password}")
                self.write(f"Hash: {hash_value}")
                self.write()
        if cancelled:
            self.warning("[!] RECOVERY CANCELLED")
            self.write("No definitive no-match result is reported for an interrupted search.")
        elif not findings:
            self.write(self.paint("[-] PASSWORD NOT FOUND", RED, bold=True))
            self.write("[-] No password in the supplied wordlist matched the hash.")
        if total > 1 or findings:
            self.write()
            self.write(f"Recovered: {len(findings)} of {total}")
            self.write(f"Unresolved: {unresolved}")
        self.write()

    def password_generator_menu(self) -> None:
        self.banner()
        self.success("WELCOME TO PASSWORD GENERATOR")
        self.write()
        self.write(self.paint("[1] GENERATE STRONG PASSWORD", YELLOW, bold=True))
        self.write(self.paint("[2] GENERATE TARGET WORDLIST", YELLOW, bold=True))
        self.write(self.paint("[0] BACK TO MAIN MENU", YELLOW, bold=True))
        self.write()

    def show_generated_password(self, password: str, *, length: int, categories: str) -> None:
        self.banner()
        self.success("STRONG PASSWORD GENERATED SUCCESSFULLY")
        self.write(self.paint(f"Generated Password: {password}", WHITE, bold=True))
        self.write(f"Length: {length}")
        self.write(f"Character categories: {categories}")
        self.write()

    def show_password_saved(self, path: Path) -> None:
        self.success("PASSWORD SAVED SUCCESSFULLY")
        self.write(self.paint(f"Output File: {path}", CYAN, bold=True))
        self.write()

    def show_wordlist_success(self, path: Path, count: int) -> None:
        self.banner()
        self.success("[+] WORDLIST GENERATED SUCCESSFULLY")
        self.write(self.paint(f"[+] OUTPUT FILE: {path}", GREEN, bold=True))
        self.write(self.paint(f"[+] UNIQUE CANDIDATES WRITTEN: {count}", GREEN, bold=True))
        self.write(self.paint("[+] FORMAT: ONE CANDIDATE PER LINE", GREEN, bold=True))
        self.write()

    def show_empty_wordlist(self) -> None:
        self.banner()
        self.warning("NO CANDIDATES MATCHED THE REQUESTED LENGTH RANGE.")
        self.write("No wordlist file was written. Adjust the profile, transformations, or length range.")
        self.write()

    def show_encryption_success(self, artifacts: EncryptionArtifacts) -> None:
        self.banner()
        self.success("ENCRYPTION COMPLETED SUCCESSFULLY")
        self.write(
            self.paint(f"Generated Password: {artifacts.password}", WHITE, bold=True)
        )
        self.write()
        self.write(self.paint("IMPORTANT: SAVE YOUR RECOVERY INFORMATION!", RED, bold=True))
        self.write("• Your generated password is displayed above.")
        self.write(
            "• Your password is also saved in the password text file inside the "
            "outputs directory."
        )
        self.write("• Your Recovery Key file is saved in the outputs directory.")
        self.write("• Store both securely and keep backup copies in separate, safe locations.")
        self.write("• Anyone who obtains your Recovery Key may be able to decrypt your data.")
        self.write(
            "• If you lose both the password and the Recovery Key, your encrypted data "
            "cannot be recovered."
        )
        self.write()
        self.write(
            self.paint(
                "WARNING: Original files will be deleted only after successful "
                "encryption, verification, and your explicit confirmation.",
                RED,
                bold=True,
            )
        )
        self.write()
        self.write(self.paint(f"Encrypted Output: {artifacts.container}", CYAN))
        self.write(self.paint(f"Password File:    {artifacts.password_file}", CYAN))
        self.write(self.paint(f"Recovery Key:     {artifacts.recovery_file}", CYAN))
        self.write()

    def show_decryption_success(self, artifacts: DecryptionArtifacts) -> None:
        self.banner()
        self.success("DECRYPTION COMPLETED SUCCESSFULLY")
        self.write(self.paint(f"Restored Output: {artifacts.output}", CYAN, bold=True))
        self.write(f"Container type:  {artifacts.kind}")
        self.write(f"Recovery method: {artifacts.method}")
        self.write(f"Encrypted input preserved: {artifacts.container}")
        for warning in artifacts.warnings:
            self.warning(f"WARNING: {warning}")
        self.write()

    def unavailable(self) -> None:
        self.warning("This feature is not available in the current release.")
        self.write()
