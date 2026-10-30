#!/usr/bin/env python3
"""CIPHER STRIKE - terminal encryption and password toolkit.

Run with:  python cipherstrike.py (Windows) or python3 cipherstrike.py (Linux).

Menu options 1 and 2 provide file/folder encryption and decryption.  Option 3
provides authorized offline password-hash recovery through the official
Hashcat executable.  Option 4 provides the independent strong password
generator and synthetic-lab-profile wordlist generator.
"""

from __future__ import annotations

import sys
from dataclasses import replace
from pathlib import Path

from cipherstrike.crypto import (
    AuthenticationError,
    CryptoError,
    KdfParams,
    RecoveryKey,
    read_container_hint,
)
from cipherstrike.decrypt import decrypt_file_container, decrypt_folder_container
from cipherstrike.encrypt import (
    EncryptionArtifacts,
    delete_source_after_confirmation,
    encrypt_file,
    encrypt_folder,
)
from cipherstrike.hashcli import hash_recovery_screen
from cipherstrike.output import prepare_output_path
from cipherstrike.passwordgen import (
    PasswordOptions,
    generate_strong_password,
    parse_password_length,
    save_password_file,
)
from cipherstrike.ui import UI
from cipherstrike.utils import (
    CipherStrikeError,
    OperationCancelled,
    default_outputs_dir,
    validate_encrypted_container,
    validate_recovery_file_path,
    validate_source_directory,
    validate_source_file,
)
from cipherstrike.wordlist import (
    EmptyWordlistError,
    LabProfile,
    WordlistOptions,
    generate_candidates,
    parse_keywords,
    parse_output_length,
    parse_separators,
    resolve_wordlist_path,
    validate_birthdate,
    validate_email,
    validate_important_year,
    validate_phone,
    validate_text_field,
    validate_username,
    write_wordlist_file,
)

EXIT_INTERRUPTED = 130


def _configure_terminal_encoding() -> None:
    """Prefer UTF-8 for the banner while keeping redirected output robust."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (OSError, ValueError):
            pass


# ---------------------------------------------------------------------------
# Path and recovery prompts (0 returns to the parent menu)
# ---------------------------------------------------------------------------


def _prompt_source_file(ui: UI) -> Path | None:
    while True:
        raw = ui.ask("FILE PATH:")
        if raw.strip() == "0":
            return None
        try:
            return validate_source_file(raw)
        except CipherStrikeError as exc:
            ui.error(str(exc))


def _prompt_source_folder(ui: UI) -> Path | None:
    while True:
        raw = ui.ask("FOLDER PATH:")
        if raw.strip() == "0":
            return None
        try:
            return validate_source_directory(raw)
        except CipherStrikeError as exc:
            ui.error(str(exc))


def _prompt_container(ui: UI, *, folder: bool) -> Path | None:
    label = "ENCRYPTED FOLDER CONTAINER PATH:" if folder else "ENCRYPTED FILE PATH:"
    while True:
        raw = ui.ask(label)
        if raw.strip() == "0":
            return None
        try:
            return validate_encrypted_container(raw)
        except CipherStrikeError as exc:
            ui.error(str(exc))


def _prompt_recovery_key(ui: UI) -> RecoveryKey | None:
    while True:
        raw = ui.ask("RECOVERY KEY FILE PATH:")
        if raw.strip() == "0":
            return None
        try:
            path = validate_recovery_file_path(raw)
            return RecoveryKey.load(path)
        except CipherStrikeError as exc:
            ui.error(str(exc))


# ---------------------------------------------------------------------------
# Existing encryption / decryption flows
# ---------------------------------------------------------------------------


def _handle_encryption_result(ui: UI, artifacts: EncryptionArtifacts) -> None:
    ui.show_encryption_success(artifacts)
    confirmation = ui.confirm_delete(artifacts.source)
    if confirmation != "DELETE":
        ui.info(
            "Original source preserved. The verified encrypted outputs remain in "
            "the outputs directory."
        )
        return
    try:
        deleted = delete_source_after_confirmation(
            artifacts.source, artifacts.source_snapshot, confirmation
        )
    except CipherStrikeError as exc:
        ui.error(f"Source deletion failed. The original source was preserved: {exc}")
        return
    if deleted:
        ui.success("Original source deleted after successful verification.")
        ui.warning(
            "Ordinary deletion does not guarantee physical erasure on SSDs, "
            "journaled filesystems, snapshots, or backups."
        )


def encryption_screen(ui: UI) -> None:
    while True:
        ui.encrypt_menu()
        choice = ui.navigation_choice()
        if choice == "0":
            return
        ui.dim("Enter 0 at the path prompt to return to this menu.")
        source = _prompt_source_file(ui) if choice == "1" else _prompt_source_folder(ui)
        if source is None:
            continue
        try:
            if choice == "1":
                ui.info("Encrypting, authenticating, and verifying the container...")
                artifacts = encrypt_file(
                    source, default_outputs_dir(), params=KdfParams()
                )
            else:
                ui.info(
                    "Encrypting, authenticating, and verifying the folder container..."
                )
                artifacts = encrypt_folder(
                    source, default_outputs_dir(), params=KdfParams()
                )
        except CipherStrikeError as exc:
            ui.error(str(exc))
            return
        except OSError as exc:
            ui.error(f"Filesystem operation failed: {exc.strerror or exc}")
            return
        except Exception as exc:  # keep the interactive application from crashing
            ui.error(f"Unexpected encryption failure: {exc}")
            return
        _handle_encryption_result(ui, artifacts)
        return


def _decrypt_with_chosen_method(
    ui: UI, container: Path, *, folder: bool
) -> bool:
    """Run one decryption attempt; return False only when the user goes back."""
    password: str | None = None
    key: RecoveryKey | None = None
    while True:
        ui.recovery_menu()
        method = ui.navigation_choice(prompt="Select a recovery method:")
        if method == "0":
            return False
        if method == "1":
            entered = ui.ask("Password:", secret=True)
            if not entered:
                ui.error("Password cannot be empty.")
                continue
            password = entered
            break
        ui.dim("Enter 0 at the recovery-key prompt to return to this menu.")
        selected_key = _prompt_recovery_key(ui)
        if selected_key is None:
            continue
        key = selected_key
        break

    try:
        if folder:
            artifacts = decrypt_folder_container(
                container,
                default_outputs_dir(),
                password=password,
                recovery_key=key,
                confirm_overwrite=ui.confirm_overwrite,
            )
        else:
            artifacts = decrypt_file_container(
                container,
                default_outputs_dir(),
                password=password,
                recovery_key=key,
                confirm_overwrite=ui.confirm_overwrite,
            )
    except OperationCancelled as exc:
        ui.warning(str(exc))
        return True
    except AuthenticationError:
        ui.error(
            "Decryption failed. The password may be incorrect, or the encrypted "
            "data may be corrupted or modified."
        )
        return True
    except (CryptoError, CipherStrikeError) as exc:
        ui.error(f"Decryption failed: {exc}")
        return True
    except OSError as exc:
        ui.error(f"Filesystem operation failed: {exc.strerror or exc}")
        return True
    except Exception as exc:
        ui.error(f"Unexpected decryption failure: {exc}")
        return True
    ui.show_decryption_success(artifacts)
    return True


def decryption_screen(ui: UI) -> None:
    while True:
        ui.decrypt_menu()
        choice = ui.navigation_choice()
        if choice == "0":
            return
        folder = choice == "2"
        ui.dim("Enter 0 at the container path prompt to return to this menu.")
        container = _prompt_container(ui, folder=folder)
        if container is None:
            continue
        try:
            hint = read_container_hint(container)
        except CipherStrikeError as exc:
            ui.error(f"Invalid encrypted container: {exc}")
            continue
        if folder and hint.kind != "folder":
            ui.error(
                "The selected container is a file container. Choose DECRYPT FILE instead."
            )
            continue
        if not folder and hint.kind != "file":
            ui.error(
                "The selected container is a folder container. Choose DECRYPT FOLDER instead."
            )
            continue
        if _decrypt_with_chosen_method(ui, container, folder=folder):
            return


# ---------------------------------------------------------------------------
# Strong password flow
# ---------------------------------------------------------------------------


def _prompt_password_length(ui: UI) -> int:
    while True:
        raw = ui.ask("HOW MANY CHARACTERS IN PASSWORD YOU WANT? (MAX. 64):")
        try:
            return parse_password_length(raw)
        except CipherStrikeError as exc:
            ui.error(str(exc))


def _prompt_password_options(ui: UI) -> PasswordOptions:
    length = _prompt_password_length(ui)
    while True:
        uppercase = ui.ask_yes_no("INCLUDE UPPERCASE LETTERS? (Y/N):", default=False)
        lowercase = ui.ask_yes_no("INCLUDE LOWERCASE LETTERS? (Y/N):", default=False)
        numbers = ui.ask_yes_no("INCLUDE NUMBERS? (Y/N):", default=False)
        specials = ui.ask_yes_no("INCLUDE SPECIAL CHARACTERS? (Y/N):", default=False)
        try:
            return PasswordOptions(
                length=length,
                uppercase=uppercase,
                lowercase=lowercase,
                numbers=numbers,
                specials=specials,
            )
        except CipherStrikeError as exc:
            ui.error(str(exc))


def _prompt_save_name_password(ui: UI) -> str | None:
    ui.dim("Files are saved inside outputs/. Press Enter to cancel saving.")
    while True:
        raw = ui.ask("FILE NAME:")
        if not raw.strip():
            return None
        try:
            prepare_output_path(default_outputs_dir(), raw, extension=".txt")
            return raw
        except CipherStrikeError as exc:
            ui.error(str(exc))


def strong_password_flow(ui: UI) -> None:
    ui.banner()
    ui.success("GENERATE STRONG PASSWORD")
    ui.write()
    options = _prompt_password_options(ui)
    try:
        password = generate_strong_password(options)
    except CipherStrikeError as exc:
        ui.error(f"Password generation failed: {exc}")
        return

    ui.show_generated_password(
        password,
        length=options.length,
        categories=", ".join(options.categories),
    )
    if not ui.ask_yes_no("SAVE PASSWORD TO TXT FILE? (Y/N):", default=False):
        ui.info("Password was generated but not saved.")
        return

    filename = _prompt_save_name_password(ui)
    if filename is None:
        ui.info("Password was generated but not saved.")
        return
    try:
        path = prepare_output_path(default_outputs_dir(), filename, extension=".txt")
    except CipherStrikeError as exc:
        ui.error(f"Could not prepare password file: {exc}")
        return
    overwrite = False
    if path.exists() or path.is_symlink():
        if not ui.confirm_overwrite(path):
            ui.warning("Existing file preserved. Password was not saved.")
            return
        overwrite = True
    try:
        saved_path = save_password_file(
            password,
            options,
            output_dir=default_outputs_dir(),
            filename=filename,
            overwrite=overwrite,
        )
    except CipherStrikeError as exc:
        ui.error(f"Could not save password: {exc}")
        return
    except OSError as exc:
        ui.error(f"Could not save password: {exc.strerror or exc}")
        return
    ui.show_password_saved(saved_path)


# ---------------------------------------------------------------------------
# Target-wordlist flow
# ---------------------------------------------------------------------------


def _prompt_profile_text(ui: UI, prompt: str, label: str) -> str:
    while True:
        raw = ui.ask(prompt)
        try:
            return validate_text_field(raw, field_label=label, allow_blank=True)
        except CipherStrikeError as exc:
            ui.error(str(exc))


def _prompt_birthdate(ui: UI, prompt: str, label: str) -> str:
    while True:
        raw = ui.ask(prompt)
        try:
            return validate_birthdate(raw, label)
        except CipherStrikeError as exc:
            ui.error(str(exc))


def _prompt_keywords(ui: UI) -> tuple[str, ...]:
    while True:
        raw = ui.ask("KEYWORDS (COMMA-SEPARATED):")
        try:
            keywords = parse_keywords(raw)
        except CipherStrikeError as exc:
            ui.error(str(exc))
            continue
        if not keywords:
            ui.error("At least one keyword is required when Add Keywords? is Y.")
            continue
        return keywords


def _prompt_phone(ui: UI) -> str:
    while True:
        try:
            return validate_phone(ui.ask("LAB PROFILE PHONE NUMBER:"))
        except CipherStrikeError as exc:
            ui.error(str(exc))


def _prompt_email(ui: UI) -> str:
    while True:
        try:
            return validate_email(ui.ask("LAB PROFILE EMAIL ADDRESS:"))
        except CipherStrikeError as exc:
            ui.error(str(exc))


def _prompt_username(ui: UI) -> str:
    while True:
        try:
            return validate_username(ui.ask("LAB PROFILE USERNAME:"))
        except CipherStrikeError as exc:
            ui.error(str(exc))


def _prompt_important_year(ui: UI) -> str:
    while True:
        try:
            return validate_important_year(ui.ask("IMPORTANT YEAR:"))
        except CipherStrikeError as exc:
            ui.error(str(exc))


def _prompt_separators(ui: UI) -> tuple[str, ...]:
    while True:
        try:
            return parse_separators(ui.ask("CUSTOM SEPARATORS:"))
        except CipherStrikeError as exc:
            ui.error(str(exc))


def _prompt_required_separators(ui: UI) -> tuple[str, ...]:
    ui.warning(
        "Custom separators were enabled, but the profile supplied none. "
        "Enter at least one separator or press Ctrl+C to cancel."
    )
    while True:
        try:
            separators = parse_separators(ui.ask("CUSTOM SEPARATORS:"))
        except CipherStrikeError as exc:
            ui.error(str(exc))
            continue
        if separators:
            return separators
        ui.error("At least one custom separator is required for this option.")


def _collect_lab_profile(ui: UI) -> LabProfile:
    first_name = _prompt_profile_text(ui, "FIRST NAME:", "first name")
    surname = _prompt_profile_text(ui, "SURNAME:", "surname")
    nickname = _prompt_profile_text(ui, "NICKNAME:", "nickname")
    birthdate = _prompt_birthdate(ui, "BIRTHDATE (DDMMYYYY):", "birthdate")
    partner_name = _prompt_profile_text(ui, "PARTNER'S NAME:", "partner's name")
    partner_nickname = _prompt_profile_text(
        ui, "PARTNER'S NICKNAME:", "partner's nickname"
    )
    partner_birthdate = _prompt_birthdate(
        ui, "PARTNER'S BIRTHDATE (DDMMYYYY):", "partner's birthdate"
    )
    child_name = _prompt_profile_text(ui, "CHILD'S NAME:", "child's name")
    child_nickname = _prompt_profile_text(
        ui, "CHILD'S NICKNAME:", "child's nickname"
    )
    child_birthdate = _prompt_birthdate(
        ui, "CHILD'S BIRTHDATE (DDMMYYYY):", "child's birthdate"
    )
    pet_name = _prompt_profile_text(ui, "PET'S NAME:", "pet's name")
    company_name = _prompt_profile_text(ui, "COMPANY NAME:", "company name")

    add_keywords = ui.ask_yes_no("ADD KEYWORDS? (Y/N):", default=False)
    keywords = _prompt_keywords(ui) if add_keywords else ()

    phone = _prompt_phone(ui)
    email = _prompt_email(ui)
    username = _prompt_username(ui)
    city = _prompt_profile_text(ui, "LAB PROFILE CITY:", "city")
    country = _prompt_profile_text(ui, "LAB PROFILE COUNTRY:", "country")
    important_year = _prompt_important_year(ui)
    custom_separators = _prompt_separators(ui)

    return LabProfile(
        first_name=first_name,
        surname=surname,
        nickname=nickname,
        birthdate=birthdate,
        partner_name=partner_name,
        partner_nickname=partner_nickname,
        partner_birthdate=partner_birthdate,
        child_name=child_name,
        child_nickname=child_nickname,
        child_birthdate=child_birthdate,
        pet_name=pet_name,
        company_name=company_name,
        keywords=keywords,
        phone=phone,
        email=email,
        username=username,
        city=city,
        country=country,
        important_year=important_year,
        custom_separators=custom_separators,
    )


def _prompt_wordlist_options(ui: UI) -> WordlistOptions:
    special_chars = ui.ask_yes_no("SPECIAL CHARACTERS? (Y/N):", default=False)
    random_numbers = ui.ask_yes_no("RANDOM NUMBERS? (Y/N):", default=False)
    leet_mode = ui.ask_yes_no("LEET MODE? (Y/N):", default=False)
    custom_separators = ui.ask_yes_no(
        "INCLUDE CUSTOM SEPARATORS? (Y/N):", default=False
    )
    while True:
        min_raw = ui.ask("MINIMUM OUTPUT LENGTH:")
        max_raw = ui.ask("MAXIMUM OUTPUT LENGTH:")
        try:
            min_length = parse_output_length(min_raw, label="Minimum output length")
            max_length = parse_output_length(max_raw, label="Maximum output length")
            return WordlistOptions(
                special_chars=special_chars,
                random_numbers=random_numbers,
                leet_mode=leet_mode,
                custom_separators=custom_separators,
                min_length=min_length,
                max_length=max_length,
            )
        except CipherStrikeError as exc:
            ui.error(str(exc))


def _prompt_wordlist_filename(ui: UI) -> tuple[Path, bool]:
    ui.dim("Wordlist files are saved inside outputs/.")
    while True:
        raw = ui.ask("OUTPUT FILE NAME:")
        try:
            path = resolve_wordlist_path(default_outputs_dir(), raw)
        except CipherStrikeError as exc:
            ui.error(str(exc))
            continue
        if path.is_dir():
            ui.error("The requested output path is a directory; choose a file name.")
            continue
        overwrite = False
        if path.exists() or path.is_symlink():
            if not ui.confirm_overwrite(path):
                ui.warning("Existing file preserved. Choose another output file name.")
                continue
            overwrite = True
        return path, overwrite


def target_wordlist_flow(ui: UI) -> None:
    ui.banner()
    ui.success("GENERATE TARGET WORDLIST")
    ui.info(
        "Use only synthetic lab-profile data, owned test accounts, and approved datasets."
    )
    ui.write()
    try:
        profile = _collect_lab_profile(ui)
    except CipherStrikeError as exc:
        ui.error(f"Profile validation failed: {exc}")
        return
    if not profile.has_source_data():
        ui.error(
            "At least one profile field, date, or keyword is required. "
            "No values were invented."
        )
        return
    options = _prompt_wordlist_options(ui)
    if options.custom_separators and not profile.custom_separators:
        profile = replace(
            profile, custom_separators=_prompt_required_separators(ui)
        )
    output_path, overwrite = _prompt_wordlist_filename(ui)

    try:
        ui.info("Generating candidates from the supplied profile data...")
        candidates = generate_candidates(profile, options)
    except EmptyWordlistError as exc:
        ui.error(str(exc))
        return
    except CipherStrikeError as exc:
        ui.error(f"Wordlist generation failed: {exc}")
        return
    except Exception as exc:
        ui.error(f"Unexpected wordlist generation failure: {exc}")
        return

    if not candidates:
        ui.show_empty_wordlist()
        return

    ui.info("Writing and verifying the wordlist file...")
    try:
        verified_count = write_wordlist_file(
            candidates, output_path, overwrite=overwrite
        )
    except CipherStrikeError as exc:
        ui.error(f"Could not write wordlist: {exc}")
        return
    except OSError as exc:
        ui.error(f"Could not write wordlist: {exc.strerror or exc}")
        return
    ui.show_wordlist_success(output_path, verified_count)


# ---------------------------------------------------------------------------
# Main menu
# ---------------------------------------------------------------------------


def password_generator_screen(ui: UI) -> None:
    while True:
        ui.password_generator_menu()
        choice = ui.navigation_choice(prompt="SELECT OPTION:")
        if choice == "0":
            return
        if choice == "1":
            strong_password_flow(ui)
        else:
            target_wordlist_flow(ui)


def main(argv: list[str] | None = None) -> int:
    """Application entry point.  Returns a process exit status."""
    _ = argv
    _configure_terminal_encoding()
    ui = UI()
    try:
        while True:
            ui.main_menu()
            choice = ui.main_choice()
            if choice == "1":
                encryption_screen(ui)
            elif choice == "2":
                decryption_screen(ui)
            elif choice == "3":
                hash_recovery_screen(ui)
            elif choice == "4":
                password_generator_screen(ui)
    except KeyboardInterrupt:
        ui.write()
        ui.warning("Interrupted. Exiting CIPHER STRIKE.")
        return EXIT_INTERRUPTED
    except Exception as exc:
        ui.error(f"Unexpected application error: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
