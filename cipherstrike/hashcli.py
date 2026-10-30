"""Interactive password-hash recovery screens backed by Hashcat."""

from __future__ import annotations

from pathlib import Path

from .hashcat import (
    AttemptResult,
    HashcatBackendError,
    HashcatCancelled,
    HashcatEngine,
    HashcatError,
    HashcatNotFoundError,
    HashcatOutputError,
    HashcatStartupError,
    UnsupportedHashModeError,
)
from .hashcat_modes import (
    EmptyHashFileError,
    EmptyWordlistError,
    HashFileNotFoundError,
    HashInputError,
    HashType,
    InvalidHashFormatError,
    MixedHashTypesError,
    UnsupportedHashDetectionError,
    WordlistNotFoundError,
    detect_hash_file,
    get_hash_type,
    menu_applications,
    menu_password_storage,
    menu_raw,
    menu_windows,
    validate_hash_file,
    validate_wordlist,
)
from .ui import UI

HASH_MISSING = (
    "[!] ERROR: Hash file not found.",
    "[!] Please check the file path and try again.",
)
WORDLIST_MISSING = (
    "[!] ERROR: Wordlist file not found.",
    "[!] Please enter a valid wordlist path.",
)
HASH_EMPTY = (
    "[!] ERROR: Hash file is empty.",
    "[!] Please provide a hash file containing at least one hash.",
)
WORDLIST_EMPTY = (
    "[!] ERROR: Wordlist file is empty.",
    "[!] Please provide a nonempty wordlist.",
)


def _choose_type(
    ui: UI, title: str, keys: tuple[str, ...], *, prompt: str = "SELECT:"
) -> HashType | None:
    specs = [get_hash_type(key) for key in keys]
    ui.hash_menu(title, [(str(index), spec.label) for index, spec in enumerate(specs, 1)])
    choice = ui.select_hash_option(len(specs), prompt=prompt)
    if choice == "0":
        return None
    return specs[int(choice, 10) - 1]


def _prepare_engine(ui: UI, spec: HashType) -> HashcatEngine | None:
    ui.info("[*] Checking Hashcat availability...")
    try:
        engine = HashcatEngine.discover()
        ui.info(f"[*] Hashcat version: {engine.version}")
        engine.check_ready(spec)
        return engine
    except HashcatNotFoundError:
        ui.show_hashcat_missing()
        return None
    except UnsupportedHashModeError as exc:
        ui.show_hash_error(
            (
                "[!] ERROR: The installed Hashcat version does not support this mode.",
                f"[!] {exc}",
            )
        )
        return None
    except HashcatBackendError as exc:
        ui.show_hash_error(
            (
                "[!] ERROR: Hashcat could not initialize a supported device/backend.",
                f"[!] {exc}",
            )
        )
        return None
    except HashcatStartupError as exc:
        ui.show_hash_error(
            (
                "[!] ERROR: Hashcat startup failed.",
                f"[!] {exc}",
            )
        )
        return None
    except HashcatError as exc:
        ui.show_hash_error(("[!] ERROR: Hashcat is not ready.", f"[!] {exc}"))
        return None


def _check_path(path: Path, *, hash_file: bool) -> tuple[bool, tuple[str, ...] | None]:
    label = "Hash" if hash_file else "Wordlist"
    missing = HASH_MISSING if hash_file else WORDLIST_MISSING
    if not path.exists():
        return False, missing
    if not path.is_file():
        return False, (
            f"[!] ERROR: {label} path is not a regular file.",
            f"[!] Please select a valid {label.lower()} file.",
        )
    try:
        size = path.stat().st_size
    except OSError as exc:
        return False, (
            f"[!] ERROR: Cannot inspect the {label.lower()} file.",
            f"[!] {exc.strerror or exc}",
        )
    if size == 0:
        return False, HASH_EMPTY if hash_file else WORDLIST_EMPTY
    return True, None


def _prompt_path(ui: UI, *, hash_file: bool) -> Path | None:
    label = "HASH FILE PATH:" if hash_file else "WORDLIST FILE PATH:"
    while True:
        raw = ui.ask(label)
        if raw.strip() == "0":
            return None
        path = Path(raw.strip()).expanduser()
        ok, error = _check_path(path, hash_file=hash_file)
        if ok:
            try:
                return path.resolve(strict=True)
            except OSError as exc:
                ui.show_hash_error(
                    (
                        "[!] ERROR: Could not resolve the selected file path.",
                        f"[!] {exc.strerror or exc}",
                    )
                )
                continue
        if error is not None:
            ui.show_hash_error(error)


def _report_file_error(ui: UI, exc: HashInputError) -> None:
    if isinstance(exc, (HashFileNotFoundError, EmptyHashFileError)):
        ui.show_hash_error(HASH_MISSING if isinstance(exc, HashFileNotFoundError) else HASH_EMPTY)
    elif isinstance(exc, (WordlistNotFoundError, EmptyWordlistError)):
        ui.show_hash_error(
            WORDLIST_MISSING if isinstance(exc, WordlistNotFoundError) else WORDLIST_EMPTY
        )
    elif isinstance(exc, InvalidHashFormatError):
        ui.show_invalid_hash(str(exc))
    else:
        ui.show_hash_error(("[!] ERROR: Input validation failed.", f"[!] {exc}"))


def _result_failure(ui: UI, result: AttemptResult) -> None:
    detail = result.diagnostic.strip()
    lines = ["[!] ERROR: Hashcat did not complete the recovery attempt."]
    if detail:
        lines.append(f"[!] {detail}")
    lines.append(
        "[!] No no-match conclusion is reported for a failed or interrupted process."
    )
    ui.show_hash_error(lines)


def _run_hashcat(
    ui: UI,
    engine: HashcatEngine,
    spec: HashType,
    hash_lines: list[str],
    wordlist: Path,
) -> None:
    findings: list[tuple[str, str]] = []
    total = len(hash_lines)
    ui.info(f"[*] Starting password recovery for {total} hash(es)...")
    for index, hash_line in enumerate(hash_lines, start=1):
        ui.info(f"[*] Processing hash {index}/{total} with {spec.label}...")

        def on_status(message: str) -> None:
            ui.dim(f"[*] {message}")

        try:
            result = engine.run_attempt(
                spec, hash_line, wordlist, status_callback=on_status
            )
        except HashcatCancelled:
            ui.show_hash_results(
                findings=findings,
                total=total,
                unresolved=total - len(findings),
                cancelled=True,
            )
            return
        except HashcatOutputError as exc:
            if findings:
                ui.show_hash_results(
                    findings=findings,
                    total=total,
                    unresolved=total - len(findings),
                )
            ui.show_hash_error(
                ("[!] ERROR: Could not verify Hashcat output.", f"[!] {exc}")
            )
            return
        except HashcatError as exc:
            if findings:
                ui.show_hash_results(
                    findings=findings,
                    total=total,
                    unresolved=total - len(findings),
                )
            ui.show_hash_error(
                ("[!] ERROR: Hashcat recovery failed.", f"[!] {exc}")
            )
            return

        if result.status == "found":
            findings.append((hash_line, result.password or ""))
        elif result.status == "not_found":
            continue
        elif result.status == "cancelled":
            ui.show_hash_results(
                findings=findings,
                total=total,
                unresolved=total - len(findings),
                cancelled=True,
            )
            return
        else:
            if findings:
                ui.show_hash_results(
                    findings=findings,
                    total=total,
                    unresolved=total - len(findings),
                )
            _result_failure(ui, result)
            return

    ui.show_hash_results(
        findings=findings,
        total=total,
        unresolved=total - len(findings),
    )


def _recover(
    ui: UI,
    spec: HashType,
    *,
    hash_path: Path | None = None,
    hash_prompt_back: bool = True,
) -> None:
    ui.show_hash_selected(spec.label)
    engine = _prepare_engine(ui, spec)
    if engine is None:
        return
    if hash_path is None:
        hash_path = _prompt_path(ui, hash_file=True)
        if hash_path is None:
            return
    wordlist = _prompt_path(ui, hash_file=False)
    if wordlist is None:
        return

    ui.info("[*] Validating input files...")
    try:
        hash_lines = validate_hash_file(hash_path, spec)
    except HashInputError as exc:
        _report_file_error(ui, exc)
        return
    try:
        validate_wordlist(wordlist)
    except HashInputError as exc:
        _report_file_error(ui, exc)
        return

    ui.info("[*] Hash format validated.")
    _run_hashcat(ui, engine, spec, hash_lines, wordlist)


def raw_hashes_screen(ui: UI) -> None:
    while True:
        ui.hash_menu("RAW HASHES", menu_raw())
        choice = ui.select_hash_option(9)
        if choice == "0":
            return
        if choice == "1":
            spec = get_hash_type("md5")
        elif choice == "2":
            spec = get_hash_type("sha1")
        elif choice == "3":
            spec = get_hash_type("sha224")
        elif choice == "4":
            spec = get_hash_type("sha256")
        elif choice == "5":
            spec = get_hash_type("sha384")
        elif choice == "6":
            spec = get_hash_type("sha512")
        elif choice == "7":
            spec = _choose_type(
                ui,
                "SHA3 VARIANTS",
                ("sha3_224", "sha3_256", "sha3_384", "sha3_512"),
            )
            if spec is None:
                continue
        elif choice == "8":
            spec = _choose_type(ui, "RIPEMD VARIANTS", ("ripemd160",))
            if spec is None:
                continue
        else:
            spec = _choose_type(
                ui,
                "BLAKE2 VARIANTS",
                ("blake2b512", "blake2b256", "blake2s256"),
            )
            if spec is None:
                continue
        _recover(ui, spec)
        return


def password_storage_screen(ui: UI) -> None:
    while True:
        ui.hash_menu("PASSWORD STORAGE", menu_password_storage())
        choice = ui.select_hash_option(6)
        if choice == "0":
            return
        if choice == "1":
            spec = get_hash_type("bcrypt")
        elif choice == "2":
            spec = _choose_type(
                ui,
                "PBKDF2 VARIANTS",
                ("pbkdf2_sha256", "pbkdf2_sha1", "pbkdf2_sha512", "pbkdf2_md5"),
            )
            if spec is None:
                continue
        elif choice == "3":
            spec = _choose_type(
                ui, "SCRYPT VARIANTS", ("scrypt", "scryptcrypt")
            )
            if spec is None:
                continue
        elif choice == "4":
            spec = _choose_type(ui, "ARGON2 VARIANTS", ("argon2id",))
            if spec is None:
                continue
        elif choice == "5":
            spec = get_hash_type("phpass")
        else:
            spec = get_hash_type("yescrypt")
        _recover(ui, spec)
        return


def windows_authentication_screen(ui: UI) -> None:
    while True:
        ui.hash_menu("WINDOWS AUTHENTICATION", menu_windows())
        choice = ui.select_hash_option(4)
        if choice == "0":
            return
        if choice == "1":
            spec = get_hash_type("ntlm")
        elif choice == "2":
            spec = get_hash_type("netntlmv1")
        elif choice == "3":
            spec = get_hash_type("netntlmv2")
        else:
            spec = _choose_type(
                ui,
                "KERBEROS 5 VARIANTS",
                (
                    "krb5_asreq_23",
                    "krb5_tgs_23",
                    "krb5_asrep_23",
                    "krb5_tgs_17",
                    "krb5_tgs_18",
                    "krb5_asrep_17",
                    "krb5_asrep_18",
                ),
            )
            if spec is None:
                continue
        _recover(ui, spec)
        return


def application_hashes_screen(ui: UI) -> None:
    while True:
        ui.hash_menu("APPLICATION HASHES", menu_applications())
        choice = ui.select_hash_option(7)
        if choice == "0":
            return
        if choice == "1":
            spec = get_hash_type("wordpress_phpass")
        elif choice == "2":
            spec = get_hash_type("django_pbkdf2_sha256")
        elif choice == "3":
            spec = _choose_type(
                ui, "MYSQL VARIANTS", ("mysql323", "mysql41", "mysql_a")
            )
            if spec is None:
                continue
        elif choice == "4":
            spec = get_hash_type("postgresql")
        elif choice == "5":
            spec = _choose_type(
                ui,
                "MICROSOFT SQL SERVER VARIANTS",
                ("mssql2000", "mssql2005", "mssql2012", "mssql2025"),
            )
            if spec is None:
                continue
        elif choice == "6":
            spec = _choose_type(
                ui,
                "CISCO VARIANTS",
                ("cisco_ios1", "cisco_type4", "cisco_ios9"),
            )
            if spec is None:
                continue
        else:
            spec = _choose_type(
                ui,
                "LDAP VARIANTS",
                ("ldap_sha", "ldap_ssha", "ldap_ssha256", "ldap_ssha512"),
            )
            if spec is None:
                continue
        _recover(ui, spec)
        return


def auto_detect_screen(ui: UI) -> None:
    ui.show_hash_selected("Auto Detect Hash Type")
    hash_path = _prompt_path(ui, hash_file=True)
    if hash_path is None:
        return
    ui.info("[*] Analyzing hash syntax...")
    try:
        candidates, _line_count = detect_hash_file(hash_path)
    except UnsupportedHashDetectionError as exc:
        ui.show_invalid_hash(str(exc))
        return
    except MixedHashTypesError as exc:
        ui.show_hash_error(
            (
                "[!] ERROR: Mixed hash types were detected.",
                f"[!] {exc}",
            )
        )
        return
    except HashInputError as exc:
        _report_file_error(ui, exc)
        return

    if len(candidates) == 1:
        selected = candidates[0]
    else:
        ui.hash_menu(
            "MULTIPLE HASH TYPES DETECTED",
            [
                (str(index), spec.label)
                for index, spec in enumerate(candidates, start=1)
            ],
        )
        choice = ui.select_hash_option(len(candidates))
        if choice == "0":
            return
        selected = candidates[int(choice, 10) - 1]

    _recover(ui, selected, hash_path=hash_path)


def hash_recovery_screen(ui: UI) -> None:
    while True:
        ui.hash_recovery_menu()
        choice = ui.select_hash_option(5)
        if choice == "0":
            return
        if choice == "1":
            raw_hashes_screen(ui)
        elif choice == "2":
            password_storage_screen(ui)
        elif choice == "3":
            windows_authentication_screen(ui)
        elif choice == "4":
            application_hashes_screen(ui)
        else:
            auto_detect_screen(ui)
