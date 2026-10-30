"""UI, strict menu validation, branding, and success-screen tests."""

from __future__ import annotations

import importlib.util
import io
from pathlib import Path
from types import SimpleNamespace

import pytest

from cipherstrike.crypto import KdfParams
from cipherstrike.ui import (
    GREEN,
    MAIN_CHOICE_ERROR,
    MENU_CHOICE_ERROR,
    TWO_CHOICE_ERROR,
    YELLOW,
    UI,
)


def _ui(
    inputs: list[str],
    *,
    color: bool = False,
    secret: str | None = None,
) -> tuple[UI, io.StringIO, io.StringIO]:
    output = io.StringIO()
    errors = io.StringIO()
    iterator = iter(inputs)
    ui = UI(
        stream=output,
        error_stream=errors,
        input_fn=lambda _prompt: next(iterator),
        secret_fn=lambda _prompt: secret if secret is not None else next(iterator),
        force_color=color,
    )
    return ui, output, errors


def _rendered(ui: UI, output: io.StringIO) -> str:
    # UI writes to stdout; all tests use the same StringIO exclusively.
    return output.getvalue()


def test_binary_choice_rejects_everything_except_1_and_2() -> None:
    ui, output, _errors = _ui(["3", "0", "-1", "x", "", "2"])
    assert ui.binary_choice() == "2"
    rendered = _rendered(ui, output)
    assert rendered.count(f"[ERROR] {TWO_CHOICE_ERROR}") == 5


def test_main_choice_rejects_invalid_values() -> None:
    ui, output, _errors = _ui(["0", "5", "9", "-1", "abc", "4"])
    assert ui.main_choice() == "4"
    rendered = _rendered(ui, output)
    assert rendered.count(f"[ERROR] {MAIN_CHOICE_ERROR}") == 5


def test_banner_and_menu_use_required_colours_and_wording() -> None:
    ui, output, _errors = _ui([], color=True)
    ui.main_menu()
    rendered = _rendered(ui, output)
    assert "\x1b[92m" in rendered  # green branding
    assert "\x1b[93m" in rendered  # yellow menu
    assert "CIPHER STRIKE" in rendered
    assert "[1] ENCRYPT FILES/FOLDER" in rendered
    assert "[2] DECRYPT FILES/FOLDER" in rendered
    assert "[3] CRACK PASSWORD HASH" in rendered
    assert "[4] PASSWORD GENERATOR" in rendered
    assert "Select an option:" not in rendered  # prompt is printed by ask()


def test_navigation_choice_accepts_zero_and_rejects_other_values() -> None:
    ui, output, _errors = _ui(["3", "4", "abc", "", "0"])
    assert ui.navigation_choice() == "0"
    rendered = _rendered(ui, output)
    assert rendered.count(f"[ERROR] {MENU_CHOICE_ERROR}") == 4


def test_yes_no_accepts_only_y_n_or_enter() -> None:
    ui, output, _errors = _ui(["maybe", "", "Y"])
    assert ui.ask_yes_no("DEFAULT NO? (Y/N):", default=False) is False
    assert "Invalid selection. Please enter Y, N, or press Enter." in _rendered(ui, output)

    ui_y, _output_y, _errors_y = _ui(["y"])
    assert ui_y.ask_yes_no("Y? (Y/N):") is True


def test_hash_option_choice_validation() -> None:
    ui, output, _errors = _ui(["9", "x", "", "2"])
    assert ui.select_hash_option(2) == "2"
    rendered = _rendered(ui, output)
    assert rendered.count("[ERROR] Invalid selection. Please choose 0-2.") == 3


def test_hash_recovery_menu_has_required_options() -> None:
    ui, output, _errors = _ui([], color=True)
    ui.hash_recovery_menu()
    rendered = _rendered(ui, output)
    assert "\x1b[92m" in rendered
    assert "\x1b[93m" in rendered
    assert "CRACK PASSWORD HASH" in rendered
    assert "[1] Raw Hashes" in rendered
    assert "[2] Password Storage" in rendered
    assert "[3] Windows Authentication" in rendered
    assert "[4] Application Hashes" in rendered
    assert "[5] Auto Detect Hash Type" in rendered
    assert "[0] Back" in rendered


def test_hash_submenu_labels_are_present() -> None:
    from cipherstrike.hashcat_modes import (
        menu_applications,
        menu_password_storage,
        menu_raw,
        menu_windows,
    )

    ui, output, _errors = _ui([])
    ui.hash_menu("RAW HASHES", menu_raw())
    ui.hash_menu("PASSWORD STORAGE", menu_password_storage())
    ui.hash_menu("WINDOWS AUTHENTICATION", menu_windows())
    ui.hash_menu("APPLICATION HASHES", menu_applications())
    rendered = _rendered(ui, output)
    for label in (
        "[1] MD5",
        "[9] BLAKE2",
        "[1] bcrypt",
        "[6] yescrypt",
        "[1] NTLM",
        "[4] Kerberos 5",
        "[1] WordPress phpass",
        "[7] LDAP Password Hashes",
    ):
        assert label in rendered


def test_hash_results_screens() -> None:
    ui, output, _errors = _ui([])
    ui.show_hash_results(
        findings=[("hash-one", "password-one")], total=1, unresolved=0
    )
    rendered = _rendered(ui, output)
    assert "[+] PASSWORD FOUND: password-one" in rendered
    assert "Hash: hash-one" in rendered
    assert "Recovered: 1 of 1" in rendered

    ui2, output2, _errors2 = _ui([])
    ui2.show_hash_results(findings=[], total=1, unresolved=1)
    rendered2 = _rendered(ui2, output2)
    assert "[-] PASSWORD NOT FOUND" in rendered2
    assert "[-] No password in the supplied wordlist matched the hash." in rendered2

    ui3, output3, _errors3 = _ui([])
    ui3.show_hash_results(findings=[], total=1, unresolved=1, cancelled=True)
    rendered3 = _rendered(ui3, output3)
    assert "[!] RECOVERY CANCELLED" in rendered3
    assert "PASSWORD NOT FOUND" not in rendered3


def test_hashcat_missing_screen() -> None:
    ui, output, _errors = _ui([], color=True)
    ui.show_hashcat_missing()
    rendered = _rendered(ui, output)
    assert "[!] ERROR: Hashcat was not found." in rendered
    assert "https://hashcat.net/hashcat/" in rendered
    assert "\x1b[91m" in rendered


def test_password_generator_menu_has_required_options() -> None:
    ui, output, _errors = _ui([], color=True)
    ui.password_generator_menu()
    rendered = _rendered(ui, output)
    assert "\x1b[92m" in rendered
    assert "\x1b[93m" in rendered
    assert "WELCOME TO PASSWORD GENERATOR" in rendered
    assert "[1] GENERATE STRONG PASSWORD" in rendered
    assert "[2] GENERATE TARGET WORDLIST" in rendered
    assert "[0] BACK TO MAIN MENU" in rendered


def test_encryption_and_decryption_menus_offer_back() -> None:
    ui, output, _errors = _ui([])
    ui.encrypt_menu()
    ui.decrypt_menu()
    ui.recovery_menu()
    rendered = _rendered(ui, output)
    assert rendered.count("[0] BACK TO MAIN MENU") == 2
    assert "[0] BACK TO DECRYPTION MENU" in rendered


def test_password_success_screen_contains_password_and_save_path(tmp_path: Path) -> None:
    ui, output, _errors = _ui([])
    ui.show_generated_password("Aa1!Bb2@", length=8, categories="uppercase, lowercase, numbers, special characters")
    ui.show_password_saved(tmp_path / "pass.txt")
    rendered = _rendered(ui, output)
    assert "STRONG PASSWORD GENERATED SUCCESSFULLY" in rendered
    assert "Generated Password: Aa1!Bb2@" in rendered
    assert "PASSWORD SAVED SUCCESSFULLY" in rendered
    assert "pass.txt" in rendered


def test_wordlist_success_and_empty_screens() -> None:
    ui, output, _errors = _ui([])
    ui.show_wordlist_success(Path("outputs/example.txt"), 3)
    rendered = _rendered(ui, output)
    assert "[+] WORDLIST GENERATED SUCCESSFULLY" in rendered
    assert f"[+] OUTPUT FILE: {Path('outputs/example.txt')}" in rendered
    assert "[+] UNIQUE CANDIDATES WRITTEN: 3" in rendered
    assert "[+] FORMAT: ONE CANDIDATE PER LINE" in rendered

    ui2, output2, _errors2 = _ui([])
    ui2.show_empty_wordlist()
    assert "NO CANDIDATES MATCHED THE REQUESTED LENGTH RANGE." in _rendered(ui2, output2)


def test_no_colour_fallback_is_readable() -> None:
    ui, output, _errors = _ui([])
    ui.main_menu()
    rendered = _rendered(ui, output)
    assert "\x1b[" not in rendered
    assert "[1] ENCRYPT FILES/FOLDER" in rendered


def test_unavailable_placeholder_message() -> None:
    ui, output, _errors = _ui([])
    ui.unavailable()
    assert (
        "This feature is not available in the current release."
        in _rendered(ui, output)
    )


def test_encryption_success_screen_layout(tmp_path: Path) -> None:
    ui, output, _errors = _ui([], color=False)
    artifacts = SimpleNamespace(
        password="Aa1!" + "x" * 28,
        container=tmp_path / "doc.csafe",
        password_file=tmp_path / "doc.password.txt",
        recovery_file=tmp_path / "doc.recovery",
    )
    ui.show_encryption_success(artifacts)  # type: ignore[arg-type]
    rendered = _rendered(ui, output)
    heading = rendered.index("ENCRYPTION COMPLETED SUCCESSFULLY")
    generated = rendered.index(f"Generated Password: {artifacts.password}")
    important = rendered.index("IMPORTANT: SAVE YOUR RECOVERY INFORMATION!")
    assert heading < generated < important
    assert "WARNING: Original files will be deleted only after successful" in rendered
    assert str(artifacts.container) in rendered
    assert str(artifacts.password_file) in rendered
    assert str(artifacts.recovery_file) in rendered
    assert "Anyone who obtains your Recovery Key may be able to decrypt your data." in rendered
    assert "If you lose both the password and the Recovery Key" in rendered


def test_confirm_delete_requires_exact_token() -> None:
    ui, _output, _errors = _ui(["no"])
    assert ui.confirm_delete(Path("/tmp/source")) == "no"
    ui2, _output2, _errors2 = _ui(["DELETE"])
    assert ui2.confirm_delete(Path("/tmp/source")) == "DELETE"


def test_confirm_overwrite_rejects_invalid_then_accepts_no() -> None:
    ui, output, _errors = _ui(["maybe", ""])
    assert ui.confirm_overwrite(Path("/tmp/out")) is False
    assert "Invalid selection. Please choose y or n." in _rendered(ui, output)


def _load_cli_module():
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location(
        "cipherstrike_cli_test", root / "cipherstrike.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_encryption_screen_declining_deletion_preserves_source(
    tmp_path: Path,
    fast_params: KdfParams,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "manual.txt"
    source.write_text("manual flow", encoding="utf-8")
    outputs = tmp_path / "outputs"
    cli = _load_cli_module()
    monkeypatch.setattr(cli, "default_outputs_dir", lambda: outputs)
    monkeypatch.setattr(cli, "KdfParams", lambda: fast_params)
    ui, output, _errors = _ui(["1", str(source), "no"])
    cli.encryption_screen(ui)
    assert source.exists()
    assert "ENCRYPTION COMPLETED SUCCESSFULLY" in _rendered(ui, output)
    assert "Original source preserved." in _rendered(ui, output)
    assert list(outputs.glob("*.csafe"))
    assert list(outputs.glob("*.recovery"))
    assert list(outputs.glob("*.password.txt"))


def test_error_uses_red_with_colour() -> None:
    ui, output, _errors = _ui([], color=True)
    ui.error("bad thing")
    assert "\x1b[91m" in _rendered(ui, output)
    assert "[ERROR] bad thing" in _rendered(ui, output)


def test_decryption_screen_password_flow(
    tmp_path: Path,
    fast_params: KdfParams,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from cipherstrike.encrypt import encrypt_file

    source = tmp_path / "interactive-decrypt.txt"
    source.write_text("interactive decryption", encoding="utf-8")
    outputs = tmp_path / "outputs"
    artifacts = encrypt_file(source, outputs, params=fast_params)

    cli = _load_cli_module()
    monkeypatch.setattr(cli, "default_outputs_dir", lambda: outputs)
    ui, output, _errors = _ui(
        ["1", str(artifacts.container), "1"],
        secret=artifacts.password,
    )
    cli.decryption_screen(ui)
    rendered = _rendered(ui, output)
    assert "DECRYPTION COMPLETED SUCCESSFULLY" in rendered
    restored = outputs / source.name
    assert restored.exists()
    assert restored.read_text(encoding="utf-8") == "interactive decryption"
    assert artifacts.container.exists()
