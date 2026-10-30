"""Safe process integration with the official Hashcat executable.

Hashcat is the only password-recovery engine used here.  This module never
implements a cracker and never builds a shell command from user input; every
path and value is passed as an argument-list item.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .hashcat_modes import HashType
from .utils import CipherStrikeError

HASHCAT_OFFICIAL_URL = "https://hashcat.net/hashcat/"
DEFAULT_TIMEOUT = 30
PROCESS_GRACE_SECONDS = 5


class HashcatError(CipherStrikeError):
    """Base error for Hashcat integration problems."""


class HashcatNotFoundError(HashcatError):
    pass


class HashcatStartupError(HashcatError):
    pass


class UnsupportedHashModeError(HashcatError):
    pass


class HashcatBackendError(HashcatError):
    pass


class HashcatExecutionError(HashcatError):
    pass


class HashcatOutputError(HashcatError):
    pass


class HashcatCancelled(HashcatError):
    pass


@dataclass(frozen=True)
class AttemptResult:
    status: str  # found | not_found | cancelled | failed
    password: str | None = None
    returncode: int | None = None
    diagnostic: str = ""


def _tail(text: str, limit: int = 2_000) -> str:
    value = " ".join(text.split())
    return value[-limit:]


def resolve_hashcat_executable(explicit: str | Path | None = None) -> Path:
    """Resolve an explicit path or the CIPHERSTRIKE_HASHCAT/HASHCAT_PATH env vars."""
    candidates: list[str | Path] = []
    if explicit is not None:
        candidates.append(explicit)
    for variable in ("CIPHERSTRIKE_HASHCAT", "HASHCAT_PATH"):
        value = os.environ.get(variable)
        if value:
            candidates.append(value)
    for candidate in candidates:
        path = Path(candidate).expanduser()
        if path.is_file():
            return path.resolve()
    found = shutil.which("hashcat") or shutil.which("hashcat.exe")
    if found:
        return Path(found).resolve()
    raise HashcatNotFoundError(
        "Hashcat was not found. Install Hashcat from "
        f"{HASHCAT_OFFICIAL_URL} or set CIPHERSTRIKE_HASHCAT to its executable path."
    )


def parse_mode_table(help_text: str) -> dict[int, str]:
    """Parse the ``hashcat -hh`` hash-mode table."""
    modes: dict[int, str] = {}
    in_table = False
    for line in help_text.splitlines():
        if "- [ Hash Modes ] -" in line:
            in_table = True
            continue
        if in_table and re.match(r"^\s*-\s*\[\s*", line):
            break
        if not in_table:
            continue
        match = re.match(r"^\s*(\d+)\s*\|\s*(.+?)\s*\|\s*", line)
        if match:
            modes[int(match.group(1))] = match.group(2).strip()
    return modes


def build_command(
    executable: Path,
    spec: HashType,
    hash_file: Path,
    wordlist: Path,
    outfile: Path,
    potfile: Path,
) -> list[str]:
    """Build a dictionary-attack argument list without any shell string."""
    return [
        str(executable),
        "-m",
        str(spec.mode),
        "-a",
        "0",
        "--restore-disable",
        "--logfile-disable",
        "--potfile-path",
        str(potfile),
        "--outfile",
        str(outfile),
        "--outfile-format",
        "2",
        "--status",
        "--status-timer",
        "5",
        str(hash_file),
        str(wordlist),
    ]


def decode_outfile_plain(line: str) -> str:
    """Decode Hashcat's ``$HEX[...]`` plaintext escaping when present."""
    value = line
    if value.startswith("$HEX[") and value.endswith("]"):
        encoded = value[5:-1]
        try:
            raw = bytes.fromhex(encoded)
        except ValueError as exc:
            raise HashcatOutputError("Hashcat produced invalid $HEX[] output.") from exc
        return raw.decode("utf-8", errors="replace")
    return value


def parse_outfile(outfile: Path) -> str | None:
    """Read the first recovered plaintext from a format-2 Hashcat outfile."""
    if not outfile.exists():
        return None
    try:
        raw = outfile.read_bytes()
    except OSError as exc:
        raise HashcatOutputError("Could not read Hashcat's output file.") from exc
    if not raw:
        return None
    try:
        text = raw.decode("utf-8", errors="replace")
    except UnicodeDecodeError as exc:
        raise HashcatOutputError("Hashcat outfile is not valid text.") from exc
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    if text.endswith("\n"):
        text = text[:-1]
    lines = text.split("\n")
    if not lines:
        return None
    return decode_outfile_plain(lines[0])


class HashcatEngine:
    """Verified handle to one installed Hashcat executable."""

    def __init__(
        self,
        executable: Path,
        version: str,
        modes: dict[int, str],
        *,
        backend_checked: bool = False,
    ) -> None:
        self.executable = executable
        self.version = version
        self.modes = modes
        self._backend_checked = backend_checked

    @classmethod
    def discover(cls, executable: str | Path | None = None) -> "HashcatEngine":
        path = resolve_hashcat_executable(executable)
        version_result = cls._capture([str(path), "--version"], timeout=DEFAULT_TIMEOUT)
        if version_result.returncode != 0 or not version_result.stdout.strip():
            raise HashcatStartupError(
                "Hashcat was found but could not report its version."
            )
        version = version_result.stdout.strip().splitlines()[0].strip()
        help_result = cls._capture([str(path), "-hh"], timeout=DEFAULT_TIMEOUT)
        if help_result.returncode != 0:
            raise HashcatStartupError(
                "Hashcat was found but its supported-mode table could not be read."
            )
        modes = parse_mode_table(help_result.stdout + "\n" + help_result.stderr)
        if not modes:
            raise HashcatStartupError(
                "Could not parse Hashcat's supported hash-mode table."
            )
        return cls(path, version, modes)

    @staticmethod
    def _capture(
        args: list[str], *, timeout: int
    ) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(
                args,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                shell=False,
                check=False,
            )
        except FileNotFoundError as exc:
            raise HashcatNotFoundError(
                f"Hashcat executable was not found: {args[0]}"
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise HashcatStartupError("Hashcat did not respond in time.") from exc
        except OSError as exc:
            raise HashcatStartupError(
                f"Could not start Hashcat: {exc.strerror or exc}"
            ) from exc

    def verify_mode(self, spec: HashType) -> None:
        actual_name = self.modes.get(spec.mode)
        if actual_name is None:
            raise UnsupportedHashModeError(
                f"Hashcat {self.version} does not list hash mode {spec.mode} "
                f"({spec.label}). No recovery attempt was started."
            )
        if spec.mode_name_hint.lower() not in actual_name.lower():
            raise UnsupportedHashModeError(
                f"Hashcat {self.version} lists mode {spec.mode} as {actual_name!r}, "
                f"which does not match {spec.mode_name_hint!r}. No recovery attempt "
                "was started."
            )

    def check_backends(self) -> None:
        if self._backend_checked:
            return
        result = self._capture([str(self.executable), "-I"], timeout=DEFAULT_TIMEOUT)
        combined = f"{result.stdout}\n{result.stderr}"
        lowered = combined.lower()
        if result.returncode != 0:
            raise HashcatBackendError(
                "Hashcat could not initialize a supported device/backend. "
                f"Details: {_tail(combined)}"
            )
        if "no devices found" in lowered:
            raise HashcatBackendError(
                "Hashcat reported that no supported device/backend is available. "
                "Install a supported OpenCL/CUDA/HIP/Metal backend or run Hashcat "
                "on a compatible system."
            )
        if not combined.strip():
            raise HashcatBackendError(
                "Hashcat produced no backend information; recovery was not started."
            )
        self._backend_checked = True

    def check_ready(self, spec: HashType) -> None:
        self.verify_mode(spec)
        self.check_backends()

    def run_attempt(
        self,
        spec: HashType,
        hash_line: str,
        wordlist: Path,
        *,
        status_callback: Callable[[str], None] | None = None,
    ) -> AttemptResult:
        """Run one dictionary attack for exactly one hash line."""
        try:
            with tempfile.TemporaryDirectory(prefix="cipherstrike-hashcat-") as temp_name:
                temp = Path(temp_name)
                hash_file = temp / "hash.txt"
                outfile = temp / "recovered.txt"
                potfile = temp / "hashcat.pot"
                hash_file.write_text(
                    hash_line.strip() + "\n", encoding="utf-8", newline="\n"
                )
                command = build_command(
                    self.executable, spec, hash_file, wordlist, outfile, potfile
                )
                return self._run_process(
                    command, outfile, status_callback=status_callback
                )
        except OSError as exc:
            raise HashcatExecutionError(
                f"Could not create temporary Hashcat files: {exc.strerror or exc}"
            ) from exc

    def _run_process(
        self,
        command: list[str],
        outfile: Path,
        *,
        status_callback: Callable[[str], None] | None,
    ) -> AttemptResult:
        diagnostics: list[str] = []
        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                shell=False,
            )
        except FileNotFoundError as exc:
            raise HashcatNotFoundError(
                f"Hashcat executable was not found: {command[0]}"
            ) from exc
        except OSError as exc:
            raise HashcatStartupError(
                f"Could not start Hashcat: {exc.strerror or exc}"
            ) from exc

        interrupted = False
        try:
            assert process.stdout is not None
            for line in process.stdout:
                stripped = line.strip()
                if not stripped:
                    continue
                lowered = stripped.lower()
                if stripped.startswith(
                    (
                        "Status...........:",
                        "Recovered........:",
                        "Progress.........:",
                        "Speed.#",
                    )
                ):
                    if status_callback is not None:
                        status_callback(stripped[:180])
                elif any(
                    marker in lowered
                    for marker in (
                        "error",
                        "no devices",
                        "no opencl",
                        "no backend",
                        "failed",
                        "aborted",
                        "interrupted",
                        "exhausted",
                        "cracked",
                    )
                ):
                    diagnostics.append(stripped[:300])
                    if len(diagnostics) > 40:
                        diagnostics.pop(0)
            returncode = process.wait()
        except KeyboardInterrupt:
            interrupted = True
            self._terminate(process)
            raise HashcatCancelled("Hashcat recovery was cancelled by the user.") from None
        finally:
            if not interrupted:
                try:
                    if process.stdout is not None:
                        process.stdout.close()
                except OSError:
                    pass

        recovered = parse_outfile(outfile)
        if recovered is not None:
            return AttemptResult(
                status="found",
                password=recovered,
                returncode=returncode,
                diagnostic="\n".join(diagnostics),
            )

        combined = "\n".join(diagnostics)
        lowered = combined.lower()
        if returncode == 2 or "aborted" in lowered or "interrupted" in lowered:
            return AttemptResult(
                status="cancelled",
                returncode=returncode,
                diagnostic=combined,
            )
        if "no devices" in lowered or "no opencl" in lowered or "no backend" in lowered:
            return AttemptResult(
                status="failed",
                returncode=returncode,
                diagnostic="Hashcat reported no usable devices/backend.",
            )
        if "status...........: exhausted" in lowered:
            return AttemptResult(
                status="not_found",
                returncode=returncode,
                diagnostic=combined,
            )
        if returncode == 1 and not any(
            marker in lowered for marker in ("error", "failed", "no devices", "no backend")
        ):
            return AttemptResult(
                status="not_found",
                returncode=returncode,
                diagnostic=combined,
            )
        if "status...........: cracked" in lowered:
            raise HashcatOutputError(
                "Hashcat reported a cracked hash but produced no recoverable outfile."
            )
        return AttemptResult(
            status="failed",
            returncode=returncode,
            diagnostic=combined or "Hashcat ended without a verifiable status.",
        )

    @staticmethod
    def _terminate(process: subprocess.Popen[str]) -> None:
        try:
            process.terminate()
            process.wait(timeout=PROCESS_GRACE_SECONDS)
        except (OSError, subprocess.TimeoutExpired):
            try:
                process.kill()
                process.wait(timeout=PROCESS_GRACE_SECONDS)
            except (OSError, subprocess.TimeoutExpired):
                pass
