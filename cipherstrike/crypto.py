"""Cryptographic core for CIPHER STRIKE.

Design summary (format version 1)
---------------------------------
A random 32-byte Data Encryption Key (DEK) encrypts the payload with
AES-256-GCM in independently authenticated 1 MiB chunks.  A random 8-byte
nonce prefix plus a 32-bit chunk counter forms each 12-byte GCM nonce; a fresh
DEK is generated for every container, so nonce reuse cannot occur across
containers.

The DEK is wrapped twice, independently:

* a 32-character generated password -> Argon2id -> AES-256-GCM key-encryption
  key (KEK);
* a random 32-byte Recovery Key secret -> HKDF-SHA256 -> AES-256-GCM KEK.

The header contains both wrapped copies and is authenticated with HMAC-SHA256
using a key derived from the DEK.  The final chunk is an authenticated JSON
manifest containing the payload size, chunk count, and SHA-256 digest.  Missing
chunks, truncation, reordering, modified ciphertext, wrong passwords, and a
wrong Recovery Key all fail closed before plaintext is published.

No cryptographic primitive is implemented in this project; it uses
``cryptography`` (OpenSSL-backed AES-GCM/HKDF) and ``argon2-cffi``.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import stat
import struct
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO, Mapping

from argon2.low_level import Type as Argon2Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .utils import CipherStrikeError, ValidationError, write_private_text

APP_FORMAT_NAME = "CIPHER STRIKE"
FORMAT_VERSION = 1
MAGIC = b"CIPHERSTRIKE\x00"
HEADER_MAC_SIZE = 32
MAX_HEADER_SIZE = 1_048_576
DEFAULT_CHUNK_SIZE = 1_048_576
MIN_CHUNK_SIZE = 4_096
MAX_CHUNK_SIZE = 16 * 1_048_576
MAX_MANIFEST_SIZE = 16_384
NONCE_PREFIX_SIZE = 8
FILE_ID_SIZE = 16
DEK_SIZE = 32
GCM_NONCE_SIZE = 12
GCM_TAG_SIZE = 16
PASSWORD_MIN_LENGTH = 1
PASSWORD_MAX_BYTES = 1_024
RECOVERY_ID_SIZE = 16
RECOVERY_SECRET_SIZE = 32
RECOVERY_FILE_MAX_BYTES = 32_768
MIN_PASSWORD_SALT = 16
MAX_PASSWORD_SALT = 64
MAX_KDF_MEMORY_KIB = 262_144
MIN_KDF_MEMORY_KIB = 8_192
MAX_KDF_TIME_COST = 10
MAX_KDF_PARALLELISM = 16

UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
LOWERCASE = "abcdefghijklmnopqrstuvwxyz"
DIGITS = "0123456789"
SPECIALS = "!@#$%^&*()-_=+[]{};:,.?"
PASSWORD_LENGTH = 32


class CryptoError(CipherStrikeError):
    """Base class for cryptographic and container-format errors."""


class InvalidContainerError(CryptoError):
    """The container is malformed, unsupported, or has been modified."""


class AuthenticationError(CryptoError):
    """An authenticated decryption check failed."""


class RecoveryKeyError(CryptoError):
    """A Recovery Key file is missing, malformed, or unrelated."""


@dataclass(frozen=True)
class KdfParams:
    """Argon2id parameters recorded in the authenticated container header."""

    time_cost: int = 3
    memory_cost: int = 65_536
    parallelism: int = 4
    hash_len: int = 32

    def __post_init__(self) -> None:
        if not isinstance(self.time_cost, int) or not (
            1 <= self.time_cost <= MAX_KDF_TIME_COST
        ):
            raise ValueError("Invalid Argon2id time cost.")
        if not isinstance(self.memory_cost, int) or not (
            MIN_KDF_MEMORY_KIB <= self.memory_cost <= MAX_KDF_MEMORY_KIB
        ):
            raise ValueError("Invalid Argon2id memory cost.")
        if not isinstance(self.parallelism, int) or not (
            1 <= self.parallelism <= MAX_KDF_PARALLELISM
        ):
            raise ValueError("Invalid Argon2id parallelism.")
        if self.hash_len != 32:
            raise ValueError("Argon2id output length must be 32 bytes.")

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": "argon2id",
            "time_cost": self.time_cost,
            "memory_cost": self.memory_cost,
            "parallelism": self.parallelism,
            "hash_len": self.hash_len,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "KdfParams":
        if not isinstance(value, Mapping) or set(value) != {
            "name",
            "time_cost",
            "memory_cost",
            "parallelism",
            "hash_len",
        }:
            raise InvalidContainerError("Invalid key-derivation parameters.")
        if value.get("name") != "argon2id":
            raise InvalidContainerError("Unsupported key-derivation function.")
        try:
            return cls(
                time_cost=value["time_cost"],
                memory_cost=value["memory_cost"],
                parallelism=value["parallelism"],
                hash_len=value["hash_len"],
            )
        except (TypeError, ValueError) as exc:
            raise InvalidContainerError("Invalid key-derivation parameters.") from exc


@dataclass(frozen=True)
class ContainerInfo:
    """Authenticated public metadata about a container."""

    kind: str
    original_name: str
    created_utc: str
    source_mode: int
    source_mtime_ns: int
    chunk_size: int


@dataclass(frozen=True)
class ContainerHint:
    """Unauthenticated metadata used only to reject an obviously wrong mode."""

    kind: str
    original_name: str


@dataclass(frozen=True)
class PayloadManifest:
    size: int
    chunks: int
    sha256: str


@dataclass(frozen=True)
class DecryptionResult:
    info: ContainerInfo
    manifest: PayloadManifest
    computed_sha256: str
    computed_size: int


@dataclass(frozen=True)
class ContainerSecrets:
    password: str
    recovery_key: "RecoveryKey"


@dataclass(frozen=True)
class RecoveryKey:
    """The independent 32-byte recovery secret and its random identifier."""

    recovery_id: bytes
    secret: bytes

    def __post_init__(self) -> None:
        if len(self.recovery_id) != RECOVERY_ID_SIZE:
            raise ValueError("Invalid Recovery Key identifier length.")
        if len(self.secret) != RECOVERY_SECRET_SIZE:
            raise ValueError("Invalid Recovery Key secret length.")

    @classmethod
    def generate(cls) -> "RecoveryKey":
        return cls(
            recovery_id=secrets.token_bytes(RECOVERY_ID_SIZE),
            secret=secrets.token_bytes(RECOVERY_SECRET_SIZE),
        )

    def _checksum(self) -> bytes:
        material = (
            b"CIPHERSTRIKE/v1/recovery-file\x00" + self.recovery_id + self.secret
        )
        return hashlib.sha256(material).digest()[:16]

    def to_text(self, container_name: str | None = None) -> str:
        """Render a human-readable, copyable Recovery Key file."""
        item = container_name or "(unspecified)"
        return (
            "# CIPHER STRIKE RECOVERY KEY\n"
            "# KEEP THIS FILE PRIVATE. Anyone who obtains it may be able to\n"
            "# decrypt the associated CIPHER STRIKE container.\n"
            f"# Associated container: {item}\n"
            "#\n"
            "-----BEGIN CIPHER STRIKE RECOVERY KEY-----\n"
            "VERSION: 1\n"
            f"RECOVERY ID: {_b64encode(self.recovery_id)}\n"
            f"RECOVERY SECRET: {_b64encode(self.secret)}\n"
            f"CHECKSUM: {_b64encode(self._checksum())}\n"
            "-----END CIPHER STRIKE RECOVERY KEY-----\n"
        )

    @classmethod
    def from_text(cls, text: str) -> "RecoveryKey":
        if not isinstance(text, str) or not text.strip():
            raise RecoveryKeyError("The Recovery Key file is empty.")
        if len(text.encode("utf-8", "strict")) > RECOVERY_FILE_MAX_BYTES:
            raise RecoveryKeyError("The Recovery Key file is too large.")
        begin = "-----BEGIN CIPHER STRIKE RECOVERY KEY-----"
        end = "-----END CIPHER STRIKE RECOVERY KEY-----"
        lines = [line.strip() for line in text.replace("\r\n", "\n").split("\n")]
        begin_positions = [i for i, line in enumerate(lines) if line == begin]
        end_positions = [i for i, line in enumerate(lines) if line == end]
        if len(begin_positions) != 1 or len(end_positions) != 1:
            raise RecoveryKeyError("Invalid Recovery Key file format.")
        start, stop = begin_positions[0], end_positions[0]
        if stop <= start:
            raise RecoveryKeyError("Invalid Recovery Key file format.")
        trailing = [line for line in lines[stop + 1 :] if line and not line.startswith("#")]
        if trailing:
            raise RecoveryKeyError("Invalid Recovery Key file format.")
        fields: dict[str, str] = {}
        for line in lines[start + 1 : stop]:
            if not line or line.startswith("#"):
                continue
            if ":" not in line:
                raise RecoveryKeyError("Invalid Recovery Key file format.")
            key, value = line.split(":", 1)
            key = key.strip()
            value = value.strip()
            if key in fields or not key or not value:
                raise RecoveryKeyError("Invalid Recovery Key file format.")
            fields[key] = value
        if set(fields) != {"VERSION", "RECOVERY ID", "RECOVERY SECRET", "CHECKSUM"}:
            raise RecoveryKeyError("Invalid Recovery Key file format.")
        if fields["VERSION"] != "1":
            raise RecoveryKeyError("Unsupported Recovery Key version.")
        try:
            recovery_id = _b64decode_field(
                fields["RECOVERY ID"], RECOVERY_ID_SIZE, "Recovery Key identifier"
            )
            secret = _b64decode_field(
                fields["RECOVERY SECRET"], RECOVERY_SECRET_SIZE, "Recovery Key secret"
            )
            checksum = _b64decode_field(fields["CHECKSUM"], 16, "Recovery Key checksum")
        except InvalidContainerError as exc:
            raise RecoveryKeyError("Invalid Recovery Key encoding.") from exc
        key = cls(recovery_id=recovery_id, secret=secret)
        if not hmac.compare_digest(checksum, key._checksum()):
            raise RecoveryKeyError(
                "The Recovery Key checksum is invalid; the file may be corrupted."
            )
        return key

    @classmethod
    def load(cls, path: Path) -> "RecoveryKey":
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(path, flags)
        except OSError as exc:
            raise RecoveryKeyError(
                f"Cannot open Recovery Key file: {path} ({exc.strerror or exc})"
            ) from exc
        try:
            with os.fdopen(fd, "rb") as handle:
                raw = handle.read(RECOVERY_FILE_MAX_BYTES + 1)
        except OSError as exc:
            raise RecoveryKeyError(f"Cannot read Recovery Key file: {path}") from exc
        if len(raw) > RECOVERY_FILE_MAX_BYTES:
            raise RecoveryKeyError("The Recovery Key file is too large.")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise RecoveryKeyError("The Recovery Key file is not valid UTF-8.") from exc
        return cls.from_text(text)


# ---------------------------------------------------------------------------
# Encoding helpers
# ---------------------------------------------------------------------------


def _b64encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _b64decode_field(value: str, expected_len: int, label: str) -> bytes:
    if not isinstance(value, str) or not value or len(value) > 1_024:
        raise InvalidContainerError(f"Invalid {label}.")
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError) as exc:
        raise InvalidContainerError(f"Invalid {label}.") from exc
    if len(raw) != expected_len:
        raise InvalidContainerError(f"Invalid {label}.")
    return raw


def _b64decode_range(value: str, minimum: int, maximum: int, label: str) -> bytes:
    if not isinstance(value, str) or not value or len(value) > 4_096:
        raise InvalidContainerError(f"Invalid {label}.")
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError) as exc:
        raise InvalidContainerError(f"Invalid {label}.") from exc
    if not minimum <= len(raw) <= maximum:
        raise InvalidContainerError(f"Invalid {label}.")
    return raw


def _read_exact(stream: BinaryIO, amount: int) -> bytes:
    chunks: list[bytes] = []
    remaining = amount
    while remaining > 0:
        piece = stream.read(remaining)
        if not piece:
            raise InvalidContainerError("Unexpected end of encrypted container.")
        chunks.append(piece)
        remaining -= len(piece)
    return b"".join(chunks)


def _header_mac_input(header_core: bytes) -> bytes:
    return MAGIC + struct.pack(">HI", FORMAT_VERSION, len(header_core)) + header_core


def _derive_header_mac_key(dek: bytes, file_id: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=file_id,
        info=b"CIPHERSTRIKE/v1/header-authentication",
    ).derive(dek)


def _slot_aad(kind: str, file_id: bytes, slot_type: str, recovery_id: bytes = b"") -> bytes:
    return (
        b"CIPHERSTRIKE/v1/slot|"
        + kind.encode("ascii")
        + b"|"
        + slot_type.encode("ascii")
        + b"|"
        + file_id
        + b"|"
        + recovery_id
    )


def _chunk_aad(kind: str, file_id: bytes, index: int, final: bool) -> bytes:
    return (
        b"CIPHERSTRIKE/v1/chunk|"
        + kind.encode("ascii")
        + b"|"
        + file_id
        + b"|"
        + struct.pack(">Q", index)
        + (b"|final" if final else b"|data")
    )


def _nonce(prefix: bytes, counter: int) -> bytes:
    if not 0 <= counter <= 0xFFFFFFFF:
        raise CryptoError("Container chunk counter exhausted.")
    return prefix + struct.pack(">I", counter)


def _derive_password_kek(password: str, salt: bytes, params: KdfParams) -> bytes:
    if not isinstance(password, str):
        raise CryptoError("Password must be text.")
    if not password:
        raise AuthenticationError("Password cannot be empty.")
    try:
        password_bytes = password.encode("utf-8", "strict")
    except UnicodeEncodeError as exc:
        raise AuthenticationError("Password contains unsupported characters.") from exc
    if len(password_bytes) > PASSWORD_MAX_BYTES:
        raise AuthenticationError("Password is too long.")
    try:
        return hash_secret_raw(
            secret=password_bytes,
            salt=salt,
            time_cost=params.time_cost,
            memory_cost=params.memory_cost,
            parallelism=params.parallelism,
            hash_len=params.hash_len,
            type=Argon2Type.ID,
        )
    except Exception as exc:  # argon2-cffi exposes several backend exceptions
        raise CryptoError("Password-based key derivation failed.") from exc


def _derive_recovery_kek(key: RecoveryKey) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=key.recovery_id,
        info=b"CIPHERSTRIKE/v1/recovery-key-encryption",
    ).derive(key.secret)


def generate_password(length: int = PASSWORD_LENGTH) -> str:
    """Generate a 32-character password with every required character class."""
    if length != PASSWORD_LENGTH:
        raise ValueError("CIPHER STRIKE passwords are exactly 32 characters.")
    required = [
        secrets.choice(UPPERCASE),
        secrets.choice(LOWERCASE),
        secrets.choice(DIGITS),
        secrets.choice(SPECIALS),
    ]
    pool = UPPERCASE + LOWERCASE + DIGITS + SPECIALS
    characters = required + [secrets.choice(pool) for _ in range(length - len(required))]
    secrets.SystemRandom().shuffle(characters)
    password = "".join(characters)
    if (
        len(password) != PASSWORD_LENGTH
        or not any(c in UPPERCASE for c in password)
        or not any(c in LOWERCASE for c in password)
        or not any(c in DIGITS for c in password)
        or not any(c in SPECIALS for c in password)
    ):
        # This is impossible with a functioning CSPRNG; fail closed rather
        # than return a password that violates the documented policy.
        raise CryptoError("Password generation failed its category checks.")
    return password


def generate_credentials() -> ContainerSecrets:
    """Generate a fresh password and Recovery Key for one container."""
    return ContainerSecrets(
        password=generate_password(),
        recovery_key=RecoveryKey.generate(),
    )


# ---------------------------------------------------------------------------
# Header construction and parsing
# ---------------------------------------------------------------------------


def _validate_original_name(name: str) -> str:
    if not isinstance(name, str):
        raise ValidationError("Original name must be text.")
    if not name or not name.strip() or name in {".", ".."}:
        raise ValidationError("Original name is empty or reserved.")
    try:
        encoded_name = name.encode("utf-8", "strict")
    except UnicodeEncodeError as exc:
        raise ValidationError("Original name is not valid UTF-8.") from exc
    if len(encoded_name) > 1_024:
        raise ValidationError("Original name is too long.")
    if "\x00" in name or "/" in name or "\\" in name:
        raise ValidationError(
            "File or folder names containing path separators or NUL bytes "
            "are not supported."
        )
    if any(ord(char) < 32 or ord(char) == 127 for char in name):
        raise ValidationError("Original name contains control characters.")
    return name


def _build_header(
    *,
    kind: str,
    original_name: str,
    password: str,
    recovery_key: RecoveryKey,
    source_mode: int,
    source_mtime_ns: int,
    params: KdfParams,
    chunk_size: int,
) -> tuple[dict[str, Any], bytes, bytes, bytes]:
    if kind not in {"file", "folder"}:
        raise ValueError("Invalid container kind.")
    if not MIN_CHUNK_SIZE <= chunk_size <= MAX_CHUNK_SIZE:
        raise ValueError("Invalid chunk size.")
    if not 0 <= source_mode <= 0o777:
        raise ValueError("Invalid source mode.")
    if source_mtime_ns < 0:
        raise ValueError("Invalid source timestamp.")

    original_name = _validate_original_name(original_name)
    dek = secrets.token_bytes(DEK_SIZE)
    file_id = secrets.token_bytes(FILE_ID_SIZE)
    nonce_prefix = secrets.token_bytes(NONCE_PREFIX_SIZE)
    password_salt = secrets.token_bytes(32)
    password_nonce = secrets.token_bytes(GCM_NONCE_SIZE)
    recovery_nonce = secrets.token_bytes(GCM_NONCE_SIZE)

    password_aad = _slot_aad(kind, file_id, "password")
    password_kek = _derive_password_kek(password, password_salt, params)
    wrapped_with_password = AESGCM(password_kek).encrypt(
        password_nonce, dek, password_aad
    )

    recovery_aad = _slot_aad(
        kind, file_id, "recovery", recovery_key.recovery_id
    )
    recovery_kek = _derive_recovery_kek(recovery_key)
    wrapped_with_recovery = AESGCM(recovery_kek).encrypt(
        recovery_nonce, dek, recovery_aad
    )

    header: dict[str, Any] = {
        "format": APP_FORMAT_NAME,
        "version": FORMAT_VERSION,
        "kind": kind,
        "original_name": original_name,
        "created_utc": datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z"),
        "file_id": _b64encode(file_id),
        "nonce_prefix": _b64encode(nonce_prefix),
        "chunk_size": chunk_size,
        "source_mode": source_mode,
        "source_mtime_ns": source_mtime_ns,
        "kdf": params.to_dict(),
        "slots": {
            "password": {
                "salt": _b64encode(password_salt),
                "nonce": _b64encode(password_nonce),
                "wrapped_dek": _b64encode(wrapped_with_password),
            },
            "recovery": {
                "recovery_id": _b64encode(recovery_key.recovery_id),
                "nonce": _b64encode(recovery_nonce),
                "wrapped_dek": _b64encode(wrapped_with_recovery),
            },
        },
    }
    header_core = json.dumps(
        header, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    mac_key = _derive_header_mac_key(dek, file_id)
    header_mac = hmac.new(mac_key, _header_mac_input(header_core), hashlib.sha256).digest()
    return header, header_core, header_mac, dek


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load_json_object(raw: bytes, label: str) -> dict[str, Any]:
    try:
        text = raw.decode("utf-8", "strict")
        value = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        raise InvalidContainerError(f"Invalid {label}.") from exc
    if not isinstance(value, dict):
        raise InvalidContainerError(f"Invalid {label}.")
    return value


def _validate_header(header: Mapping[str, Any]) -> tuple[ContainerInfo, KdfParams, dict[str, Any]]:
    expected_keys = {
        "format",
        "version",
        "kind",
        "original_name",
        "created_utc",
        "file_id",
        "nonce_prefix",
        "chunk_size",
        "source_mode",
        "source_mtime_ns",
        "kdf",
        "slots",
    }
    if not isinstance(header, Mapping) or set(header) != expected_keys:
        raise InvalidContainerError("Invalid container header.")
    if header.get("format") != APP_FORMAT_NAME:
        raise InvalidContainerError("Not a CIPHER STRIKE container.")
    if header.get("version") != FORMAT_VERSION:
        raise InvalidContainerError("Unsupported CIPHER STRIKE format version.")
    kind = header.get("kind")
    if kind not in {"file", "folder"}:
        raise InvalidContainerError("Invalid container kind.")
    original_name = header.get("original_name")
    try:
        original_name = _validate_original_name(original_name)
    except ValidationError as exc:
        raise InvalidContainerError("Invalid original name in container.") from exc
    created = header.get("created_utc")
    if not isinstance(created, str) or not created or len(created) > 64:
        raise InvalidContainerError("Invalid creation timestamp.")
    file_id = _b64decode_field(header.get("file_id"), FILE_ID_SIZE, "file identifier")
    nonce_prefix = _b64decode_field(
        header.get("nonce_prefix"), NONCE_PREFIX_SIZE, "nonce prefix"
    )
    chunk_size = header.get("chunk_size")
    if not isinstance(chunk_size, int) or not (
        MIN_CHUNK_SIZE <= chunk_size <= MAX_CHUNK_SIZE
    ):
        raise InvalidContainerError("Invalid chunk size.")
    source_mode = header.get("source_mode")
    if not isinstance(source_mode, int) or not 0 <= source_mode <= 0o777:
        raise InvalidContainerError("Invalid source mode.")
    source_mtime_ns = header.get("source_mtime_ns")
    if not isinstance(source_mtime_ns, int) or source_mtime_ns < 0:
        raise InvalidContainerError("Invalid source timestamp.")
    params = KdfParams.from_dict(header.get("kdf"))
    slots = header.get("slots")
    if not isinstance(slots, Mapping) or set(slots) != {"password", "recovery"}:
        raise InvalidContainerError("The container must contain exactly two recovery slots.")
    password_slot = slots.get("password")
    recovery_slot = slots.get("recovery")
    if not isinstance(password_slot, Mapping) or set(password_slot) != {
        "salt",
        "nonce",
        "wrapped_dek",
    }:
        raise InvalidContainerError("Invalid password slot.")
    if not isinstance(recovery_slot, Mapping) or set(recovery_slot) != {
        "recovery_id",
        "nonce",
        "wrapped_dek",
    }:
        raise InvalidContainerError("Invalid recovery slot.")
    _b64decode_range(
        password_slot.get("salt"), MIN_PASSWORD_SALT, MAX_PASSWORD_SALT, "password salt"
    )
    _b64decode_field(password_slot.get("nonce"), GCM_NONCE_SIZE, "password nonce")
    _b64decode_field(password_slot.get("wrapped_dek"), DEK_SIZE + GCM_TAG_SIZE, "wrapped key")
    _b64decode_field(
        recovery_slot.get("recovery_id"), RECOVERY_ID_SIZE, "recovery identifier"
    )
    _b64decode_field(recovery_slot.get("nonce"), GCM_NONCE_SIZE, "recovery nonce")
    _b64decode_field(
        recovery_slot.get("wrapped_dek"), DEK_SIZE + GCM_TAG_SIZE, "wrapped key"
    )
    info = ContainerInfo(
        kind=kind,
        original_name=original_name,
        created_utc=created,
        source_mode=source_mode,
        source_mtime_ns=source_mtime_ns,
        chunk_size=chunk_size,
    )
    return info, params, {"file_id": file_id, "nonce_prefix": nonce_prefix, "slots": slots}


def _read_header(
    stream: BinaryIO,
) -> tuple[ContainerInfo, KdfParams, dict[str, Any], bytes, bytes]:
    prefix = stream.read(len(MAGIC) + 6)
    if len(prefix) < len(MAGIC) + 6:
        raise InvalidContainerError("Not a CIPHER STRIKE container.")
    if prefix[: len(MAGIC)] != MAGIC:
        raise InvalidContainerError("Not a CIPHER STRIKE container.")
    version, header_len = struct.unpack(">HI", prefix[len(MAGIC) :])
    if version != FORMAT_VERSION:
        raise InvalidContainerError("Unsupported CIPHER STRIKE format version.")
    if not 2 <= header_len <= MAX_HEADER_SIZE:
        raise InvalidContainerError("Invalid container header length.")
    header_core = _read_exact(stream, header_len)
    header_mac = _read_exact(stream, HEADER_MAC_SIZE)
    header = _load_json_object(header_core, "container header")
    info, params, extra = _validate_header(header)
    return info, params, extra, header_core, header_mac


def _unwrap_dek(
    *,
    info: ContainerInfo,
    params: KdfParams,
    extra: Mapping[str, Any],
    header_core: bytes,
    header_mac: bytes,
    password: str | None,
    recovery_key: RecoveryKey | None,
) -> bytes:
    if (password is None) == (recovery_key is None):
        raise CryptoError("Select exactly one recovery method.")
    file_id: bytes = extra["file_id"]
    slots: Mapping[str, Any] = extra["slots"]
    try:
        if password is not None:
            slot = slots["password"]
            salt = _b64decode_range(
                slot["salt"], MIN_PASSWORD_SALT, MAX_PASSWORD_SALT, "password salt"
            )
            nonce = _b64decode_field(slot["nonce"], GCM_NONCE_SIZE, "password nonce")
            wrapped = _b64decode_field(
                slot["wrapped_dek"], DEK_SIZE + GCM_TAG_SIZE, "wrapped key"
            )
            kek = _derive_password_kek(password, salt, params)
            aad = _slot_aad(info.kind, file_id, "password")
        else:
            assert recovery_key is not None
            slot = slots["recovery"]
            recovery_id = _b64decode_field(
                slot["recovery_id"], RECOVERY_ID_SIZE, "recovery identifier"
            )
            if not hmac.compare_digest(recovery_id, recovery_key.recovery_id):
                raise RecoveryKeyError(
                    "This Recovery Key does not belong to the selected container."
                )
            nonce = _b64decode_field(slot["nonce"], GCM_NONCE_SIZE, "recovery nonce")
            wrapped = _b64decode_field(
                slot["wrapped_dek"], DEK_SIZE + GCM_TAG_SIZE, "wrapped key"
            )
            kek = _derive_recovery_kek(recovery_key)
            aad = _slot_aad(info.kind, file_id, "recovery", recovery_id)
        try:
            dek = AESGCM(kek).decrypt(nonce, wrapped, aad)
        except InvalidTag as exc:
            raise AuthenticationError(
                "Decryption failed: the recovery information is incorrect, or the "
                "container is corrupted or has been modified."
            ) from exc
    except RecoveryKeyError:
        raise
    except CryptoError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise InvalidContainerError("Invalid recovery slot.") from exc

    if len(dek) != DEK_SIZE:
        raise InvalidContainerError("Invalid wrapped data-encryption key.")
    mac_key = _derive_header_mac_key(dek, file_id)
    expected_mac = hmac.new(
        mac_key, _header_mac_input(header_core), hashlib.sha256
    ).digest()
    if not hmac.compare_digest(expected_mac, header_mac):
        raise InvalidContainerError(
            "Container header authentication failed; the file is corrupted or modified."
        )
    return dek


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------


def _manifest_bytes(size: int, chunks: int, digest_hex: str) -> bytes:
    manifest = {
        "format": "CIPHER STRIKE PAYLOAD",
        "version": FORMAT_VERSION,
        "size": size,
        "chunks": chunks,
        "sha256": digest_hex,
    }
    return json.dumps(
        manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def _parse_manifest(raw: bytes) -> PayloadManifest:
    if not raw or len(raw) > MAX_MANIFEST_SIZE:
        raise InvalidContainerError("Invalid payload manifest.")
    try:
        value = json.loads(
            raw.decode("ascii", "strict"), object_pairs_hook=_reject_duplicate_keys
        )
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        raise InvalidContainerError("Invalid payload manifest.") from exc
    if not isinstance(value, dict) or set(value) != {
        "format",
        "version",
        "size",
        "chunks",
        "sha256",
    }:
        raise InvalidContainerError("Invalid payload manifest.")
    if value.get("format") != "CIPHER STRIKE PAYLOAD":
        raise InvalidContainerError("Invalid payload manifest.")
    if value.get("version") != FORMAT_VERSION:
        raise InvalidContainerError("Unsupported payload manifest version.")
    size = value.get("size")
    chunks = value.get("chunks")
    digest = value.get("sha256")
    if not isinstance(size, int) or size < 0:
        raise InvalidContainerError("Invalid payload size.")
    if not isinstance(chunks, int) or chunks < 0:
        raise InvalidContainerError("Invalid payload chunk count.")
    if not isinstance(digest, str) or len(digest) != 64:
        raise InvalidContainerError("Invalid payload digest.")
    try:
        bytes.fromhex(digest)
    except ValueError as exc:
        raise InvalidContainerError("Invalid payload digest.") from exc
    return PayloadManifest(size=size, chunks=chunks, sha256=digest.lower())


# ---------------------------------------------------------------------------
# Streaming writer
# ---------------------------------------------------------------------------


class ContainerWriter:
    """Write one authenticated CIPHER STRIKE container to a binary stream.

    ``close`` writes the final authenticated manifest and flushes the stream.
    The caller owns the underlying stream and must close it.  On any exception
    the caller must delete the incomplete output.
    """

    def __init__(
        self,
        stream: BinaryIO,
        *,
        kind: str,
        original_name: str,
        password: str,
        recovery_key: RecoveryKey,
        source_mode: int,
        source_mtime_ns: int,
        params: KdfParams | None = None,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
    ) -> None:
        self._stream = stream
        self._kind = kind
        self._chunk_size = chunk_size
        self._params = params or KdfParams()
        self._recovery_key = recovery_key
        self._password = password
        self._aes: AESGCM
        self._digest = hashlib.sha256()
        self._payload_size = 0
        self._buffer = bytearray()
        self._chunks = 0
        self._nonce_prefix: bytes
        self._file_id: bytes
        self._closed = False

        header, header_core, header_mac, dek = _build_header(
            kind=kind,
            original_name=original_name,
            password=password,
            recovery_key=recovery_key,
            source_mode=source_mode,
            source_mtime_ns=source_mtime_ns,
            params=self._params,
            chunk_size=chunk_size,
        )
        self._aes = AESGCM(dek)
        self._file_id = _b64decode_field(header["file_id"], FILE_ID_SIZE, "file identifier")
        self._nonce_prefix = _b64decode_field(
            header["nonce_prefix"], NONCE_PREFIX_SIZE, "nonce prefix"
        )
        self._stream.write(_header_mac_input(header_core))
        self._stream.write(header_mac)
        self.info = ContainerInfo(
            kind=kind,
            original_name=original_name,
            created_utc=header["created_utc"],
            source_mode=source_mode,
            source_mtime_ns=source_mtime_ns,
            chunk_size=chunk_size,
        )

    @property
    def payload_size(self) -> int:
        return self._payload_size

    @property
    def payload_sha256(self) -> str:
        return self._digest.hexdigest()

    @property
    def chunk_count(self) -> int:
        return self._chunks

    @property
    def closed(self) -> bool:
        return self._closed

    def write(self, data: bytes | bytearray | memoryview) -> int:
        if self._closed:
            raise CryptoError("Cannot write to a closed container.")
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("ContainerWriter.write expects bytes.")
        view = memoryview(data)
        self._buffer.extend(view)
        while len(self._buffer) >= self._chunk_size:
            piece = bytes(self._buffer[: self._chunk_size])
            del self._buffer[: self._chunk_size]
            self._write_data_chunk(piece)
        return len(view)

    def _write_record(self, plaintext: bytes, final: bool) -> None:
        index = self._chunks
        nonce = _nonce(self._nonce_prefix, index)
        aad = _chunk_aad(self._kind, self._file_id, index, final)
        ciphertext = self._aes.encrypt(nonce, plaintext, aad)
        if len(ciphertext) > 0xFFFFFFFF:
            raise CryptoError("Encrypted chunk is too large.")
        self._stream.write(struct.pack(">IB", len(ciphertext), 1 if final else 0))
        self._stream.write(ciphertext)

    def _write_data_chunk(self, plaintext: bytes) -> None:
        if not plaintext:
            return
        if self._chunks >= 0xFFFFFFFF:
            raise CryptoError("Payload contains too many chunks.")
        self._write_record(plaintext, final=False)
        self._digest.update(plaintext)
        self._payload_size += len(plaintext)
        self._chunks += 1

    def close(self) -> None:
        if self._closed:
            return
        if self._buffer:
            self._write_data_chunk(bytes(self._buffer))
            self._buffer.clear()
        manifest = _manifest_bytes(
            size=self._payload_size,
            chunks=self._chunks,
            digest_hex=self._digest.hexdigest(),
        )
        self._write_record(manifest, final=True)
        try:
            self._stream.flush()
            fileno = getattr(self._stream, "fileno", None)
            if fileno is not None:
                os.fsync(fileno())
        except (OSError, ValueError) as exc:
            raise CryptoError("Failed to flush encrypted output to disk.") from exc
        self._closed = True


# ---------------------------------------------------------------------------
# Streaming reader
# ---------------------------------------------------------------------------


class NullSink:
    """A binary sink that discards authenticated plaintext."""

    def write(self, data: bytes) -> int:
        return len(data)


def decrypt_container_stream(
    stream: BinaryIO,
    sink: BinaryIO,
    *,
    password: str | None = None,
    recovery_key: RecoveryKey | None = None,
    expected_kind: str | None = None,
) -> DecryptionResult:
    """Authenticate and decrypt one container from an open binary stream."""
    info, params, extra, header_core, header_mac = _read_header(stream)
    if expected_kind is not None and info.kind != expected_kind:
        raise InvalidContainerError(
            "The selected container does not match the chosen decryption mode."
        )
    dek = _unwrap_dek(
        info=info,
        params=params,
        extra=extra,
        header_core=header_core,
        header_mac=header_mac,
        password=password,
        recovery_key=recovery_key,
    )
    file_id: bytes = extra["file_id"]
    nonce_prefix: bytes = extra["nonce_prefix"]
    aes = AESGCM(dek)
    digest = hashlib.sha256()
    total = 0
    index = 0
    while True:
        record_header = stream.read(5)
        if not record_header:
            raise InvalidContainerError(
                "Encrypted container ended before its final authenticated record."
            )
        if len(record_header) != 5:
            raise InvalidContainerError("Truncated encrypted container record.")
        ciphertext_len, final_byte = struct.unpack(">IB", record_header)
        if final_byte not in (0, 1):
            raise InvalidContainerError("Invalid encrypted record flag.")
        final = bool(final_byte)
        if final:
            if ciphertext_len < GCM_TAG_SIZE + 1 or ciphertext_len > MAX_MANIFEST_SIZE + GCM_TAG_SIZE:
                raise InvalidContainerError("Invalid final encrypted record length.")
        else:
            if not GCM_TAG_SIZE + 1 <= ciphertext_len <= info.chunk_size + GCM_TAG_SIZE:
                raise InvalidContainerError("Invalid encrypted record length.")
        ciphertext = _read_exact(stream, ciphertext_len)
        nonce = _nonce(nonce_prefix, index)
        aad = _chunk_aad(info.kind, file_id, index, final)
        try:
            plaintext = aes.decrypt(nonce, ciphertext, aad)
        except InvalidTag as exc:
            raise AuthenticationError(
                "Decryption failed: the recovery information is incorrect, or the "
                "encrypted data is corrupted or modified."
            ) from exc
        if final:
            manifest = _parse_manifest(plaintext)
            if stream.read(1):
                raise InvalidContainerError("Unexpected trailing data after final record.")
            if manifest.chunks != index:
                raise InvalidContainerError("Payload chunk count does not match manifest.")
            if manifest.size != total:
                raise InvalidContainerError("Payload size does not match manifest.")
            if not hmac.compare_digest(manifest.sha256, digest.hexdigest()):
                raise InvalidContainerError("Payload digest does not match manifest.")
            return DecryptionResult(
                info=info,
                manifest=manifest,
                computed_sha256=digest.hexdigest(),
                computed_size=total,
            )
        if not plaintext:
            raise InvalidContainerError("Empty payload records are not permitted.")
        if len(plaintext) > info.chunk_size:
            raise InvalidContainerError("Decrypted chunk exceeds the recorded size.")
        sink.write(plaintext)
        digest.update(plaintext)
        total += len(plaintext)
        index += 1


def _open_container_stream(path: Path) -> BinaryIO:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise CryptoError(
            f"Cannot open encrypted container: {exc.strerror or exc}"
        ) from exc
    return os.fdopen(fd, "rb")


def decrypt_container_file(
    path: Path,
    sink: BinaryIO,
    *,
    password: str | None = None,
    recovery_key: RecoveryKey | None = None,
    expected_kind: str | None = None,
) -> DecryptionResult:
    """Open, authenticate, and decrypt a container file."""
    try:
        with _open_container_stream(path) as stream:
            return decrypt_container_stream(
                stream,
                sink,
                password=password,
                recovery_key=recovery_key,
                expected_kind=expected_kind,
            )
    except OSError as exc:
        raise CryptoError(f"Cannot read encrypted container: {exc.strerror or exc}") from exc


def verify_container_file(
    path: Path,
    *,
    password: str | None = None,
    recovery_key: RecoveryKey | None = None,
    expected_kind: str | None = None,
) -> DecryptionResult:
    """Fully authenticate and decrypt a container, discarding plaintext."""
    return decrypt_container_file(
        path,
        NullSink(),
        password=password,
        recovery_key=recovery_key,
        expected_kind=expected_kind,
    )


def verify_both_recovery_methods(
    path: Path,
    *,
    password: str,
    recovery_key: RecoveryKey,
    expected_kind: str | None = None,
) -> tuple[DecryptionResult, DecryptionResult]:
    """Prove that both independent recovery mechanisms decrypt the container."""
    with_password = verify_container_file(
        path, password=password, expected_kind=expected_kind
    )
    with_recovery = verify_container_file(
        path, recovery_key=recovery_key, expected_kind=expected_kind
    )
    if (
        with_password.info.kind != with_recovery.info.kind
        or with_password.info.original_name != with_recovery.info.original_name
        or with_password.manifest != with_recovery.manifest
        or with_password.computed_sha256 != with_recovery.computed_sha256
        or with_password.computed_size != with_recovery.computed_size
    ):
        raise CryptoError("Recovery methods produced inconsistent verification results.")
    return with_password, with_recovery


def read_container_hint(path: Path) -> ContainerHint:
    """Read unauthenticated metadata for a non-security-sensitive UI hint.

    Callers must not use this name for output paths or treat the container as
    valid until authenticated decryption succeeds.
    """
    try:
        with _open_container_stream(path) as stream:
            info, _params, _extra, _core, _mac = _read_header(stream)
            return ContainerHint(kind=info.kind, original_name=info.original_name)
    except OSError as exc:
        raise CryptoError(f"Cannot read encrypted container: {exc.strerror or exc}") from exc


def write_recovery_file(path: Path, key: RecoveryKey, container_name: str) -> None:
    """Create a private Recovery Key file."""
    write_private_text(path, key.to_text(container_name))


def apply_file_metadata(path: Path, info: ContainerInfo) -> None:
    """Best-effort restoration of safe mode bits and modification time."""
    try:
        os.chmod(path, info.source_mode & 0o777)
    except OSError:
        pass
    try:
        os.utime(path, ns=(info.source_mtime_ns, info.source_mtime_ns))
    except OSError:
        pass


def safe_mode(mode: int) -> int:
    """Preserve ordinary permission bits while stripping setuid/setgid/sticky."""
    return stat.S_IMODE(mode) & 0o777
