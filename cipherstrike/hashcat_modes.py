"""Central hash-type registry, syntax validators, and genuine auto-detection.

Mode numbers are aligned with the official Hashcat 8.0.0 hash-mode table:
https://github.com/hashcat/hashcat/blob/v8.0.0/docs/hashcat-example-hashes.md

The installed Hashcat executable remains the final authority.  Before any
recovery attempt, the engine checks that the selected mode number exists in
``hashcat -hh`` and that the mode name matches this registry.  Unsupported or
renumbered modes are reported rather than guessed.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

from .utils import CipherStrikeError, ValidationError


class HashInputError(CipherStrikeError):
    """Base error for hash/wordlist input or format problems."""


class HashFileNotFoundError(HashInputError):
    pass


class WordlistNotFoundError(HashInputError):
    pass


class EmptyHashFileError(HashInputError):
    pass


class EmptyWordlistError(HashInputError):
    pass


class InvalidHashFormatError(HashInputError):
    pass


class UnsupportedHashDetectionError(HashInputError):
    pass


class MixedHashTypesError(HashInputError):
    pass


HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
BASE64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
PRINTABLE_ASCII_RE = re.compile(r"^[\x21-\x7e]+$")


@dataclass(frozen=True)
class HashType:
    key: str
    label: str
    mode: int
    mode_name_hint: str
    category: str
    syntax: str
    validator: Callable[[str], None]
    example: str = ""
    detect: bool = True


def _fail(spec_label: str, expected: str) -> None:
    raise InvalidHashFormatError(
        f"Hash does not match the expected {spec_label} syntax. Expected: {expected}"
    )


def _strip(line: str) -> str:
    if not isinstance(line, str):
        raise InvalidHashFormatError("Hash must be text.")
    return line.strip().lstrip("\ufeff")


def _hex_validator(length: int, label: str, syntax: str) -> Callable[[str], None]:
    def validate(line: str) -> None:
        value = _strip(line)
        if len(value) != length or not HEX_RE.fullmatch(value):
            _fail(label, syntax)

    return validate


def _nonempty_segments(value: str, count: int) -> list[str]:
    parts = value.split("$")
    if len(parts) < count or any(part == "" for part in parts):
        return []
    return parts


def _bcrypt(line: str) -> None:
    value = _strip(line)
    if not re.fullmatch(r"\$2[abxy]\$\d{2}\$[./A-Za-z0-9]{53}", value):
        _fail("bcrypt", "$2b$<cost>$<53-character salt+hash>")


def _phpass(line: str) -> None:
    value = _strip(line)
    if not re.fullmatch(r"\$[PH]\$[./0-9A-Za-z]{31}", value):
        _fail("phpass", "$P$ or $H$ followed by 31 portable-hash characters")


def _pbkdf2(algorithm: str) -> Callable[[str], None]:
    pattern = re.compile(
        rf"^{re.escape(algorithm)}:[0-9]+:[A-Za-z0-9+/]+={{0,2}}:[A-Za-z0-9+/]+={{0,2}}$"
    )

    def validate(line: str) -> None:
        value = _strip(line)
        if not pattern.fullmatch(value):
            _fail(
                f"PBKDF2-HMAC-{algorithm.upper()}",
                f"{algorithm}:<iterations>:<base64 salt>:<base64 derived key>",
            )

    return validate


def _django_pbkdf2(line: str) -> None:
    value = _strip(line)
    if not re.fullmatch(
        r"pbkdf2_sha256\$[0-9]+\$[^$]+\$[A-Za-z0-9+/]+={0,2}", value
    ):
        _fail(
            "Django PBKDF2-SHA256",
            "pbkdf2_sha256$<iterations>$<salt>$<base64 hash>",
        )


def _scrypt(line: str) -> None:
    value = _strip(line)
    if not re.fullmatch(
        r"SCRYPT:[0-9]+:[0-9]+:[0-9]+:[A-Za-z0-9+/]+={0,2}:[A-Za-z0-9+/]+={0,2}",
        value,
    ):
        _fail(
            "scrypt",
            "SCRYPT:<N>:<r>:<p>:<base64 salt>:<base64 hash>",
        )


def _scryptcrypt(line: str) -> None:
    value = _strip(line)
    if not re.fullmatch(
        r"\$7\$[./0-9A-Za-z]{16,32}\$[./0-9A-Za-z]{43}", value
    ):
        _fail("scryptcrypt", "$7$<setting>$<43-character hash>")


def _argon2id(line: str) -> None:
    value = _strip(line)
    if not re.fullmatch(
        r"\$argon2id\$v=[0-9]+\$m=[0-9]+,t=[0-9]+,p=[0-9]+\$"
        r"[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+",
        value,
    ):
        _fail(
            "Argon2id",
            "$argon2id$v=<version>$m=<memory>,t=<iterations>,p=<lanes>$<salt>$<hash>",
        )


def _yescrypt(line: str) -> None:
    value = _strip(line)
    if not re.fullmatch(r"\$y\$[./0-9A-Za-z]+\$[./0-9A-Za-z]+\$[./0-9A-Za-z]+", value):
        _fail("yescrypt", "$y$<setting>$<salt>$<hash>")


def _netntlmv1(line: str) -> None:
    value = _strip(line)
    if not re.fullmatch(
        r"[^:]*::[^:]*:[0-9a-fA-F]{48}:[0-9a-fA-F]{48}:[0-9a-fA-F]{16}",
        value,
    ):
        _fail(
            "NetNTLMv1",
            "<user>::<domain>:<48-hex LM response>:<48-hex NT response>:<16-hex challenge>",
        )


def _netntlmv2(line: str) -> None:
    value = _strip(line)
    if not re.fullmatch(
        r"[^:]*::[^:]*:[0-9a-fA-F]{16}:[0-9a-fA-F]{32}:[0-9a-fA-F]{32,}",
        value,
    ):
        _fail(
            "NetNTLMv2",
            "<user>::<domain>:<16-hex challenge>:<32-hex HMAC>:<hex blob>",
        )


def _kerberos_pa23(line: str) -> None:
    value = _strip(line)
    if not re.fullmatch(r"\$krb5pa\$23\$[^$]+\$[^$]+\$[^$]+\$[0-9a-fA-F]+", value):
        _fail("Kerberos 5 AS-REQ Pre-Auth etype 23", "$krb5pa$23$...$...$...$<hex>")


def _kerberos_tgs23(line: str) -> None:
    value = _strip(line)
    if not re.fullmatch(
        r"\$krb5tgs\$23\$\*[^*]+\*\$[0-9a-fA-F]+\$[0-9a-fA-F]+", value
    ):
        _fail(
            "Kerberos 5 TGS-REP etype 23",
            "$krb5tgs$23$*<user>$<realm>$<spn>*$<checksum>$<edata2>",
        )


def _kerberos_asrep23(line: str) -> None:
    value = _strip(line)
    if not re.fullmatch(
        r"\$krb5asrep\$23\$[^:]+:[0-9a-fA-F]{32}\$[0-9a-fA-F]+", value
    ):
        _fail(
            "Kerberos 5 AS-REP etype 23",
            "$krb5asrep$23$<user@realm>:<32-hex checksum>$<edata2>",
        )


def _kerberos_tgs_etype(etype: str) -> Callable[[str], None]:
    def validate(line: str) -> None:
        value = _strip(line)
        if not re.fullmatch(
            rf"\$krb5tgs\${etype}\$[^$]+\$[^$]+\$[0-9a-fA-F]+\$[0-9a-fA-F]+",
            value,
        ):
            _fail(
                f"Kerberos 5 TGS-REP etype {etype}",
                f"$krb5tgs${etype}$<user>$<realm>$<checksum>$<edata2>",
            )

    return validate


def _kerberos_asrep_etype(etype: str) -> Callable[[str], None]:
    def validate(line: str) -> None:
        value = _strip(line)
        if not re.fullmatch(
            rf"\$krb5asrep\${etype}\$[^$]+\$[^$]+\$[0-9a-fA-F]+\$[0-9a-fA-F]+",
            value,
        ):
            _fail(
                f"Kerberos 5 AS-REP etype {etype}",
                f"$krb5asrep${etype}$<user>$<realm>$<checksum>$<edata>",
            )

    return validate


def _mysql_a(line: str) -> None:
    value = _strip(line)
    if not re.fullmatch(r"\$mysql\$A\$[0-9]+\*[0-9A-Fa-f]+\*[0-9A-Fa-f]+", value):
        _fail("MySQL $A$", "$mysql$A$<cost>*<salt>*<hash>")


def _postgresql(line: str) -> None:
    value = _strip(line)
    if not re.fullmatch(r"[0-9a-fA-F]{32}:[0-9a-fA-F]+", value):
        _fail("PostgreSQL MD5", "<32-hex MD5>$<salt>")


def _mssql(line: str, prefix: str, hex_length: int, label: str) -> None:
    value = _strip(line)
    if (
        not value.startswith(prefix)
        or len(value) != len(prefix) + hex_length
        or not HEX_RE.fullmatch(value[2:])
    ):
        _fail(label, f"{prefix}<{hex_length} hex characters>")


def _mssql2000(line: str) -> None:
    _mssql(line, "0x0100", 88, "MSSQL 2000")


def _mssql2005(line: str) -> None:
    _mssql(line, "0x0100", 48, "MSSQL 2005")


def _mssql2012(line: str) -> None:
    _mssql(line, "0x0200", 136, "MSSQL 2012/2014")


def _mssql2025(line: str) -> None:
    _mssql(line, "0x0300", 136, "MSSQL 2025")


def _cisco_ios1(line: str) -> None:
    value = _strip(line)
    if not re.fullmatch(r"\$1\$[./0-9A-Za-z]+\$[./0-9A-Za-z]{22}", value):
        _fail("Cisco-IOS $1$", "$1$<salt>$<22-character hash>")


def _cisco_type4(line: str) -> None:
    value = _strip(line)
    if not re.fullmatch(r"[./0-9A-Za-z]{43}", value):
        _fail("Cisco-IOS type 4", "43 Base64 characters")


def _cisco_ios9(line: str) -> None:
    value = _strip(line)
    if not re.fullmatch(r"\$9\$[0-9]+\$[./0-9A-Za-z]+", value):
        _fail("Cisco-IOS $9$", "$9$<salt>$<hash>")


def _ldap_b64(prefix: str, minimum_bytes: int) -> Callable[[str], None]:
    def validate(line: str) -> None:
        value = _strip(line)
        if not value.startswith(prefix):
            _fail("LDAP hash", f"{prefix}<Base64 data>")
        encoded = value[len(prefix) :]
        if not encoded or not BASE64_RE.fullmatch(encoded):
            _fail("LDAP hash", f"{prefix}<Base64 data>")
        try:
            raw = base64.b64decode(encoded, validate=True)
        except ValueError:
            _fail("LDAP hash", f"{prefix}<Base64 data>")
        if len(raw) < minimum_bytes:
            _fail("LDAP hash", f"{prefix}<Base64 data>")

    return validate


RAW_32 = _hex_validator(32, "MD5/NTLM", "32 hexadecimal characters")
RAW_40 = _hex_validator(40, "SHA1/MySQL/RIPEMD", "40 hexadecimal characters")
RAW_56 = _hex_validator(56, "SHA2-224", "56 hexadecimal characters")
RAW_64 = _hex_validator(64, "SHA2-256/SHA3-256", "64 hexadecimal characters")
RAW_96 = _hex_validator(96, "SHA2-384/SHA3-384", "96 hexadecimal characters")
RAW_128 = _hex_validator(128, "SHA2-512/SHA3-512", "128 hexadecimal characters")


def _blake2(length: int) -> Callable[[str], None]:
    def validate(line: str) -> None:
        value = _strip(line)
        if not re.fullmatch(rf"\$BLAKE2\$[0-9a-fA-F]{{{length}}}", value):
            _fail("BLAKE2", f"$BLAKE2$<{length} hex characters>")

    return validate


HASH_TYPES: tuple[HashType, ...] = (
    # Raw
    HashType("md5", "MD5", 0, "MD5", "raw", "32 hex", RAW_32, "8743b52063cd84097a65d1633f5c74f5"),
    HashType("sha1", "SHA1", 100, "SHA1", "raw", "40 hex", RAW_40, "b89eaac7e61417341b710b727768294d0e6a277b"),
    HashType("sha224", "SHA224", 1300, "SHA2-224", "raw", "56 hex", RAW_56, "e4fa1555ad877bf0ec455483371867200eee89550a93eff2f95a6198"),
    HashType("sha256", "SHA256", 1400, "SHA2-256", "raw", "64 hex", RAW_64, "127e6fbfe24a750e72930c220a8e138275656b8e5d8f48a98c3c92df2caba935"),
    HashType("sha384", "SHA384", 10800, "SHA2-384", "raw", "96 hex", RAW_96, "07371af1ca1fca7c6941d2399f3610f1e392c56c6d73fddffe38f18c430a2817028dae1ef09ac683b62148a2c8757f42"),
    HashType("sha512", "SHA512", 1700, "SHA2-512", "raw", "128 hex", RAW_128, "82a9dda829eb7f8ffe9fbe49e45d47d2dad9664fbb7adf72492e3c81ebd3e29134d9bc12212bf83c6840f10e8246b9db54a4859b7ccd0123d86e5872c1e5082f"),
    HashType("sha3_224", "SHA3-224", 17300, "SHA3-224", "raw", "56 hex", RAW_56, "412ef78534ba6ab0e9b1607d3e9767a25c1ea9d5e83176b4c2817a6c"),
    HashType("sha3_256", "SHA3-256", 17400, "SHA3-256", "raw", "64 hex", RAW_64, "d60fcf6585da4e17224f58858970f0ed5ab042c3916b76b0b828e62eaf636cbd"),
    HashType("sha3_384", "SHA3-384", 17500, "SHA3-384", "raw", "96 hex", RAW_96, "983ba28532cc6320d04f20fa485bcedb38bddb666eca5f1e5aa279ff1c6244fe5f83cf4bbf05b95ff378dd2353617221"),
    HashType("sha3_512", "SHA3-512", 17600, "SHA3-512", "raw", "128 hex", RAW_128, "7c2dc1d743735d4e069f3bda85b1b7e9172033dfdd8cd599ca094ef8570f3930c3f2c0b7afc8d6152ce4eaad6057a2ff22e71934b3a3dd0fb55a7fc84a53144e"),
    HashType("ripemd160", "RIPEMD-160", 6000, "RIPEMD-160", "raw", "40 hex", RAW_40, "012cb9b334ec1aeb71a9c8ce85586082467f7eb6"),
    HashType("blake2b512", "BLAKE2b-512", 600, "BLAKE2b-512", "raw", "$BLAKE2$ + 128 hex", _blake2(128), "$BLAKE2$296c269e70ac5f0095e6fb47693480f0f7b97ccd0307f5c3bfa4df8f5ca5c9308a0e7108e80a0a9c0ebb715e8b7109b072046c6cd5e155b4cfd2f27216283b1e"),
    HashType("blake2b256", "BLAKE2b-256", 34800, "BLAKE2b-256", "raw", "$BLAKE2$ + 64 hex", _blake2(64), "$BLAKE2$68b163391b3e779dcddba4e6d8fa03e962c29569b430efa5ba014303358557e1"),
    HashType("blake2s256", "BLAKE2s-256", 31000, "BLAKE2s-256", "raw", "$BLAKE2$ + 64 hex", _blake2(64), "$BLAKE2$2c719b484789ad5f6fc1739012182169b25484af156adc91d4f64f72400e574a"),
    # Password storage
    HashType("bcrypt", "bcrypt", 3200, "bcrypt", "storage", "$2a$/$2b$/$2y$", _bcrypt, "$2a$05$MBCzKhG1KhezLh.0LRa0Kuw12nLJtpHy6DIaU.JAnqJUDYspHC.Ou"),
    HashType("pbkdf2_sha256", "PBKDF2-HMAC-SHA256", 40024, "PBKDF2-HMAC-SHA256", "storage", "sha256:iterations:salt:hash", _pbkdf2("sha256"), "sha256:1000:NjI3MDM3:vVfavLQL9ZWjg8BUMq6/FB8FtpkIGWYk"),
    HashType("pbkdf2_md5", "PBKDF2-HMAC-MD5", 40031, "PBKDF2-HMAC-MD5", "storage", "md5:iterations:salt:hash", _pbkdf2("md5"), "md5:1000:NjAxMDY4MQ==:a00DtIW9hP9voC85fmEA5uVhgdDx67nSPSm9yADHjkI="),
    HashType("pbkdf2_sha1", "PBKDF2-HMAC-SHA1", 40032, "PBKDF2-HMAC-SHA1", "storage", "sha1:iterations:salt:hash", _pbkdf2("sha1"), "sha1:1000:MTYwNTM4MDU4Mzc4MzA=:aGghFQBtQ8+WVlMk5GEaMw=="),
    HashType("pbkdf2_sha512", "PBKDF2-HMAC-SHA512", 40034, "PBKDF2-HMAC-SHA512", "storage", "sha512:iterations:salt:hash", _pbkdf2("sha512"), "sha512:1000:NzY2:DNWohLbdIWIt4Npk9gpTvA=="),
    HashType("scrypt", "scrypt (Hashcat format)", 8900, "scrypt", "storage", "SCRYPT:N:r:p:salt:hash", _scrypt, "SCRYPT:16384:8:1:OTEyNzU0ODg=:Cc8SPjRH1hFQhuIPCdF51uNGtJ2aOY/isuoMlMUsJ8c="),
    HashType("scryptcrypt", "scryptcrypt / scrypt (Unix)", 36300, "scryptcrypt", "storage", "$7$setting$hash", _scryptcrypt, "$7$C6..../....nRiFmykMMn62$SxIhqyA0SkQFM1dimuhCTqWH4zlIFIvfF.1IzSL.Rb/"),
    HashType("argon2id", "Argon2id", 34000, "Argon2", "storage", "$argon2id$...", _argon2id, "$argon2id$v=19$m=65536,t=3,p=1$FBMjI4RJBhIykCgol1KEJA$2ky5GAdhT1kH4kIgPN/oERE3Taiy43vNN70a3HpiKQU"),
    HashType("phpass", "phpass", 400, "phpass", "storage", "$P$/$H$", _phpass, "$P$946647711V1klyitUYhtB8Yw5DMA/w."),
    HashType("yescrypt", "yescrypt", 36100, "yescrypt", "storage", "$y$...", _yescrypt, "$y$j9T$oJqQoBLMgF5$77xERSZazujSxPgj6nYmzH5r0O2HelZJUyfW.ta7vxD"),
    # Windows
    HashType("ntlm", "NTLM", 1000, "NTLM", "windows", "32 hex", RAW_32, "b4b9b02e6f09a9bd760f388b67351e2b"),
    HashType("netntlmv1", "NetNTLMv1 / ESS", 5500, "NetNTLMv1", "windows", "<user>::<domain>:<LM>:<NT>:<challenge>", _netntlmv1, "::5V4T:ada06359242920a500000000000000000000000000000000:0556d5297b5daa70eaffde82ef99293a3f3bb59b7c9704ea:9c23f6c094853920"),
    HashType("netntlmv2", "NetNTLMv2", 5600, "NetNTLMv2", "windows", "<user>::<domain>:<challenge>:<HMAC>:<blob>", _netntlmv2, "0UL5G37JOI0SX::6VB1IS0KA74:ebe1afa18b7fbfa6:aab8bf8675658dd2a939458a1077ba08:010100000000000031c8aa092510945398b9f7b7dde1a9fb00000000f7876f2b04b700"),
    HashType("krb5_asreq_23", "Kerberos 5 etype 23 AS-REQ Pre-Auth", 7500, "Kerberos 5, etype 23, AS-REQ", "windows", "$krb5pa$23$...", _kerberos_pa23, "$krb5pa$23$user$realm$salt$5cbb0c882a2b26956e81644edbdb746326f4f5f0e947144fb3095dffe4b4b03e854fc1d631323632303636373330383333353630"),
    HashType("krb5_tgs_23", "Kerberos 5 etype 23 TGS-REP", 13100, "Kerberos 5, etype 23, TGS-REP", "windows", "$krb5tgs$23$...", _kerberos_tgs23, "$krb5tgs$23$*user$realm$test/spn*$b548e10f5694ae018d7ad63c257af7dc$35e8e45658860bc31a859b41a08989265f4ef8afd75652ab4d7a30ef151bf6350d879ae189a8cb769e01fa573c6315232b37e4bcad9105520640a781e5fd85c09615e78267e494f433f067cc6958200a82f70627ce0eebc2ac445729c2a8a0255dc3ede2c4973d2d93ac8c1a56b26444df300cb93045d05ff2326affaa3ae97f5cd866c14b78a459f0933a550e0b6507bf8af27c2391ef69fbdd649dd059a4b9ae2440edd96c82479645ccdb06bae0eead3b7f639178a90cf24d9a"),
    HashType("krb5_asrep_23", "Kerberos 5 etype 23 AS-REP", 18200, "Kerberos 5, etype 23, AS-REP", "windows", "$krb5asrep$23$...", _kerberos_asrep23, "$krb5asrep$23$user@domain.com:3e156ada591263b8aab0965f5aebd837$007497cb51b6c8116d6407a782ea0e1c5402b17db7afa6b05a6d30ed164a9933c754d720e279c6c573679bd27128fe77e5fea1f72334c1193c8ff0b370fadc6368bf2d49bbfdba4c5dccab95e8c8ebfdc75f438a0797dbfb2f8a1a5f4c423f9bfc1fea483342a11bd56a216f4d5158ccc4b224b52894fadfba3957dfe4b6b8f5f9f9fe422811a314768673e0c924340b8ccb84775ce9defaa3baa0910b676ad0036d13032b0dd94e3b13903cc738a7b6d00b0b3c210d1f972a6c7cae9bd3c959acf7565be528fc179118f28c679f6deeee1456f0781eb8154e18e49cb27b64bf74cd7112a0ebae2102ac"),
    HashType("krb5_tgs_17", "Kerberos 5 etype 17 TGS-REP", 19600, "Kerberos 5, etype 17, TGS-REP", "windows", "$krb5tgs$17$...", _kerberos_tgs_etype("17"), "$krb5tgs$17$srv_http$synacktiv.local$849e31b3db1c1f203fa20b85$948690f5875125348286ad3346d27b43eaabc71896b620c16de7ddcdbd561628c650c508856a3f574261948b6db4b48332d30536e978046a423ad4368f9a69b4dc4642dab4e0d475d8299be718fd6f98ac85a771b457b2453e78c9411dfce572b19660fe7a5a8246d9b2a91ea2f14d1986ea0a77ecf9b8330bc8fd9ab540bcf46b74c5aa7005cfccd89ec05f66aeab30c6b2bf8595cf6c9a1b68ad885258850c4b1dd9265f270fb2af52fd76c16246df51ea67efc58a65c345686c84e43642febe908a"),
    HashType("krb5_tgs_18", "Kerberos 5 etype 18 TGS-REP", 19700, "Kerberos 5, etype 18, TGS-REP", "windows", "$krb5tgs$18$...", _kerberos_tgs_etype("18"), "$krb5tgs$18$srv_http$synacktiv.local$16ce51f6eba20c8ee534ff8a$57d07b23643a516834795f0c010da8f549b7e65063e5a367ca9240f9b800adad1734df7e7d5dd8307e785de4f40aacf901df41aa6ce695f8619ec579c1fa57ee93661cf402aeef4e3a42e7e3477645d52c09dc72feade03512dffe0df517344f673c63532b790c242cc1d50f4b4b34976cb6e08ab325b3aefb2684262a5ee9faacb14d059754f50553be5bfa5c4c51e833ff2b6ac02c6e5d4c4eb193e27d7dde301bd1ddf480e5e282b8c27ef37b136c8f140b56de105b73adeb1de16232fa1ab5c9f6"),
    HashType("krb5_asrep_17", "Kerberos 5 etype 17 AS-REP", 32100, "Kerberos 5, etype 17, AS-REP", "windows", "$krb5asrep$17$...", _kerberos_asrep_etype("17"), "$krb5asrep$17$user$EXAMPLE.COM$a419c4030e555734b06c2629$c09a1421f96eb126c757a4b87830381f142477d9a85b2beb3093dbfd44f38ddb6016a479537fb7b36e046315869fe79187217971ff6a12c1e0a2df3f68045e03814b21f756d8981f781803d65e8572823c88979581d93cf7d768f2efced16f3719b8d1004d9e73d798de255383476bced47d1982f16be77d0feb55a1f44f58bd013fa4caee58ac614caf0f1cf9101ec9623c5b8c2a1491b73f134f074790088fdb360b5ebce0d32a8145ed00a81ddf77188e150b92d8e8ddd0285d27f1514253e5546e6bba864b362bb1e6483b26d08fa4cc268bfbefe0f690039bcc524b774599df3680c1c3431d891bfa99514a877f964e"),
    HashType("krb5_asrep_18", "Kerberos 5 etype 18 AS-REP", 32200, "Kerberos 5, etype 18, AS-REP", "windows", "$krb5asrep$18$...", _kerberos_asrep_etype("18"), "$krb5asrep$18$user$EXAMPLE.COM$aa4c494f520b27873a4de8f7$ebc9976a77f62e8ccca02d43d68bafcc66a81fcbb44a336b00ce401982f32975a5f9bcdc752643252185866685b0a30aaf50e449e392a5994e6979f23aba25f7704c90b2efa03b703c3c2f9e3617cc588ed226d0417e7742d45407878fd946d046b4a9732b9a203cb857811714b009c195b7c96b9bccb7e48832b11a4e92ecf24c49e54de8d0d5d5351445b5126db90bb7eebc7861db1e61de1175824b0a45023a6fa06c2a9d3035fdcf863bea922648e3dc28b48e39b1dec0869e7fe4de399cb52dfcf2596599da54a4bb0169c72d9496de2e137a4594e0e8a69082fc558ac9ace65d32eae5e260a65ca3f2f5871aaeee7a3b090b50f39321d120c144421e0abe7d"),
    # Applications
    HashType("wordpress_phpass", "WordPress phpass", 400, "phpass", "application", "$P$/$H$", _phpass, "$P$946647711V1klyitUYhtB8Yw5DMA/w.", detect=False),
    HashType("django_pbkdf2_sha256", "Django PBKDF2-SHA256", 40022, "Django", "application", "pbkdf2_sha256$...", _django_pbkdf2, "pbkdf2_sha256$10000$1135411628$bFYX62rfJobJ07VwrUMXfuffLfj2RDM2G6/BrTrUWkE="),
    HashType("mysql323", "MySQL323", 200, "MySQL323", "application", "16 hex", _hex_validator(16, "MySQL323", "16 hexadecimal characters"), "7196759210defdc0"),
    HashType("mysql41", "MySQL4.1/MySQL5", 300, "MySQL4.1/MySQL5", "application", "40 hex", _hex_validator(40, "MySQL4.1/MySQL5", "40 hexadecimal characters"), "fcf7c1b8749cf99d88e5f34271d636178fb5d130"),
    HashType("mysql_a", "MySQL $A$", 7401, "MySQL $A$", "application", "$mysql$A$...", _mysql_a, "$mysql$A$005*F9CC98CE08892924F50A213B6BC571A2C11778C5*625479393559393965414D45316477456B484F41316E64484742577A2E3162785353526B7554584647562F"),
    HashType("postgresql", "PostgreSQL MD5", 12, "PostgreSQL", "application", "md5hex:salt", _postgresql, "93a8cf6a7d43e3b5bcd2dc6abb3e02c6:27032153220030464358344758762807"),
    HashType("mssql2000", "MSSQL 2000", 131, "MSSQL (2000)", "application", "0x0100 + 88 hex", _mssql2000, "0x0100778883860000000000000000000000000000000000000000eda3604e067a06f2732b05b9cb90b8a710996939"),
    HashType("mssql2005", "MSSQL 2005", 132, "MSSQL (2005)", "application", "0x0100 + 48 hex", _mssql2005, "0x010045083578bf13a6e30ca29c40e540813772754d54a5ffd325"),
    HashType("mssql2012", "MSSQL 2012/2014", 1731, "MSSQL (2012, 2014)", "application", "0x0200 + 136 hex", _mssql2012, "0x02003788006711b2e74e7d8cb4be96b1d187c962c5591a02d5a6ae81b3a4a094b26b7877958b26733e45016d929a756ed30d0a5ee65d3ce1970f9b7bf946e705c595f07625b1"),
    HashType("mssql2025", "MSSQL 2025", 36601, "MSSQL (2025)", "application", "0x0300 + 136 hex", _mssql2025, "0x03004DB403DDD3A508F81058E6AD92A6A20E5C72A06AD0B00C0A733EAD6582BE2443AFA70C9516C2DFDC60EA927B40BD732D7763477484FC014435AAC4D57EA88237B39806C1"),
    HashType("cisco_ios1", "Cisco-IOS $1$ (MD5)", 500, "md5crypt", "application", "$1$salt$hash", _cisco_ios1, "$1$38652870$DUjsu4TTlTsOe/xxZ05uf/"),
    HashType("cisco_type4", "Cisco-IOS type 4 (SHA256)", 5700, "Cisco-IOS type 4", "application", "43 Base64 characters", _cisco_type4, "2btjjy78REtmYkkW0csHUbJZOstRXoWdX1mGrmmfeHI"),
    HashType("cisco_ios9", "Cisco-IOS $9$ (scrypt)", 9300, "Cisco-IOS $9$", "application", "$9$salt$hash", _cisco_ios9, "$9$87023684531115$phio0TBQwaO7KZ8toQFyGFyDvyOzidaypRWN0uKX0hU"),
    HashType("ldap_sha", "LDAP {SHA}", 101, "nsldap", "application", "{SHA}Base64", _ldap_b64("{SHA}", 20), "{SHA}uJ6qx+YUFzQbcQtyd2gpTQ5qJ3s="),
    HashType("ldap_ssha", "LDAP {SSHA}", 111, "nsldaps", "application", "{SSHA}Base64", _ldap_b64("{SSHA}", 21), "{SSHA}FLzWcQqyle6Mo7NvrwXCMAmRzXQxNjYxMTYzNw=="),
    HashType("ldap_ssha256", "LDAP {SSHA256}", 1411, "SSHA-256", "application", "{SSHA256}Base64", _ldap_b64("{SSHA256}", 33), "{SSHA256}L5Wk0zPY2lmoR5pH20zngq37KkxFwgTquEhx95rxfVk3Ng=="),
    HashType("ldap_ssha512", "LDAP {SSHA512}", 1711, "SSHA-512", "application", "{SSHA512}Base64", _ldap_b64("{SSHA512}", 65), "{SSHA512}Bz8w5q6qEtB1Nnc8b1jfTvTXVTwohWag33oghQGOtLChnkZTw/cuJaHQlLJEI3AWKZGCRyLA6Phujdxo+is7AjA2MDcyNjY1Mg=="),
)

HASH_TYPES_BY_KEY = {spec.key: spec for spec in HASH_TYPES}
DETECTION_TYPES = tuple(spec for spec in HASH_TYPES if spec.detect)


def get_hash_type(key: str) -> HashType:
    try:
        return HASH_TYPES_BY_KEY[key]
    except KeyError as exc:
        raise ValidationError(f"Unknown hash type: {key}") from exc


def validate_line(spec: HashType, line: str) -> None:
    spec.validator(line)


def read_hash_lines(path: Path) -> list[str]:
    """Read a hash file and return nonempty BOM-stripped lines."""
    if not path.exists():
        raise HashFileNotFoundError(f"Hash file not found: {path}")
    if not path.is_file():
        raise ValidationError(f"Hash path is not a regular file: {path}")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ValidationError(
            f"Cannot read hash file: {path} ({exc.strerror or exc})"
        ) from exc
    if not raw:
        raise EmptyHashFileError(f"Hash file is empty: {path}")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise InvalidHashFormatError(
            "Hash file is not valid UTF-8 text."
        ) from exc
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        raise EmptyHashFileError(f"Hash file contains no nonempty hash lines: {path}")
    return lines


def validate_hash_file(path: Path, spec: HashType) -> list[str]:
    lines = read_hash_lines(path)
    for index, line in enumerate(lines, start=1):
        try:
            spec.validator(line)
        except InvalidHashFormatError as exc:
            raise InvalidHashFormatError(
                f"Hash line {index} is invalid for {spec.label}: {exc}"
            ) from exc
    return lines


def validate_wordlist(path: Path) -> None:
    if not path.exists():
        raise WordlistNotFoundError(f"Wordlist file not found: {path}")
    if not path.is_file():
        raise ValidationError(f"Wordlist path is not a regular file: {path}")
    try:
        if path.stat().st_size == 0:
            raise EmptyWordlistError(f"Wordlist file is empty: {path}")
        with path.open("rb") as handle:
            handle.read(1)
    except OSError as exc:
        raise ValidationError(
            f"Cannot read wordlist file: {path} ({exc.strerror or exc})"
        ) from exc


def detect_candidates(line: str) -> tuple[HashType, ...]:
    """Return every registered type whose syntax accepts the line.

    Multiple candidates are returned for ambiguous lengths/syntax.  This is
    deliberately not a "most likely algorithm" guess.
    """
    matches: list[HashType] = []
    for spec in DETECTION_TYPES:
        try:
            spec.validator(line)
        except InvalidHashFormatError:
            continue
        matches.append(spec)
    return tuple(matches)


def detect_hash_file(path: Path) -> tuple[tuple[HashType, ...], int]:
    """Detect one consistent candidate set across a hash file.

    Mixed or unsupported files raise instead of being silently split.
    """
    lines = read_hash_lines(path)
    baseline: tuple[HashType, ...] | None = None
    for index, line in enumerate(lines, start=1):
        candidates = detect_candidates(line)
        if not candidates:
            raise UnsupportedHashDetectionError(
                f"Hash line {index} did not match any supported format."
            )
        if baseline is None:
            baseline = candidates
            continue
        if {spec.key for spec in candidates} != {spec.key for spec in baseline}:
            raise MixedHashTypesError(
                "The hash file contains lines with different candidate formats. "
                "Auto-detect requires one consistent format; use explicit hash-type "
                "selection or provide a compatible file."
            )
    if baseline is None:
        raise EmptyHashFileError(f"Hash file contains no nonempty hash lines: {path}")
    return baseline, len(lines)


def menu_raw() -> tuple[tuple[str, str], ...]:
    return (
        ("1", "MD5"),
        ("2", "SHA1"),
        ("3", "SHA224"),
        ("4", "SHA256"),
        ("5", "SHA384"),
        ("6", "SHA512"),
        ("7", "SHA3"),
        ("8", "RIPEMD"),
        ("9", "BLAKE2"),
    )


def menu_password_storage() -> tuple[tuple[str, str], ...]:
    return (
        ("1", "bcrypt"),
        ("2", "PBKDF2"),
        ("3", "scrypt"),
        ("4", "Argon2"),
        ("5", "phpass"),
        ("6", "yescrypt"),
    )


def menu_windows() -> tuple[tuple[str, str], ...]:
    return (
        ("1", "NTLM"),
        ("2", "NetNTLMv1"),
        ("3", "NetNTLMv2"),
        ("4", "Kerberos 5"),
    )


def menu_applications() -> tuple[tuple[str, str], ...]:
    return (
        ("1", "WordPress phpass"),
        ("2", "Django PBKDF2"),
        ("3", "MySQL"),
        ("4", "PostgreSQL"),
        ("5", "Microsoft SQL Server"),
        ("6", "Cisco"),
        ("7", "LDAP Password Hashes"),
    )
