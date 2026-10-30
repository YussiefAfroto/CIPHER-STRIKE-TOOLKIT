# CIPHER STRIKE

**A guided command-line toolkit for authenticated file and folder encryption, password and wordlist generation, and authorized Hashcat-based password-hash recovery.**

CIPHER STRIKE is a menu-driven Python application for people who want a clear
workflow around file encryption and offline password-recovery tasks. It is
intended for learners, system administrators, and authorized security testers.
It is **not** a password manager, a backup system, a network attack tool, or a
guarantee that a password can be recovered.

> **Release status:** tested on Windows 11 Pro (64-bit) with Python 3.13.0.
> Linux instructions are provided as unverified guidance below; Linux and macOS
> execution were not tested in this review. Hashcat is an external engine, is
> not bundled, and was not installed during the review, so real Hashcat
> recovery remains unverified. See [Testing](#23-testing) and
> [Hashcat verification](#26-password-hash-recovery-with-hashcat).

---

## Contents

1. [Project overview](#1-project-overview)
2. [Features and status](#2-features-and-status)
3. [Security design and cryptographic approach](#3-security-design-and-cryptographic-approach)
4. [Supported platforms and prerequisites](#4-supported-platforms-and-prerequisites)
5. [Python and dependency requirements](#5-python-and-dependency-requirements)
6. [Installation overview](#6-installation-overview)
7. [Windows installation](#7-windows-installation)
8. [Linux installation](#8-linux-installation)
9. [Running the application](#9-running-the-application)
10. [Main menu options](#10-main-menu-options)
11. [Step-by-step file encryption](#11-step-by-step-file-encryption)
12. [Step-by-step folder encryption](#12-step-by-step-folder-encryption)
13. [Generated password and password text file](#13-generated-password-and-password-text-file)
14. [Recovery Key generation, storage, and usage](#14-recovery-key-generation-storage-and-usage)
15. [File decryption with a password](#15-file-decryption-with-a-password)
16. [File decryption with a Recovery Key](#16-file-decryption-with-a-recovery-key)
17. [Folder restoration](#17-folder-restoration)
18. [The `outputs/` directory](#18-the-outputs-directory)
19. [Original-source deletion and confirmation policy](#19-original-source-deletion-and-confirmation-policy)
20. [Common errors and troubleshooting](#20-common-errors-and-troubleshooting)
21. [Security limitations, backups, and recovery warnings](#21-security-limitations-backups-and-recovery-warnings)
22. [Project structure and responsibilities](#22-project-structure-and-responsibilities)
23. [Testing](#23-testing)
24. [Responsible use and license](#24-responsible-use-and-license)
25. [Password generator and wordlist generator](#25-password-generator-and-wordlist-generator)
26. [Password hash recovery with Hashcat](#26-password-hash-recovery-with-hashcat)
27. [Roadmap](#27-roadmap)
28. [Contributing and security reports](#28-contributing-and-security-reports)
29. [Disclaimer](#29-disclaimer)
30. [Appendix A: encrypted-file format version 1](#30-appendix-a-encrypted-file-format-version-1)

---

## 1. Project overview

CIPHER STRIKE is a menu-driven Python command-line application that brings
several defensive and authorized-testing workflows into one terminal
interface:

* encrypt one regular file into one `.csafe` container;
* encrypt a complete folder tree into one `.csafe` container;
* decrypt a container using the password created during encryption;
* decrypt a container using the independent Recovery Key file;
* generate a cryptographically strong random password of 1-64 characters;
* generate a synthetic-lab-profile wordlist with opt-in transformations;
* guide an authorized offline dictionary attack through the official Hashcat
  executable.

The application was tested on Windows 11 Pro with Python 3.13.0. Linux support
is intended but was not executed in this review; macOS was not tested. It does
not require root or administrator privileges for ordinary file operations. It
creates an `outputs/` directory next to the project and applies restrictive
permissions where the operating system supports POSIX permission bits.

### 1.1 Who this is for

CIPHER STRIKE is for:

* learners who want to see authenticated encryption workflows in a terminal;
* users who need a guided way to encrypt files or folders with a generated
  password and Recovery Key;
* authorized security testers working with synthetic lab profiles and hashes
  they own or are explicitly permitted to test.

It is not a replacement for full-disk encryption, a password manager, a
backup system, or a guaranteed password-recovery service.

### 1.2 Encryption versus hashing

These are different operations:

* **Encryption** transforms readable data into ciphertext using a key or
  password designed for later recovery. CIPHER STRIKE encrypts files and
  folders with AES-256-GCM and supports two independent recovery methods.
* **Hashing** produces a one-way digest of a password or other input. A stored
  password hash is not normally "decrypted." Password-hash recovery tries
  candidate passwords against the hash format.
* **Wordlist generation** creates candidate passwords from supplied profile
  data. It does not crack anything by itself.
* A failed dictionary search means that no candidate in that wordlist matched.
  It does not prove that recovery is mathematically impossible.

> **Hashcat Engine:** CIPHER STRIKE does not implement its own password-cracking
> engine. It integrates the official Hashcat executable and provides a guided
> command-line workflow for supported operations. Hashcat performs the actual
> password-hash recovery; CIPHER STRIKE helps users select supported options,
> provide inputs, and understand the reported result.

CIPHER STRIKE provides menus, input validation, mode selection, and result
presentation around Hashcat. No John the Ripper, Hydra, or custom cracking
engine is used or supported. The guided interface is a usability layer, not a
performance layer: CIPHER STRIKE does not claim to be faster, lighter, or more
memory-efficient than Hashcat.

---

## 2. Features and status

The following table reflects the evidence gathered during the release review.
"Tested" means automated or synthetic tests were actually executed in this
environment; it does not imply independent security audit or real Hashcat
execution.

| Feature | Description | Status |
|---|---|---|
| File encryption | AES-256-GCM file containers with password and Recovery Key wrapping | Implemented and tested on Windows/Python 3.13 |
| File decryption | Password and Recovery Key paths, authentication, tamper detection | Implemented and tested on Windows/Python 3.13 |
| Folder encryption | One authenticated TAR-based container for nested folders and empty directories | Implemented and tested on Windows/Python 3.13 |
| Folder restoration | Safe extraction with traversal/symlink/special-file checks | Implemented and tested on Windows/Python 3.13 |
| Password generator | 1-64 characters, selectable categories, `secrets`, private TXT saving | Implemented and tested on Windows/Python 3.13 |
| Wordlist generator | Synthetic profile fields, transformations, deduplication, length filtering | Implemented and tested on Windows/Python 3.13 |
| Hashcat interface | Menus, validation, subprocess execution, result parsing, cancellation | Implemented; unit/mock tested; **real Hashcat recovery unverified** |
| Auto-detection | Syntax-based candidate detection with ambiguity handling | Implemented; syntax/mode tests passed; real engine unverified |
| Linux support | Intended with Python 3.10+ syntax and POSIX permission branches | **Unverified**; no Linux execution in the review environment |
| macOS support | Not tested or claimed | Unverified |

### 2.1 Implemented in this release

* Large green ASCII-art `CIPHER STRIKE` banner on every screen.
* Strict menu validation; malformed choices never trigger an operation.
* AES-256-GCM file encryption with a random 256-bit data-encryption key.
* Streaming, independently authenticated 1 MiB chunks.
* A versioned, documented container format.
* A 32-character generated password containing uppercase letters, lowercase
  letters, digits, and special characters.
* Argon2id password-based key derivation with 64 MiB memory, 3 iterations, and
  4 lanes by default.
* An independent 32-byte Recovery Key protected with HKDF-SHA256.
* Exactly two recovery slots: password and Recovery Key. There is no hidden
  master password and no third recovery route.
* Folder encryption into one authenticated container, including nested
  folders and empty directories.
* Safe folder restoration with path-traversal, symlink, hard-link, device,
  FIFO, duplicate-path, and absolute-path rejection.
* Automatic unique output names so encryption never overwrites existing files.
* Explicit overwrite confirmation before replacing an existing decrypted
  output.
* Verification of both recovery methods before encryption is reported as
  successful.
* Explicit `DELETE` confirmation and source-change checks before deleting an
  original source.
* Restrictive permissions for generated password, Recovery Key, and container
  files.
* `[4] PASSWORD GENERATOR` with a separate strong-password generator and
  synthetic-lab-profile wordlist generator.
* Strong passwords generated with `secrets`, exact requested length, optional
  uppercase/lowercase/numbers/special categories, secure shuffling, and private
  TXT saving with overwrite confirmation.
* Two-part identity combinations, date/year forms, opt-in custom separators,
  special-character suffixes, bounded numeric suffixes, and Leet substitutions
  for the wordlist generator.
* Actual wordlist counts read back from the saved file after writing.
* `[3] CRACK PASSWORD HASH` with raw, password-storage, Windows
  authentication, application-hash, and auto-detection menus.
* Official Hashcat executable discovery via PATH, `CIPHERSTRIKE_HASHCAT`, or
  `HASHCAT_PATH`.
* Runtime verification of the installed Hashcat version, selected hash mode,
  and available device/backend before recovery.
* Argument-list subprocess execution (no shell concatenation), per-hash result
  association, `$HEX[]` output decoding, cancellation, and temporary-file
  cleanup.
* Genuine syntax-based auto-detection that presents ambiguous candidates rather
  than guessing from length alone.
* `[0]` navigation in submenus and path prompts.
* Automated tests for normal operation and failure cases.

### Not implemented in this release

* A built-in password-cracking engine. Hashcat is the only cracking engine.
* Network authentication attacks, credential harvesting, or automatic
  extraction of hashes from other systems.
* Hashcat attack modes other than dictionary/straight mode (`-a 0`) in the
  interactive workflow.
* Key rotation, password changes, or multi-recipient containers.
* Compressing folder contents before encryption.
* Incremental or partial folder restoration.
* Secure physical erasure.
* A graphical interface.
* Reading plaintext from standard input.
* Hiding the original filename or container type. The authenticated header
  exposes this metadata; file contents remain encrypted.

If the official Hashcat executable is missing, hash recovery reports it clearly
and no cracking is attempted. CIPHER STRIKE never downloads or executes a
Hashcat binary automatically.

---

## 3. Security design and cryptographic approach

### Algorithms and libraries

| Purpose | Mechanism |
|---|---|
| Payload encryption | AES-256-GCM via `cryptography` (`AESGCM`) |
| Data-encryption key | 32 random bytes from `secrets.token_bytes` |
| Password-based KDF | Argon2id via `argon2-cffi` |
| Recovery-key derivation | HKDF-SHA256 via `cryptography` |
| Header authentication | HMAC-SHA256 with an HKDF-derived key |
| Payload integrity | Per-chunk GCM tags plus an authenticated final manifest with SHA-256 |
| Randomness | Python `secrets` / operating-system CSPRNG |

CIPHER STRIKE does not implement AES or Argon2 itself. It uses maintained
libraries backed by OpenSSL and the Argon2 reference implementation. The
terminal interface uses only the standard library and ANSI escape sequences;
there is no Rich or Colorama dependency.

### Key-management design

1. A fresh 32-byte **Data Encryption Key (DEK)** is generated for every
   container. It encrypts the payload.
2. A fresh 32-character password is generated.
3. Argon2id derives a 32-byte password key-encryption key (KEK) from the
   password and a random 32-byte salt.
4. AES-256-GCM wraps the DEK under the password KEK. The wrapping operation is
   bound with authenticated associated data (AAD) to the format, container
   kind, file identifier, and slot type.
5. A fresh 32-byte Recovery Key secret and a 16-byte recovery identifier are
   generated.
6. HKDF-SHA256 derives an independent recovery KEK from the recovery secret and
   identifier.
7. AES-256-GCM independently wraps the same DEK under the recovery KEK. The AAD
   also binds the recovery identifier.
8. The container header stores both wrapped copies of the DEK and the public
   parameters needed to derive each KEK. The plaintext DEK is never stored.
9. The header is authenticated with HMAC-SHA256. The HMAC key is derived from
   the DEK with HKDF-SHA256, so header verification is possible only after a
   successful unwrap.
10. Each encrypted chunk uses AES-256-GCM and an AAD binding the container
    kind, file identifier, chunk index, and final-record flag.
11. The final record authenticates a JSON manifest containing the plaintext
    size, chunk count, and SHA-256 digest. Missing, reordered, or duplicated
    chunks cannot be accepted as a complete payload.
12. After encryption, both recovery methods decrypt the staged container and
    must reproduce the same digest, size, and metadata before the artifacts
    are published.

### Nonce construction

* Every container has a unique random DEK, so nonce reuse across containers
  cannot affect confidentiality.
* The 12-byte GCM chunk nonce is an 8-byte random per-container prefix followed
  by a 4-byte big-endian chunk counter.
* Each counter value is used exactly once per container. The counter is shared
  across data records and the final manifest record.
* Password and Recovery Key wrapping operations use independent random 12-byte
  nonces.

### What the cryptography protects

* Confidentiality of file and folder contents at rest.
* Integrity and authenticity of the container header.
* Integrity and authenticity of every payload chunk.
* Detection of truncation, reordering, duplication, and trailing data.
* Detection of a wrong password or an unrelated Recovery Key.
* Independent recovery through the password or the Recovery Key file.

### What it does not protect

* A compromised machine, malicious kernel, keylogger, memory scraper, or an
  attacker who can observe the password while it is displayed.
* An attacker who obtains both the container and either recovery method.
* The original filename, container kind, creation timestamp, and KDF
  parameters, which are visible in the authenticated header.
* Data after the application has decrypted it into `outputs/`.
* Physical remnants after deleting a file. Ordinary deletion is not secure
  erasure.

See [section 21](#21-security-limitations-backups-and-recovery-warnings) for
operational limitations.

---

## 4. Supported platforms and prerequisites

### 4.1 Platform status

| Platform | Status in this release | Evidence |
|---|---|---|
| Windows 11 Pro 64-bit | **Tested** | Full test suite, CLI startup, and synthetic encryption/decryption workflows were run with Python 3.13.0 |
| Python 3.13 on Windows | **Tested** | `cryptography 46.0.7`, `argon2-cffi 25.1.0`, `pytest 9.2.0` |
| Python 3.10-3.12, 3.14, 3.15 | **Unverified** | Source uses 3.10+ syntax, but only 3.13 was exercised in this review |
| Linux (Debian/Ubuntu/Kali) | **Unverified** | POSIX branches exist; no Linux execution was possible in this environment |
| Linux (Arch) | **Unverified** | No Arch execution was performed |
| macOS | **Not tested / not claimed** | No macOS execution evidence |

The code contains Windows-specific handling for process paths and POSIX
permission handling where available. An unverified platform is not described
as tested merely because the Python source looks portable.

### 4.2 Common prerequisites

* Python **3.13** is the version verified in this review.
* The Python source uses **3.10+ syntax**, but older/newer versions were not
  exercised here. Python 3.15 is installed on the review host but was not used
  or validated for this release.
* A UTF-8-capable terminal is recommended for the banner and bullet characters.
* Ordinary file encryption does not require root or administrator privileges.
* Hashcat is optional and needed only for `[3] CRACK PASSWORD HASH`.

### 4.3 Windows prerequisites

* Windows 11 with PowerShell was tested. Windows 10 is not claimed as tested.
* Python 3.13 installed from the official Python distribution:
  <https://www.python.org/downloads/windows/>
* The `py` launcher is useful when `python` is not on `PATH`.
* Optional: official Hashcat, if you intend to use hash recovery:
  <https://hashcat.net/hashcat/>

### 4.4 Linux prerequisites

These commands target Debian/Ubuntu-based systems. They are provided as
unverified guidance because Linux execution was not possible during this
review.

```bash
sudo apt update
```

`sudo apt update` refreshes the APT package index; it does not install CIPHER
STRIKE itself. Then install the prerequisites:

```bash
sudo apt install -y git python3 python3-venv python3-pip
```

If a prebuilt wheel for `cryptography` is unavailable and a local build is
required, install common build prerequisites as well:

```bash
sudo apt install -y build-essential libssl-dev libffi-dev python3-dev
```

For Arch Linux, the equivalent package installation is **unverified**:

```bash
sudo pacman -S --needed git python python-pip
```

Hashcat is a separate prerequisite for hash recovery. Do not assume that
installing CIPHER STRIKE's Python dependencies installs Hashcat.

---

## 5. Python and dependency requirements

The application imports these third-party packages:

| Package | Constraint | Purpose |
|---|---|---|
| [`cryptography`](https://cryptography.io/) | `>=43.0.0,<47.0.0` | AES-256-GCM and HKDF |
| [`argon2-cffi`](https://argon2-cffi.readthedocs.io/) | `>=23.1.0,<26.0.0` | Argon2id password KDF |
| [`pytest`](https://pytest.org/) | `>=8.0.0,<10.0.0` | Test suite only |

`requirements.txt` contents:

```text
cryptography>=43.0.0,<47.0.0
argon2-cffi>=23.1.0,<26.0.0
pytest>=8.0.0,<10.0.0
```

`pytest` is test-only; the application itself does not import it. Hashcat is
**not** a Python package and is not installed by `requirements.txt`.

Observed versions in the clean review environment:

```text
cryptography 46.0.7
argon2-cffi 25.1.0
pytest 9.2.0
```

`python -m pip check` reported no broken requirements in that environment.

---

## 6. Installation overview

The repository URL is not known at the time of this review. Use a placeholder
until the project is published:

```bash
git clone <YOUR_GITHUB_REPOSITORY_URL>
cd <YOUR_REPOSITORY_DIRECTORY>
```

If you downloaded a ZIP instead, extract it and open a terminal in the folder
containing `cipherstrike.py` and the `cipherstrike/` package.

Choose one installation path:

* **Windows:** [section 7](#7-windows-installation) — tested path.
* **Linux:** [section 8](#8-linux-installation) — unverified Debian/Ubuntu
  guidance.

Hashcat installation is separate and optional; see
[section 26](#26-password-hash-recovery-with-hashcat).

---

## 7. Windows installation

The tested path uses Python 3.13 and a project-local virtual environment.

1. Open PowerShell and enter the project directory. Replace the example path
   with the real location:

   ```powershell
   cd C:\path\to\CIPHER-STRIKE
   ```

2. Verify that Python 3.13 is available:

   ```powershell
   py -3.13 --version
   ```

3. Create a virtual environment:

   ```powershell
   py -3.13 -m venv .venv
   ```

4. Install the exact dependencies using the environment's interpreter:

   ```powershell
   .\.venv\Scripts\python.exe -m pip install --upgrade pip
   .\.venv\Scripts\python.exe -m pip install -r requirements.txt
   .\.venv\Scripts\python.exe -m pip check
   ```

5. Start CIPHER STRIKE:

   ```powershell
   .\.venv\Scripts\python.exe cipherstrike.py
   ```

The direct interpreter path avoids PowerShell execution-policy issues. If you
prefer activation:

```powershell
.\.venv\Scripts\Activate.ps1
python cipherstrike.py
deactivate
```

If activation is blocked by policy, you can choose a process-scoped policy for
the current PowerShell window:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

Do not change the machine-wide execution policy merely to run this project.

If `python` is not on `PATH`, use `py -3.13` or the direct
`.\.venv\Scripts\python.exe` path shown above. Do not assume that Python 3.15
is supported; it was not tested in this review.

For optional Hashcat recovery, see
[section 26](#26-password-hash-recovery-with-hashcat). The application does
not install Hashcat for you.

---

## 8. Linux installation

> These instructions target Debian/Ubuntu/Kali-style systems and are
> **unverified** for CIPHER STRIKE in this review. They are not a claim that
> every distribution or Python build has been tested.

1. Update the APT package index:

   ```bash
   sudo apt update
   ```

2. Install Git, Python, virtual-environment support, and pip:

   ```bash
   sudo apt install -y git python3 python3-venv python3-pip
   ```

3. Clone the repository using your real URL and directory name:

   ```bash
   git clone <YOUR_GITHUB_REPOSITORY_URL>
   cd <YOUR_REPOSITORY_DIRECTORY>
   ```

4. Create and activate a virtual environment:

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

5. Install the pinned dependency set:

   ```bash
   python -m pip install --upgrade pip
   python -m pip install -r requirements.txt
   python -m pip check
   ```

6. Start the application:

   ```bash
   python cipherstrike.py
   ```

7. Leave the virtual environment when finished:

   ```bash
   deactivate
   ```

If `python3 -m venv` is unavailable, install the distribution's
`python3-venv` package. Package names and Python versions differ across
distributions; the commands above are not a guarantee of Linux support.

Hashcat is separate and optional; see
[section 26](#26-password-hash-recovery-with-hashcat).

---

## 9. Running the application

From the project directory, with the environment installed:

**Windows (tested):**

```powershell
.\.venv\Scripts\python.exe cipherstrike.py
```

**Linux (unverified):**

```bash
source .venv/bin/activate
python cipherstrike.py
```

The application displays the green `CIPHER STRIKE` banner and four menu
entries. It is interactive; there are no command-line flags required for the
documented workflows. Press `Ctrl+C` to exit. Interrupting a normal operation
does not publish unverified encrypted outputs and does not delete the original
source.

---

## 10. Main menu options

```text
[1] ENCRYPT FILES/FOLDER
[2] DECRYPT FILES/FOLDER
[3] CRACK PASSWORD HASH
[4] PASSWORD GENERATOR

Select an option:
```

* `1` opens the encryption interface.
* `2` opens the decryption interface.
* `3` opens the password-hash recovery menu. It requires the official Hashcat
  executable; see [section 26](#26-password-hash-recovery-with-hashcat).
* `4` opens the password generator submenu:

```text
WELCOME TO PASSWORD GENERATOR

[1] GENERATE STRONG PASSWORD
[2] GENERATE TARGET WORDLIST
[0] BACK TO MAIN MENU

SELECT OPTION:
```

* Any main-menu value other than `1`-`4`, including `0`, `5`, `9`, a negative
  number, an empty value, or text, displays:

```text
[ERROR] Invalid selection. Please choose a number between 1 and 4.
```

Two-choice navigation menus accept `0`, `1`, or `2`; invalid input displays:

```text
[ERROR] Invalid selection. Please choose 0, 1, or 2.
```

Password-hash submenus accept `0` through their highest listed option and
display `[ERROR] Invalid selection. Please choose 0-N.` for out-of-range input.

Encryption and decryption screens include `[0] BACK TO MAIN MENU`. File/folder
path prompts accept `0` to return to their parent menu. The recovery-method menu
includes `[0] BACK TO DECRYPTION MENU`, and the Recovery Key path prompt accepts
`0` to return to that recovery menu.

---

## 11. Step-by-step file encryption

1. Start the application (Windows tested path):

   ```powershell
   .\.venv\Scripts\python.exe cipherstrike.py
   ```

   On Linux, use `python cipherstrike.py` after activating the environment
   (unverified).

2. Select `1` for `ENCRYPT FILES/FOLDER`.
3. On the encryption screen, select `1` for `ENCRYPT FILE`.
4. At `FILE PATH:`, enter the path of a regular file. Example placeholder:

   ```text
   C:\path\to\report.pdf
   ```

5. The application validates the path, rejects symlinks and wrong object
   types, encrypts the file, and verifies the container with both recovery
   methods.
6. On success, the terminal shows `ENCRYPTION COMPLETED SUCCESSFULLY`, the
   generated password, the warning block, and the exact output paths.
7. The original source is still present. To delete it, type uppercase `DELETE`
   at the confirmation prompt. To keep it, press Enter.
8. The output is one container plus a Recovery Key file and a password file in
   `outputs/`.

Example result:

```text
outputs/report.csafe
outputs/report.recovery
outputs/report.password.txt
```

If those names already exist, the application selects the next free common
stem (`report-1`, `report-2`, ...) rather than overwriting anything.

---

## 12. Step-by-step folder encryption

1. Select `1` for `ENCRYPT FILES/FOLDER`.
2. Select `2` for `ENCRYPT FOLDER`.
3. At `FOLDER PATH:`, enter a directory. Example placeholder:

   ```text
   C:\path\to\Project
   ```

4. The application scans the tree without following symbolic links.
5. Supported regular files and nested directories, including empty
   directories, are written as a streaming PAX TAR archive directly into the
   encrypted container. Plaintext archive data is never written to disk.
6. The whole container is verified with both recovery methods before the
   success screen appears.
7. The source folder remains until you type uppercase `DELETE` at the explicit
   confirmation prompt.

The folder is reconstructed from one container during decryption, including
its nested structure and empty directories.

### Folder handling rules

* Symbolic links inside the selected folder are rejected; they are not silently
  skipped or followed.
* Sockets, devices, FIFOs, and other special filesystem objects are rejected.
* Hard links are treated as separate regular file contents; the link
  relationship itself is not preserved.
* File content is encrypted; names are stored in the encrypted payload archive.
* Owner permission bits (`rwx`) are preserved.
* Setuid, setgid, and sticky bits are stripped.
* File ownership, group ownership, POSIX ACLs, extended attributes, and file
  capabilities are not preserved.
* Modification times are preserved on a best-effort basis.
* The folder archive is not compressed.
* Names containing `/`, backslashes, NUL bytes, control characters, or invalid
  UTF-8 are rejected. This is deliberate to keep restoration portable and safe.
* If any file changes size, inode, mode, or modification time during
  encryption, the operation fails and the source is preserved.

---

## 13. Generated password and password text file

> This section describes the recovery password created automatically during
> **encryption**. The `[4] PASSWORD GENERATOR` menu is a separate utility and is
> documented in [section 25](#25-password-generator-and-wordlist-generator).

The application generates the password; the user is never asked to invent one.

* Length: exactly **32 characters**.
* At least one uppercase letter.
* At least one lowercase letter.
* At least one digit.
* At least one special character.
* Generated with Python's cryptographically secure `secrets` module.
* Not derived from the filename, timestamp, username, or any predictable value.

The password is displayed directly below the success heading and is saved in:

```text
outputs/<stem>.password.txt
```

The password file is created with mode `0600` where POSIX permissions are
supported. It contains the generated password, the container name, and a
security warning. It does **not** contain the Recovery Key secret.

> Treat the password text file as a secret. Storing the password, Recovery Key,
> and container together on one machine is convenient but is not a robust
> backup strategy.

---

## 14. Recovery Key generation, storage, and usage

The Recovery Key is **not** the password stored in another file. It is an
independent random 32-byte secret generated for the container.

* Stored in `outputs/<stem>.recovery`.
* File mode `0600` where POSIX permissions are supported.
* Uses its own random 16-byte identifier.
* The header contains a separate AES-256-GCM wrapping of the DEK under a
  Recovery-Key-derived KEK.
* A checksum in the text file detects accidental corruption.
* The file includes the identifier and the secret, plus a warning.

To use it during decryption, select:

```text
[2] DECRYPT WITH RECOVERY KEY
```

and provide the `.recovery` file path. The original password is not required.

The Recovery Key file can be moved or backed up independently. Anyone who
obtains it may be able to decrypt the associated container, so protect it as
you would protect the password.

If both the password and the Recovery Key are lost, there is no built-in
recovery mechanism and the data cannot be recovered by CIPHER STRIKE.

---

## 15. File decryption with a password

1. Select `2` for `DECRYPT FILES/FOLDER`.
2. Select `1` for `DECRYPT FILE`.
3. At `ENCRYPTED FILE PATH:`, enter the `.csafe` container path.
4. Select `1` for `DECRYPT WITH PASSWORD`.
5. Enter the generated password at the hidden prompt.
6. The application authenticates the header and every chunk before publishing
   plaintext.
7. On success, it displays `DECRYPTION COMPLETED SUCCESSFULLY` and the restored
   output path.
8. The encrypted container remains in place and is never deleted automatically.

If authentication fails, the application reports that the password may be
incorrect or the data may be corrupted. No plaintext is published.

---

## 16. File decryption with a Recovery Key

1. Select `2` for `DECRYPT FILES/FOLDER`.
2. Select `1` for `DECRYPT FILE`.
3. Provide the encrypted container path.
4. Select `2` for `DECRYPT WITH RECOVERY KEY`.
5. At `RECOVERY KEY FILE PATH:`, enter the `.recovery` file path.
6. The application validates the file format, checksum, and recovery
   identifier, then unwraps the DEK without the password.
7. The container is authenticated and the restored file is published to
   `outputs/`.

If the Recovery Key is missing, malformed, corrupted, or belongs to a different
container, no plaintext is published and the encrypted input is preserved.

---

## 17. Folder restoration

1. Select `2` for `DECRYPT FILES/FOLDER`.
2. Select `2` for `DECRYPT FOLDER`.
3. At `ENCRYPTED FOLDER CONTAINER PATH:`, enter the single `.csafe` container
   that represents the folder, for example `outputs/Project.csafe`.
4. Choose password or Recovery Key recovery.
5. The container is decrypted to a private staging archive and fully
   authenticated.
6. The TAR archive is validated and extracted into a private staging directory.
7. Only after successful extraction is the restored folder published to
   `outputs/<original-folder-name>`.
8. The encrypted container is preserved.

Restoration rejects:

* absolute archive paths;
* `..` traversal;
* duplicated paths;
* symbolic links and hard links;
* devices, FIFOs, and other special objects;
* paths containing NUL bytes or backslashes;
* extraction that would leave the destination root.

If an output directory with the same name already exists, the application asks
for explicit `y` confirmation before replacing it. If confirmation is refused,
the existing output is preserved and no new output is published.

---

## 18. The `outputs/` directory

`outputs/` is created next to the project files on first use and is excluded
from version control.

A successful encryption produces three related artifacts:

```text
outputs/
├── document.csafe
├── document.recovery
└── document.password.txt
```

* `.csafe` — the encrypted container.
* `.recovery` — the independent Recovery Key file.
* `.password.txt` — the generated password and context.

The directory is created with mode `0700` and generated files with mode `0600`
on POSIX systems. On filesystems that do not implement POSIX permission bits,
restrictive permissions are best-effort.

> **Windows ACL note:** `os.chmod` does not install owner-only NTFS ACLs on
> Windows. `outputs/` and its password, Recovery Key, wordlist, and recovered
> data files may inherit the project folder's Windows permissions. Use NTFS
> permissions (for example, through the folder's **Properties → Security** tab)
> to restrict `outputs/` to your account before encrypting or recovering
> sensitive material.

The common stem is derived from the source name. A suffix such as `-1`, `-2` is
added when needed so no existing artifact is overwritten. The success screen
always shows the exact final paths.

Decrypted files and folders are also written to `outputs/` using the
authenticated original name, with an overwrite confirmation if that name is
already taken.

The password generator and wordlist generator also save their TXT files in
`outputs/`:

```text
outputs/
├── strong-password.txt
└── synthetic-wordlist.txt
```

Both generators refuse to overwrite by default and ask for explicit
confirmation when a requested filename already exists.

---

## 19. Original-source deletion and confirmation policy

Encryption never deletes the source as a side effect. The order is:

1. Read the selected source.
2. Generate the cryptographic material and recovery artifacts.
3. Write and flush a staged encrypted container.
4. Verify the container with both the password and the Recovery Key.
5. Verify the generated Recovery Key and password files.
6. Publish all three artifacts without overwriting existing files.
7. Display the success screen and exact paths.
8. Ask for explicit deletion confirmation.
9. Delete the source only if the user types uppercase `DELETE`.
10. Re-check a source snapshot immediately before deletion. If the source
    changed after encryption, deletion is refused and the source is preserved.

The snapshot check covers file identity, size, mode, modification time, and
(for folders) the complete set of entries. It is not a second full content
hash of every file. A local process that modifies a file while preserving all of
these metadata fields could evade the pre-deletion check. Do not modify source
data during an encryption operation.

If the user presses Enter instead of typing `DELETE`, the original source is
retained and the application explicitly reports that it was preserved.

### Deletion is not secure erasure

Deleting a file removes its directory entry. It does not guarantee physical
erasure of every copy, especially on:

* SSDs and flash storage with wear leveling;
* journaled filesystems;
* copy-on-write filesystems and snapshots;
* backups, sync clients, and remote replicas;
* filesystem metadata and slack space.

Use full-disk encryption and a threat-appropriate sanitization procedure if
physical media recovery is in scope.

---

## 20. Common errors and troubleshooting

### `ModuleNotFoundError: No module named 'cryptography'`

Install the dependencies with the interpreter that will run the application.

Windows:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Linux:

```bash
source .venv/bin/activate
python -m pip install -r requirements.txt
```

### `python` or `python3` command not found

On Windows, use the Python launcher:

```powershell
py -3.13 --version
```

On Debian/Ubuntu/Kali, install Python, venv, and pip:

```bash
sudo apt install -y python3 python3-venv python3-pip
```

### `No module named venv` or virtual environment creation fails

On Debian/Ubuntu, install the distribution's virtual-environment package:

```bash
sudo apt install -y python3-venv
```

On Windows, recreate the environment with the tested launcher:

```powershell
py -3.13 -m venv .venv
```

### Invalid menu selection

Only the displayed numbers are valid for each menu. The application re-prompts
after an invalid choice; it does not execute an unintended operation. For
example, the main menu accepts `1`-`4`, and two-choice menus accept `0`, `1`,
or `2` where `0` means Back.

### Invalid input path

The path must exist, be readable, and be the expected object type (regular
file, folder, encrypted container, or Recovery Key file). Symlinks are rejected
for source and container inputs. Use the real path, check permissions, and try
again.

### `Permission denied` when writing outputs

On Linux, check ownership and permissions of the project directory:

```bash
ls -ld <project-directory>
```

On Windows, inspect the folder permissions from PowerShell:

```powershell
Get-Acl . | Format-List
```

Run the application as your normal user. Do not run it with `sudo` or an
elevated shell merely to work around a directory ownership problem.

### `Not a CIPHER STRIKE container`

The selected file does not begin with the expected format magic or has a
malformed header. Confirm that the path points to a `.csafe` file generated by
this application.

### `Unsupported CIPHER STRIKE format version`

The container was created by an incompatible format version. This release
implements format version 1.

### `Decryption failed: ...`

The password or Recovery Key may be wrong, or the container may be corrupted or
modified. Restore a known-good copy of the container and retry with the correct
recovery material. Do not edit `.csafe` files.

### `The selected container is a folder container`

You selected `DECRYPT FILE` for a folder container (or the reverse). Return to
the decryption menu and choose the matching option.

### `An output already exists` / overwrite prompt

Encryption chooses a new unique artifact stem automatically. Decryption asks
before replacing a restored file or folder. Answer `y` to replace it or `n` to
preserve the existing output. Declining does not affect the encrypted input.

### `Invalid password length` or an invalid Y/N prompt

Password length must be a whole number from 1 to 64. Y/N questions accept only
Y, N, or Enter. The prompt repeats rather than silently using an invalid value.

### `NO CANDIDATES MATCHED THE REQUESTED LENGTH RANGE`

The profile and enabled transformations did not produce any candidate inside
the chosen 8-32 character range. No wordlist file was written. Add profile data,
enable an appropriate transformation, or widen the length range.

### Wordlist output filename is rejected

Wordlists must be saved directly inside `outputs/`. Enter only a filename, not
`../file`, an absolute path, or a path containing `/` or `\`.

### `Source file changed` or `Source folder changed`

The source was modified during processing or before deletion. The operation
fails safely and preserves the source. Avoid editing files while encryption is
running; rerun the encryption with a stable source.

### Folder encryption reports symbolic links or special files

CIPHER STRIKE does not follow symlinks and does not silently omit unsupported
objects. Remove or replace the unsupported entries, or encrypt them separately
as regular files. Review the paths listed in the error.

### Colour does not appear

Colours are disabled automatically when output is redirected or `NO_COLOR` is
set. They can be disabled explicitly:

```bash
export NO_COLOR=1
```

To force colour in a compatible terminal:

```bash
export CIPHERSTRIKE_COLOR=always
```

To force colour off:

```bash
export CIPHERSTRIKE_COLOR=never
```

### Banner characters look wrong

Use a UTF-8 locale and a UTF-8-capable terminal, for example:

```bash
export LANG=C.UTF-8
```

### `Hashcat was not found`

Install official Hashcat from <https://hashcat.net/hashcat/> or point
CIPHER STRIKE to the executable:

```bash
export CIPHERSTRIKE_HASHCAT=/opt/hashcat/hashcat
```

On PowerShell:

```powershell
$env:CIPHERSTRIKE_HASHCAT = "C:\Tools\hashcat\hashcat.exe"
```

Verify with `hashcat --version` and `hashcat -I`.

### `The installed Hashcat version does not support this mode`

The selected mode number is absent from `hashcat -hh`, or the mode name does not
match. Update Hashcat or choose a mode that the installed build lists. CIPHER
STRIKE does not guess a substitute mode. New modes such as PBKDF2 40024-series,
Django 40022, and MSSQL 2025 require a Hashcat build that lists them.

### `Hashcat could not initialize a supported device/backend`

Hashcat is installed but no OpenCL/CUDA/HIP/Metal device is available. Run
`hashcat -I` and follow Hashcat's official backend guidance for your system.
CIPHER STRIKE deliberately does not use `--force` or modify drivers/GPU
configuration.

### `Could not verify Hashcat output`

Hashcat ended without a parseable outfile or completion status. This is treated
as an operational failure, not as "password not found." Check the Hashcat
diagnostic detail and rerun after resolving the engine/backend issue.

### `No space left on device`

Encryption requires space for the encrypted container. Folder restoration
requires additional space for the temporary archive and extracted tree. Free
space and rerun. Failed staging data is cleaned up where the filesystem allows
it.

### Argon2 or memory errors

The default password KDF uses about 64 MiB of memory per derivation. Decryption
also honors the parameters recorded in the authenticated header. Resource
limits on the host may prevent derivation; run on a host with adequate memory.

---

## 21. Security limitations, backups, and recovery warnings

* **Losing both recovery methods is permanent.** There is no hidden master
  password, no backdoor, and no undocumented recovery route.
* **A stolen Recovery Key is enough to decrypt.** It is a secret, not a public
  certificate.
* **A stolen password is enough to decrypt.**
* **Storing all three artifacts together is risky.** Prefer separate offline
  copies for the password and Recovery Key.
* **The header is authenticated, not encrypted.** The original filename, kind,
  creation time, and KDF parameters are visible to someone holding the
  container. File contents and folder member names are encrypted.
* **The password file is plaintext.** Restrict access to `outputs/` and your
  backups.
* **Decrypting creates plaintext.** Restored data in `outputs/` has the same
  exposure as any other plaintext file. Delete it securely according to your
  policy when no longer needed.
* **The application cannot protect a compromised endpoint.** Malware,
  keyloggers, memory inspection, terminal logging, shell history, screenshots,
  and backups can capture secrets.
* **No secure erase.** Ordinary deletion is not a sanitization guarantee.
* **No formal audit.** This is an implementation suitable for careful use, not
  a claim of being unbreakable or independently audited.
* **Metadata change detection before deletion is not a full content audit.**
  Use stable sources and do not edit files during the operation.
* **The folder archive format is TAR, not a compressed archive.** Large folders
  produce correspondingly large containers.
* **No compression or deduplication.** Storage overhead is expected.
* **No protection from denial of service by a malicious authenticated
  container.** A container you choose to decrypt may consume disk space while
  being restored.
* **KDF parameters are bounded on read** to limit resource exhaustion from
  malformed headers, but resource limits still depend on the host.
* **Wordlist output contains supplied profile data.** Treat generated wordlists
  as sensitive. Use synthetic lab profiles and approved datasets only, and do
  not use wordlists to attack accounts you do not own or have written
  authorization to test.
* **The wordlist transformations are CIPHER STRIKE's own design, not CUPP's
  exact algorithm.** The two programs can produce different candidates and
  counts from similar input.
* **Platform coverage is limited.** The application was exercised on Windows 11
  with Python 3.13 only. Linux code paths and macOS were not executed in this
  review.
* **Hashcat recovery is unverified here.** Hashcat was not installed in the
  review environment. The interface, mode mapping, command construction, and
  result parsing are unit/mock tested, but no real hash was cracked during this
  review.
* **No performance claim.** CIPHER STRIKE adds a guided interface around
  Hashcat; it does not claim to be faster, lighter, or more memory-efficient
  than Hashcat. Recovery speed depends on Hashcat, the selected mode, the
  wordlist, and the hardware backend.
* **Windows output permissions are not ACL-hardened by the application.** On
  Windows, `os.chmod(0o600/0o700)` is not equivalent to an NTFS owner-only ACL.
  Restrict the `outputs/` folder with NTFS permissions and protect backups.
* **Hashcat temporary files can contain sensitive data.** The integration uses
  a temporary directory and cleans it up on normal completion and cancellation,
  but a failed cleanup or a forcibly killed process can leave temporary hash or
  output files behind. Inspect the system temporary directory if this occurs.
* **No independent security audit.** Passing tests is not an audit and is not a
  guarantee that the application is free of defects.

### Backup recommendations

1. Keep at least two copies of each container.
2. Store the password separately from the Recovery Key.
3. Keep at least one copy offline or on a different system.
4. Test restoration before relying on a backup.
5. Record which recovery method belongs to which container without storing the
   secret itself in the same place.
6. Use full-disk or volume encryption in addition to application-level
   encryption when appropriate.

---

## 22. Project structure and responsibilities

```text
CIPHER-STRIKE/
├── cipherstrike.py          # Entry point, menu flow, confirmation policy
├── requirements.txt         # Constrained dependencies
├── README.md                # This documentation
├── .gitignore               # Excludes secrets, outputs, caches, environments
├── LICENSE                  # MIT license
├── cipherstrike/
│   ├── __init__.py          # Package metadata
│   ├── ui.py                # Banner, colours, menus, prompts, result screens
│   ├── encrypt.py           # File/folder encryption workflows, staging, deletion gate
│   ├── decrypt.py           # Decryption, overwrite handling, safe TAR restoration
│   ├── crypto.py            # AES-GCM, Argon2id, HKDF, format, manifest, verification
│   ├── passwordgen.py       # Strong-password generation and private TXT saving
│   ├── wordlist.py          # Lab-profile validation and candidate engine
│   ├── output.py            # Safe filename resolution and atomic text writing
│   ├── hashcat_modes.py     # Hash-type registry, validators, auto-detection
│   ├── hashcat.py           # Official Hashcat process integration
│   ├── hashcli.py           # Hash recovery menus and result reporting
│   └── utils.py             # Path validation, permissions, snapshots, cleanup
├── tests/
│   ├── conftest.py
│   ├── test_cli.py          # Menu navigation and end-to-end generator flows
│   ├── test_crypto.py
│   ├── test_hashcat_cli.py  # Hash menus, prompts, results, cancellation
│   ├── test_hashcat_engine.py
│   ├── test_hashcat_integration.py
│   ├── test_hashcat_modes.py
│   ├── test_passwordgen.py
│   ├── test_ui.py
│   ├── test_utils.py
│   └── test_wordlist.py
└── outputs/                 # Runtime output directory (ignored by Git)
```

`hashcat.py` and `hashcat_modes.py` are intentionally separate: mode metadata
and syntax validation are testable without the engine, while subprocess and
result parsing stay isolated from the interactive CLI.

`wordlist.py` is deliberately separate from `passwordgen.py`: profile-driven
candidate generation is not the same operation as generating a random
credential, and neither path shares cryptographic key material with the
encryption workflows.

No implementation code is intentionally concentrated in `cipherstrike.py`;
that file only coordinates the UI and workflows.

---

## 23. Testing

### Running the suite

Windows (the path used for the release review):

```powershell
.\.venv\Scripts\python.exe -m pytest -q -rs
```

Linux (unverified):

```bash
source .venv/bin/activate
python -m pytest -q -rs
```

The suite uses temporary directories and does not touch real user data. It
covers:

* password character-class requirements;
* file round-trips with password and Recovery Key;
* empty files and multi-chunk files;
* nested folder round-trips with empty directories and binary content;
* wrong passwords and unrelated Recovery Keys;
* modified ciphertext, modified headers, and truncated containers;
* corrupted Recovery Key files;
* strict menu validation;
* missing and wrong-type paths;
* symbolic-link rejection;
* TAR path traversal, absolute paths, and symlink members;
* unique output naming and overwrite refusal;
* source preservation when deletion is declined or verification fails;
* staging cleanup on an interrupted operation;
* private POSIX permissions where supported;
* strong-password length and category validation;
* exact generated length, `secrets` use, and private password file saving;
* password-file overwrite refusal and overwrite approval;
* profile-field date, phone, email, username, year, keyword, and separator
  validation;
* blank profile fields never becoming candidates;
* enabled/disabled separator, special-character, numeric, Leet, and year
  transformations;
* deduplication and minimum/maximum output-length filtering;
* honest empty-result handling;
* one-candidate-per-line wordlist output and read-back counting;
* output-directory creation and wordlist overwrite refusal;
* file-writing failure reporting for both generators;
* hash-mode registry values and one official example per registered type;
* syntax validation and ambiguity reporting for auto-detection;
* mixed/unsupported hash file rejection;
* Hashcat command construction, `$HEX[]` decoding, `CRLF` handling, backend
  errors, found/no-match/failure/cancellation states;
* hash-recovery menu navigation and exact result/error messages;
* `[0]` navigation in the new and existing menus.

Tests use reduced Argon2id parameters for speed. Production code uses the
documented default parameters unless a caller explicitly supplies different
valid parameters.

Real Hashcat integration tests are included but **skip automatically when the
Hashcat executable or a supported device backend is unavailable**. The
offline/unit tests use controlled fake processes and do not claim that real
Hashcat recovery was executed. To run real integration tests, install official
Hashcat from <https://hashcat.net/hashcat/> and ensure `hashcat -I` reports a
usable backend.

### Testing note for this review

The release review was performed on **Windows 11 Pro 10.0.26200 (64-bit)** with
**Python 3.13.0**, in a fresh project-local `.venv`. The exact dependency set
was installed and `python -m pip check` reported no broken requirements.

Observed test command and result:

```text
.\.venv\Scripts\python.exe -m pytest -q -rs
162 passed, 5 skipped
```

Skipped tests and reasons:

* three symbolic-link tests skipped because symbolic-link creation was not
  available in that Windows environment;
* one POSIX permission-bits test skipped because Windows does not provide POSIX
  permission semantics;
* one real Hashcat integration test skipped because Hashcat was not installed.

These are actual results from the release review, not the earlier historical
baseline. The unit and mock tests do not establish real Hashcat cracking.

Additional checks performed:

* `python -m pip check` — no broken requirements.
* application startup and main-menu rendering — passed;
* synthetic file encryption/decryption via both password and Recovery Key —
  passed;
* synthetic nested-folder encryption/restoration — passed;
* strong-password generation and private TXT saving — passed;
* synthetic wordlist generation, writing, and actual saved-line verification —
  passed.

Real Hashcat execution remains unverified on this host. To test it on a machine
where Hashcat is installed and `hashcat -I` reports a usable backend:

```powershell
.\.venv\Scripts\python.exe -m pytest -q -rs tests/test_hashcat_integration.py
```

### Development note

CIPHER STRIKE was tested on Windows 11 Pro with Python 3.13. Linux and macOS
were not executed in this review. The Linux instructions are provided for
Debian/Ubuntu-style systems but remain unverified. Do not assume Python 3.15
support because that interpreter happens to be installed on this machine; only
Python 3.13 was validated.

Hashcat was not installed during the review, so real-engine integration tests
were skipped. Unit tests validated the mode registry, official example syntax,
command construction, and output parsing; those tests do not constitute real
cracking verification.

---

## 24. Responsible use and license

### 24.1 License

CIPHER STRIKE is released under the **MIT License**. The repository includes a
`LICENSE` file with the full MIT text and the copyright notice. This license
was already present and was not changed during this review.

### 24.2 Responsible use

Use CIPHER STRIKE only with data you are authorized to protect and process.
You are responsible for safeguarding recovery information, complying with
applicable law, and maintaining tested backups. Do not use the application to
conceal evidence, interfere with investigations, or process data without
authorization.

The target-wordlist feature is for authorized security testing with synthetic
lab profiles, owned test accounts, and approved datasets. Do not use another
person's private identifiers or personal information to construct a
credential-guessing list for that person's accounts. Wordlists generated from a
profile contain that profile's data and must be protected accordingly.

Hash recovery is restricted to offline recovery of hashes you own or are
explicitly authorized to test. CIPHER STRIKE does not collect credentials,
connect to target systems, perform network login attempts, or extract hashes
from other systems. Hashcat is a separate third-party engine; review and comply
with its license and your authorization scope.

See [LICENSE](LICENSE) for the full license text. No warranty is provided. The
authors are not responsible for data loss, unauthorized access, or damages
resulting from use of this software.

---

## 25. Password generator and wordlist generator

### 25.1 Menu flow

`[4] PASSWORD GENERATOR` opens:

```text
WELCOME TO PASSWORD GENERATOR

[1] GENERATE STRONG PASSWORD
[2] GENERATE TARGET WORDLIST
[0] BACK TO MAIN MENU

SELECT OPTION:
```

Invalid values repeat this menu with a red error. `0` returns to the main menu.
After either generator flow completes, the application returns to this
submenu.

### 25.2 Strong password generator

The questions, in order, are:

```text
HOW MANY CHARACTERS IN PASSWORD YOU WANT? (MAX. 64):
INCLUDE UPPERCASE LETTERS? (Y/N):
INCLUDE LOWERCASE LETTERS? (Y/N):
INCLUDE NUMBERS? (Y/N):
INCLUDE SPECIAL CHARACTERS? (Y/N):
```

Rules:

* Length must be a whole number from `1` through `64`.
* Empty, non-numeric, negative, zero, fractional, and out-of-range answers are
  rejected and the length question repeats.
* Y/N answers accept only `Y`, `N`, or Enter. Enter means `N`; invalid nonempty
  answers repeat the same question.
* At least one category must be enabled. Otherwise the category questions
  repeat.
* Generation uses Python's `secrets` module.
* The result has exactly the requested length.
* When the length allows it, at least one character from every enabled category
  is guaranteed.
* The final order is shuffled with `secrets.SystemRandom`.

Example result screen:

```text
STRONG PASSWORD GENERATED SUCCESSFULLY
Generated Password: <generated password>
Length: 20
Character categories: uppercase, lowercase, numbers, special characters
```

The application then asks whether to save the password. If yes, it requests a
filename, appends `.txt` when no extension is supplied, and saves the file
inside `outputs/`. Existing files are never overwritten without explicit `y`
confirmation. The success line appears only after the file has been written and
read back successfully.

Password files use UTF-8 with `\n` newlines and contain a warning that the
password is stored in plaintext. They are created with mode `0600` on POSIX
filesystems.

### 25.3 Target wordlist questionnaire

The profile questions appear in this order:

1. First Name
2. Surname
3. Nickname
4. Birthdate (DDMMYYYY)
5. Partner's Name
6. Partner's Nickname
7. Partner's Birthdate (DDMMYYYY)
8. Child's Name
9. Child's Nickname
10. Child's Birthdate (DDMMYYYY)
11. Pet's Name
12. Company Name
13. Add Keywords?
14. Lab Profile Phone Number
15. Lab Profile Email Address
16. Lab Profile Username
17. Lab Profile City
18. Lab Profile Country
19. Important Year
20. Custom Separators

Optional fields may be left blank. Blank fields are never converted into words
or placeholder values. If `Add Keywords?` is `Y`, the application asks for
comma-separated keywords and trims surrounding whitespace; otherwise it does not
ask for keywords.

Validation:

* Birthdates, partner birthdates, and child birthdates must be real `DDMMYYYY`
  calendar dates with years from 1900 through the current year.
* Important Year must be four digits from 1900 through 2100.
* Phone numbers accept digits, spaces, `+`, `-`, parentheses, and dots, and must
  contain 7-15 digits.
* E-mail addresses must have a basic `local@domain.tld` shape.
* Usernames must be 3-32 characters, start with a letter or digit, and use only
  letters, digits, dot, underscore, or hyphen.
* Names, places, company names, and keywords reject control characters and path
  separators. Text fields are limited to 64 characters, up to 20 keywords may
  be supplied, and each keyword is limited to 32 characters.
* Custom separators are comma-separated punctuation tokens of 1-3 characters
  each. Letters, digits, whitespace, and more than five separators are
  rejected.
* At least one profile value, date, or keyword must be supplied.

The questionnaire does **not** ask for a target website/domain, favorite hobby,
favorite brand, or extra number-pattern questions.

### 25.4 Transformation options

After the profile, the application asks:

```text
SPECIAL CHARACTERS? (Y/N):
RANDOM NUMBERS? (Y/N):
LEET MODE? (Y/N):
INCLUDE CUSTOM SEPARATORS? (Y/N):
```

Y enables the transformation, N disables it, and Enter uses the documented
default of disabled. Invalid nonempty answers repeat the same question. If
custom separators are enabled but the profile supplied no separator values, the
application asks for at least one separator instead of inventing defaults.

Documented transformation semantics:

* **Case variants:** each supplied text field can contribute original,
  lowercase, title-case, uppercase, and compact forms.
* **Identity combinations:** two-part ordered combinations from first name,
  surname, nickname, partner name/nickname, child name/nickname, pet, company,
  and lab username. Direct concatenation is always considered. Custom separator
  combinations are added only when the option is enabled and separator values
  were supplied.
* **Dates and years:** valid dates contribute `DDMMYYYY`, short-date, year, and
  related forms. Years from supplied dates and the important year are also used
  as suffixes on seed candidates.
* **Special characters:** when enabled, one suffix per special character from
  `!@#$%^&*` is added to each seed candidate. Combinations of multiple special
  characters are not generated.
* **Random numbers:** despite the CUPP-inspired label, CIPHER STRIKE uses a
  deterministic, bounded suffix range `0`-`99` rather than an unbounded random
  expansion. This keeps results reproducible and prevents accidental runaway
  output.
* **Leet mode:** translates `a i e t o s g z` to `4 1 3 7 0 5 9 2`, preserving
  the original candidates and adding transformed variants.
* **Deduplication:** every candidate is held in a set keyed by exact text, so
  duplicates are removed regardless of which rule produced them.
* **Length filtering:** after all transformations, candidates shorter than the
  minimum or longer than the maximum are removed.

Each optional suffix family is applied to the same seed set rather than
multiplying every family by every other family. This avoids an unnecessary
cross-product of numeric suffixes, special characters, and Leet variants while
still using all supplied data.

These are CIPHER STRIKE's own documented rules, not a claim of reproducing
CUPP's exact output. CUPP builds larger two- and three-component date
cartesian products, uses a larger configurable year/special-character set, and
holds multiple intermediate lists. CIPHER STRIKE deliberately uses a smaller
bounded engine and verifies its own output.

### 25.5 Final settings and output

The application asks:

```text
MINIMUM OUTPUT LENGTH:
MAXIMUM OUTPUT LENGTH:
OUTPUT FILE NAME:
```

* Minimum is at least `8`; maximum is at most `32`.
* The minimum cannot exceed the maximum.
* `.txt` is appended when the filename has no extension.
* The file is saved directly inside `outputs/`; directory traversal is rejected.
* Existing files are never overwritten without explicit confirmation.
* There is no `MAXIMUM WORDLIST SIZE` question and no arbitrary final candidate
  count.
* If no candidate survives generation and filtering, **no file is written** and
  the application says so.

After writing, the application reopens the file, checks that each line is a
unique nonempty candidate, compares the contents with the generated set, and
reports the line count from the file:

```text
[+] WORDLIST GENERATED SUCCESSFULLY
[+] OUTPUT FILE: outputs/example.txt
[+] UNIQUE CANDIDATES WRITTEN: <actual verified count>
[+] FORMAT: ONE CANDIDATE PER LINE
```

The count is not estimated and not hardcoded. It is the number of lines read
back from the successfully written file.

### 25.6 CUPP reference review

The CUPP source (`cupp.py`) and configuration were reviewed for design
concepts. Relevant observations:

* CUPP's interactive flow asks a required first name, optional surname,
  nickname, dates, partner/child/pet/company fields, keywords, special
  characters, random numbers, and Leet mode.
* It decomposes dates into day, month, two-digit year, three-digit year, and
  four-digit year fragments, then creates one-, two-, and three-component date
  combinations.
* It creates lower/title variants, reversed names, name/date/year combinations,
  custom `_` combinations, and optional special-character/numbers suffixes.
* It deduplicates with `dict.fromkeys` while preserving first-seen order, then
  filters by strict min/max length and writes a line-separated file.
* It reopens the output to count lines, and its configuration controls years,
  special characters, numeric range, and length thresholds.
* Its implementation builds large intermediate lists; CIPHER STRIKE does not
  copy that code or architecture.

CIPHER STRIKE implements a separate, bounded engine with explicit limits on
profile fields, keywords, and separators. It uses the supplied data and
enabled rules, not a pretrained dictionary or arbitrary name pool.

---

## 26. Password hash recovery with Hashcat

### 26.1 Scope and status

`[3] CRACK PASSWORD HASH` is for authorized offline recovery of hashes you own
or are explicitly authorized to test. It does not perform network
authentication, credential collection, or hash extraction. The official
Hashcat executable is the only recovery engine; CIPHER STRIKE contains no
built-in cracker.

The mode registry is aligned with the official Hashcat 8.0.0 hash-mode table.
Before every attempt, CIPHER STRIKE runs `hashcat -hh`, checks that the selected
mode number exists, and checks that its mode name matches the registry. A
different or older Hashcat build that lacks a mode is reported as unsupported
rather than attempted with a guessed mode. Hashcat 8.0.0 is the reference
version for the numbers below.

Verification levels used below:

| Evidence level | Meaning |
|---|---|
| Mode + syntax tested | The mode number was checked against the official Hashcat 8.0.0 reference, and the official example syntax was exercised by unit tests. |
| Real recovery tested | A real Hashcat executable recovered a password from the example hash on a machine with a working backend. |
| Unverified | Implemented or documented but not executed in this environment. |

No entry below has **real recovery tested** evidence in this environment
because Hashcat was not installed. The 51 mode/format registrations are
mode-mapped and syntax-tested only. This distinction matters: a correct mode
number and accepted syntax do not prove that a password is recoverable from a
particular wordlist or hardware configuration.

> Verification status in this development environment: Hashcat was **not
> installed**, so real Hashcat recovery tests were **skipped**. Mode mappings,
> syntax validators, command construction, fake-process behavior, and result
> parsing were tested. Do not treat those tests as proof that real cracking
> succeeded on this host.

### 26.2 Installing and configuring Hashcat

Install Hashcat only from the official project:

* Website: <https://hashcat.net/hashcat/>
* Source: <https://github.com/hashcat/hashcat>
* Example hashes and modes: <https://hashcat.net/wiki/doku.php?id=example_hashes>

CIPHER STRIKE does not download, install, or execute an unconfigured Hashcat
binary. It resolves the executable in this order:

1. `CIPHERSTRIKE_HASHCAT` environment variable.
2. `HASHCAT_PATH` environment variable.
3. `hashcat` / `hashcat.exe` on `PATH`.

Linux shell example (environment unverified):

```bash
export CIPHERSTRIKE_HASHCAT=/opt/hashcat/hashcat
```

Windows PowerShell example:

```powershell
$env:CIPHERSTRIKE_HASHCAT = "C:\Tools\hashcat\hashcat.exe"
```

Hashcat on Linux is **not installed by CIPHER STRIKE or by this project's
Python dependencies**. Obtain it from the official Hashcat website/source, or
from your distribution only after checking the packaged version. Distribution
packages may be older than the upstream release and may require additional
OpenCL/CUDA/HIP runtime packages. Those backend packages and drivers are
outside this project's scope. Verify the result with:

```bash
hashcat --version
hashcat -I
```

Do not assume that a distribution package provides the same mode set as
Hashcat 8.0.0; CIPHER STRIKE checks the installed mode table at runtime.

CIPHER STRIKE additionally checks `hashcat -hh` for the selected mode and
`hashcat -I` for a usable device/backend. It never adds `--force`, changes GPU
settings, installs drivers, or promises GPU acceleration. CPU-only or
GPU-accelerated operation depends entirely on the installed Hashcat build and
host configuration.

### 26.3 Menu flow

```text
[3] CRACK PASSWORD HASH

[1] Raw Hashes
[2] Password Storage
[3] Windows Authentication
[4] Application Hashes
[5] Auto Detect Hash Type
[0] Back

SELECT:
```

Every submenu accepts `0` to return to its parent. The recovery workflow then
asks for:

```text
HASH FILE PATH:
WORDLIST FILE PATH:
```

Only a straight dictionary attack (`hashcat -a 0 -m <mode>`) is used in this
release. The user does not need to know or type Hashcat mode numbers or flags.
`0` at a path prompt returns to the parent menu.

Hash files are read as UTF-8 text with blank lines ignored and a leading BOM
tolerated. Every nonempty line is validated against the selected format before
Hashcat starts. A single invalid line rejects the whole file rather than silently
rewriting or skipping it. Username-prefixed hash lines are not supported in this
release; provide the hash syntax expected by Hashcat.

Wordlists are validated as existing, readable, nonempty regular files. They are
passed directly to Hashcat and are never loaded into Python memory.

### 26.4 Registered hash variants and verification status

The following modes are registered against official Hashcat 8.0.0
documentation. Actual availability is checked at runtime from `hashcat -hh`.
All entries are at the "Mode + syntax tested" evidence level only; no entry has
real recovery-tested evidence in this environment because Hashcat was absent.

**Raw hashes**

| Variant | Mode | Input |
|---|---:|---|
| MD5 | 0 | 32 hex |
| SHA1 | 100 | 40 hex |
| SHA224 | 1300 | 56 hex |
| SHA256 | 1400 | 64 hex |
| SHA384 | 10800 | 96 hex |
| SHA512 | 1700 | 128 hex |
| SHA3-224 | 17300 | 56 hex |
| SHA3-256 | 17400 | 64 hex |
| SHA3-384 | 17500 | 96 hex |
| SHA3-512 | 17600 | 128 hex |
| RIPEMD-160 | 6000 | 40 hex |
| BLAKE2b-512 | 600 | `$BLAKE2$` + 128 hex |
| BLAKE2b-256 | 34800 | `$BLAKE2$` + 64 hex |
| BLAKE2s-256 | 31000 | `$BLAKE2$` + 64 hex |

**Password storage**

| Variant | Mode | Input |
|---|---:|---|
| bcrypt | 3200 | `$2a$`, `$2b$`, `$2x$`, or `$2y$` modular crypt string |
| PBKDF2-HMAC-SHA256 | 40024 | `sha256:<iterations>:<base64 salt>:<base64 hash>` |
| PBKDF2-HMAC-MD5 | 40031 | `md5:<iterations>:<base64 salt>:<base64 hash>` |
| PBKDF2-HMAC-SHA1 | 40032 | `sha1:<iterations>:<base64 salt>:<base64 hash>` |
| PBKDF2-HMAC-SHA512 | 40034 | `sha512:<iterations>:<base64 salt>:<base64 hash>` |
| scrypt (Hashcat format) | 8900 | `SCRYPT:<N>:<r>:<p>:<base64 salt>:<base64 hash>` |
| scryptcrypt / scrypt (Unix) | 36300 | `$7$<setting>$<hash>` |
| Argon2id | 34000 | `$argon2id$v=...$m=...,t=...,p=...$<salt>$<hash>` |
| phpass | 400 | `$P$` or `$H$` portable hash |
| yescrypt | 36100 | `$y$<setting>$<salt>$<hash>` |

PBKDF2 variants are not interchangeable: the algorithm prefix and mode must
match. Only Argon2id is registered here; Argon2i/Argon2d are not advertised as
the same format.

**Windows authentication**

| Variant | Mode | Input |
|---|---:|---|
| NTLM | 1000 | 32 hex |
| NetNTLMv1 / ESS | 5500 | `<user>::<domain>:<LM>:<NT>:<challenge>` |
| NetNTLMv2 | 5600 | `<user>::<domain>:<challenge>:<HMAC>:<blob>` |
| Kerberos 5 etype 23 AS-REQ Pre-Auth | 7500 | `$krb5pa$23$...` |
| Kerberos 5 etype 23 TGS-REP | 13100 | `$krb5tgs$23$...` |
| Kerberos 5 etype 23 AS-REP | 18200 | `$krb5asrep$23$...` |
| Kerberos 5 etype 17 TGS-REP | 19600 | `$krb5tgs$17$...` |
| Kerberos 5 etype 18 TGS-REP | 19700 | `$krb5tgs$18$...` |
| Kerberos 5 etype 17 AS-REP | 32100 | `$krb5asrep$17$...` |
| Kerberos 5 etype 18 AS-REP | 32200 | `$krb5asrep$18$...` |

These are challenge-response/ticket formats, not ordinary NTLM hashes. They
require the exact specialized syntax shown by the Hashcat examples and are not
interchangeable with one another.

**Application and database hashes**

| Variant | Mode | Input |
|---|---:|---|
| WordPress phpass | 400 | `$P$` / `$H$` portable hash |
| Django PBKDF2-SHA256 | 40022 | `pbkdf2_sha256$<iterations>$<salt>$<base64 hash>` |
| MySQL323 | 200 | 16 hex |
| MySQL4.1/MySQL5 | 300 | 40 hex |
| MySQL `$A$` | 7401 | `$mysql$A$<cost>*<salt>*<hash>` |
| PostgreSQL MD5 | 12 | `<32-hex MD5>$<salt>` |
| MSSQL 2000 | 131 | `0x0100` + 88 hex |
| MSSQL 2005 | 132 | `0x0100` + 48 hex |
| MSSQL 2012/2014 | 1731 | `0x0200` + 136 hex |
| MSSQL 2025 | 36601 | `0x0300` + 136 hex |
| Cisco-IOS `$1$` | 500 | `$1$<salt>$<hash>` |
| Cisco-IOS type 4 | 5700 | 43 Base64 characters |
| Cisco-IOS `$9$` | 9300 | `$9$<salt>$<hash>` |
| LDAP `{SHA}` | 101 | `{SHA}<Base64>` |
| LDAP `{SSHA}` | 111 | `{SSHA}<Base64>` |
| LDAP `{SSHA256}` | 1411 | `{SSHA256}<Base64>` |
| LDAP `{SSHA512}` | 1711 | `{SSHA512}<Base64>` |

Application formats are version-specific. A format not listed here is not
advertised as supported.

### 26.5 Synthetic input examples

For a local MD5 test, use the official Hashcat example whose plaintext is
`hashcat`:

`hash.txt`:

```text
8743b52063cd84097a65d1633f5c74f5
```

`words.txt`:

```text
definitely-wrong
hashcat
```

Then choose `[3] CRACK PASSWORD HASH` → `[1] Raw Hashes` → `[1] MD5`, supply
the two file paths, and select the installed `hashcat` binary through `PATH` or
`CIPHERSTRIKE_HASHCAT`. A matching result should display:

```text
[+] PASSWORD FOUND: hashcat
```

A wordlist containing only `definitely-wrong` should complete with the no-match
messages, provided Hashcat actually ran to exhaustion.

The official example-hash page is the source of truth for synthetic examples
and exact syntax:
<https://hashcat.net/wiki/doku.php?id=example_hashes>. Do not use real
credentials or another person's private data as test input.

### 26.6 Automated detection

`[5] Auto Detect Hash Type` reads the hash file and applies the registered
syntax validators to every line. It does not select a mode from hash length
alone:

* 32 hex returns both MD5 and NTLM as candidates.
* 40 hex returns SHA1, RIPEMD-160, and MySQL4.1/MySQL5.
* 56/64/96/128 hex returns the corresponding SHA2 and SHA3 candidates.
* 64-hex `$BLAKE2$` values return BLAKE2b-256 and BLAKE2s-256.
* Prefix/signature formats such as bcrypt, Argon2id, phpass, Django, NetNTLM,
  Kerberos, MySQL `$A$`, MSSQL, Cisco, and LDAP return their specific type.

If more than one candidate remains, CIPHER STRIKE lists the candidates and asks
the user to choose. If a file contains lines with different candidate sets, the
attempt is rejected as mixed; the user must supply a compatible file or choose
an explicit hash type. Mixed files are never silently split or mislabeled.

### 26.7 Recovery execution and results

For each validated hash line, CIPHER STRIKE creates a private temporary working
directory, writes a one-line hash file, and invokes Hashcat with an argument
list:

```text
hashcat -m <verified-mode> -a 0 --restore-disable --logfile-disable
        --potfile-path <temp-pot> --outfile <temp-out> --outfile-format 2
        --status --status-timer 5 <temp-hash> <wordlist>
```

Paths containing spaces are passed as single arguments. No shell concatenation
is used. The subprocess output is filtered to status/progress and error lines;
raw candidate passwords are not printed from diagnostic output. Recovered
plaintext comes from Hashcat's outfile, with `$HEX[]` decoding for escaped
plaintext and support for Windows `CRLF` output.

If a password is recovered:

```text
[+] PASSWORD FOUND: <recovered-password>
Hash: <corresponding-hash>
```

If the search completes with no match:

```text
[-] PASSWORD NOT FOUND
[-] No password in the supplied wordlist matched the hash.
```

A process that is interrupted, aborted, failed to initialize a backend, or
returned output that cannot be parsed is reported as a failure or cancellation,
never as a definitive no-match. A multi-hash file is processed one hash at a
time so each recovered password is associated with the correct hash and the
summary reports recovered versus unresolved counts.

### 26.8 Errors

* Missing hash file:

  ```text
  [!] ERROR: Hash file not found.
  [!] Please check the file path and try again.
  ```

* Missing wordlist:

  ```text
  [!] ERROR: Wordlist file not found.
  [!] Please enter a valid wordlist path.
  ```

* Empty hash file and empty wordlist have separate messages.
* Invalid selected-format syntax:

  ```text
  [!] ERROR: Invalid or unsupported hash format.
  [!] Please verify the selected hash type and input file.
  ```

* Missing Hashcat:

  ```text
  [!] ERROR: Hashcat was not found.
  [!] Install Hashcat from https://hashcat.net/hashcat/
  ```

* Unsupported mode, Hashcat startup failure, no usable device/backend, invalid
  wordlist, output parsing failure, and cancellation all produce explicit
  errors without a false success or false no-match.

### 26.9 Limitations

* Dictionary/straight attack only (`-a 0`). Rules, masks, combinator, hybrid,
  and other Hashcat attack modes are not exposed yet.
* One hash per Hashcat process. Multi-hash files are supported but slower than a
  single batched Hashcat run.
* Username-prefixed hash files and specialized multi-file formats are not
  handled in this release.
* Real Hashcat recovery has not been executed in the development environment
  because Hashcat is not installed there. The included real-engine integration
  test skips with that reason.
* Hardware support and speed depend on the local Hashcat build, drivers, and
  backend. No GPU is promised.
* A password that is not in the supplied wordlist will not be recovered by this
  dictionary attack. That is not proof that the hash is invalid.
* Hashcat 8.0.0 mode numbering is the reference; older builds may lack new
  modes (PBKDF2 40024-series, Django 40022, MSSQL 2025, and others). The runtime
  mode check reports this rather than attempting an incorrect mode.
* WPA/WPA2, archive, document, private-key, full-disk-encryption, and other
  Hashcat formats not listed in section 26.4 are unsupported by the CIPHER
  STRIKE menus. Hashcat may support them natively, but this integration does
  not advertise or select those modes.
* On Windows, POSIX mode/timestamp restoration is best-effort and does not
  preserve POSIX ACLs or ownership.

---

## 27. Roadmap

These are planned improvements, not current functionality:

1. Validate the documented Linux workflow on at least one Debian/Ubuntu
   distribution and one Arch-based distribution, then update the platform table
   with evidence.
2. Run real Hashcat integration tests on a machine with an installed Hashcat
   backend, starting with MD5 and then covering every registered format.
3. Evaluate batching multiple hashes into one Hashcat invocation without losing
   the current per-hash result association guarantees.
4. Evaluate additional Hashcat attack modes (rules, masks, hybrid) behind
   explicit, separately documented workflows.
5. Add a version matrix and packaging guidance once more Python versions and
   platforms have been tested.

No dates or release guarantees are implied.

---

## 28. Contributing and security reports

Contributions should preserve the existing cryptographic container format and
the current CLI behavior unless a change is deliberately reviewed.

Before proposing a change:

1. Run the full test suite on a supported environment.
2. Add or update tests for changed behavior.
3. Do not include real passwords, real hashes, private keys, recovery keys,
   generated `outputs/`, or personal data.
4. Do not weaken assertions or remove security checks to make tests pass.
5. For cryptographic changes, explain compatibility with existing `.csafe`
   containers and add regression tests before changing format behavior.

A public GitHub repository URL, issue tracker, and maintainer contact are not
known yet. Once the repository is published, use its configured issue/PR
workflow. Report suspected security issues through the repository's private
security-reporting channel if one is configured; do not post live secrets or
real user data in a public issue.

---

## 29. Disclaimer

CIPHER STRIKE is provided for legitimate file operations, learning, and
authorized security testing. You are responsible for ensuring that you have
permission to encrypt, decrypt, process, or attempt recovery against every file,
hash, account, and system you use. The authors do not authorize unauthorized
access, credential theft, network attacks, or use against data you do not own
or have explicit permission to test.

Encryption and password recovery are not guarantees. Back up recovery
information, test restoration, and use the software at your own risk.

---

## 30. Appendix A: encrypted-file format version 1

All multi-byte integers in the binary framing are big-endian.

### Outer framing

```text
MAGIC             13 bytes   b"CIPHERSTRIKE\x00"
VERSION            2 bytes   unsigned, currently 1
HEADER_LENGTH      4 bytes   unsigned, maximum 1,048,576
HEADER_JSON        N bytes   UTF-8, compact, sorted-key JSON
HEADER_MAC        32 bytes   HMAC-SHA256
RECORD...                    authenticated payload records
```

The header MAC input is:

```text
MAGIC || VERSION || HEADER_LENGTH || HEADER_JSON
```

The HMAC key is:

```text
HKDF-SHA256(DEK, salt=file_id, info="CIPHERSTRIKE/v1/header-authentication", length=32)
```

### Header fields

| Field | Meaning |
|---|---|
| `format` | `"CIPHER STRIKE"` |
| `version` | `1` |
| `kind` | `"file"` or `"folder"` |
| `original_name` | Authenticated original basename |
| `created_utc` | ISO-8601 creation timestamp |
| `file_id` | 16 random bytes, base64 |
| `nonce_prefix` | 8 random bytes, base64 |
| `chunk_size` | Authenticated chunk size, default 1,048,576 |
| `source_mode` | Original permission bits, filtered to `0777` |
| `source_mtime_ns` | Original modification time in nanoseconds |
| `kdf` | Argon2id parameters |
| `slots.password` | Argon2 salt, GCM nonce, wrapped DEK |
| `slots.recovery` | Recovery identifier, GCM nonce, wrapped DEK |

The plaintext DEK does not appear in the header.

### Password slot

```text
KEK = Argon2id(password, salt, time_cost, memory_cost, parallelism, hash_len=32)
AAD = "CIPHERSTRIKE/v1/slot|" || kind || "|password|" || file_id || "|"
wrapped_dek = AES-256-GCM(KEK, nonce, DEK, AAD)
```

Default Argon2id parameters:

```text
type        = Argon2id
time_cost   = 3
memory_cost = 65536 KiB (64 MiB)
parallelism = 4
hash_len    = 32
salt        = 32 random bytes
```

### Recovery slot

```text
KEK = HKDF-SHA256(recovery_secret,
                  salt=recovery_id,
                  info="CIPHERSTRIKE/v1/recovery-key-encryption",
                  length=32)
AAD = "CIPHERSTRIKE/v1/slot|" || kind || "|recovery|" || file_id || "|" || recovery_id
wrapped_dek = AES-256-GCM(KEK, nonce, DEK, AAD)
```

### Payload records

Each record:

```text
CIPHERTEXT_LENGTH   4 bytes   unsigned
FINAL_FLAG          1 byte    0 = data, 1 = final manifest
CIPHERTEXT          N bytes   AES-256-GCM ciphertext including 16-byte tag
```

AAD for each record:

```text
"CIPHERSTRIKE/v1/chunk|" || kind || "|" || file_id || "|" ||
uint64(index) || ("|final" if final else "|data")
```

The nonce is:

```text
nonce_prefix (8 bytes) || uint32(index) (4 bytes)
```

Data chunks contain raw file bytes, or the TAR byte stream for a folder. The
final record contains an authenticated JSON manifest:

```json
{
  "format": "CIPHER STRIKE PAYLOAD",
  "version": 1,
  "size": 12345,
  "chunks": 4,
  "sha256": "hex-encoded SHA-256 of the complete plaintext payload"
}
```

The decrypter requires the manifest to be the last record, with no trailing
bytes, and verifies the chunk count, total size, and digest.

### Recovery Key file

The `.recovery` file is UTF-8 text with:

* a version;
* a base64 recovery identifier;
* a base64 32-byte recovery secret;
* a truncated SHA-256 checksum for accidental-corruption detection;
* explanatory warnings.

The checksum is not a replacement for the GCM authentication tag. The
authenticated header and wrapped DEK are the security controls.

---

**CIPHER STRIKE** — encrypt deliberately, recover deliberately.
