# Password Manager

A small, local, encrypted password vault CLI written in Python. All entries
are stored in a single encrypted file on disk — there is no server, no
cloud sync, and no plaintext data ever written to disk.

## Features

- `init` — create a new vault, protected by a master password.
- `add <site>` — add or update an entry (username, password, notes); can
  auto-generate a strong random password with `--generate`.
- `get <site>` — decrypt the vault and print one entry (including its
  password).
- `list` — list site names and usernames only — **never** prints passwords.
- `delete <site>` — remove an entry.
- `search <query>` — substring search across site, username, and notes.

## Crypto design

The vault file is a single binary blob laid out as:

```
+-----------------+------------------+-------------------------------+
| salt (16 bytes)  | nonce (12 bytes) | AES-256-GCM ciphertext + tag   |
+-----------------+------------------+-------------------------------+
```

- **Key derivation**: PBKDF2-HMAC-SHA256 with a random 16-byte salt and
  480,000 iterations (in line with OWASP's 2023 guidance for PBKDF2-SHA256),
  producing a 256-bit key from the master password.
- **Encryption**: AES-256-GCM, an authenticated encryption (AEAD) cipher,
  with a random 12-byte nonce generated per save. GCM's authentication tag
  means a wrong master password or a corrupted/tampered file is detected as
  a decryption failure — it never silently produces garbage plaintext.
- The plaintext that gets encrypted is a UTF-8 JSON array of entry objects
  (`site`, `username`, `password`, `notes`, `created_at`, `updated_at`).
  The **entire** entry list is encrypted as one blob; there is no partial or
  per-field plaintext anywhere on disk.
- All primitives (PBKDF2HMAC, AESGCM) come from the
  [`cryptography`](https://cryptography.io/) package, which wraps OpenSSL.
  Nothing in this project hand-rolls a cipher, a KDF, or a hash construction.
- Every save is atomic: the new ciphertext is written to a temporary file
  and then renamed over the vault path, so a crash mid-write can't corrupt
  the vault.

### Password generation

Generated passwords are built exclusively from the [`secrets`](https://docs.python.org/3/library/secrets.html)
module — a cryptographically secure RNG — never `random`. The generator
supports a configurable length and character classes (lowercase, uppercase,
digits, symbols, and an option to exclude visually ambiguous characters like
`Il1O0`), and guarantees at least one character from each enabled class
(when the length allows it).

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

All commands accept `--vault <path>` (defaults to `~/.password_manager_vault`)
and `--master-password <pw>` (for scripting/tests — omit it to be prompted
interactively via a hidden `getpass` prompt).

```bash
# Create a new vault
python main.py --vault myvault.db init

# Add an entry with an explicit password
python main.py --vault myvault.db add github --username alice --password 'hunter2'

# Add an entry with an auto-generated 20-character password
python main.py --vault myvault.db add gmail --username alice@example.com --generate --length 20 --show

# List entries (no passwords shown)
python main.py --vault myvault.db list

# Retrieve one entry (password included)
python main.py --vault myvault.db get github

# Search across site/username/notes
python main.py --vault myvault.db search git

# Delete an entry
python main.py --vault myvault.db delete github
```

### Example session

```
$ python main.py --vault demo.db init --master-password 'correct horse battery staple'
Initialized new vault at demo.db

$ python main.py --vault demo.db add github --username alice --generate --length 20 --show --master-password 'correct horse battery staple'
Added entry for 'github'.
Password: xQ2!mF9zR7#vL0pK3s@T

$ python main.py --vault demo.db list --master-password 'correct horse battery staple'
github  (alice)

$ python main.py --vault demo.db get github --master-password 'correct horse battery staple'
Site:     github
Username: alice
Password: xQ2!mF9zR7#vL0pK3s@T
Created:  2026-01-01T00:00:00+00:00
Updated:  2026-01-01T00:00:00+00:00

$ python main.py --vault demo.db get github --master-password 'wrong password'
Error: Failed to decrypt vault: wrong master password or corrupted file.
```

## Running the tests

```bash
pip install -r requirements.txt
python -m pytest tests/ -v
```

## Project layout

```
password_manager/
  crypto.py      # AES-256-GCM + PBKDF2-HMAC-SHA256 primitives
  vault.py       # Vault file format, entries, CRUD operations
  generator.py   # secrets-based password generator
  cli.py         # argparse CLI (init/add/get/list/delete/search)
main.py          # entry point
tests/           # unit tests
```

## Security notes

This is a portfolio/learning project, not an audited production password
manager. It has no clipboard-clearing, no auto-lock timer, and stores the
master password in memory as a plain Python string for the duration of a
CLI invocation. Use a real, audited password manager for anything that
matters.
