"""
Crypto primitives for the vault.

Design:
  - Key derivation: PBKDF2-HMAC-SHA256, 480,000 iterations (OWASP 2023
    recommendation for PBKDF2-SHA256), 16-byte random salt, 32-byte
    (256-bit) derived key.
  - Encryption: AES-256-GCM (AEAD), 12-byte random nonce per encryption.
    GCM provides both confidentiality and integrity (authentication tag),
    so tampering or a wrong key/password is detected instead of silently
    producing garbage plaintext.

Nothing here hand-rolls a cipher or a hash construction; both primitives
come from the `cryptography` package (which wraps OpenSSL).
"""

from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32  # 256-bit key for AES-256
PBKDF2_ITERATIONS = 480_000


class DecryptionError(Exception):
    """Raised when the vault cannot be decrypted (wrong password or corrupt file)."""


def derive_key(master_password: str, salt: bytes) -> bytes:
    """Derive a 256-bit key from a master password and salt using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(master_password.encode("utf-8"))


def generate_salt() -> bytes:
    return os.urandom(SALT_SIZE)


def generate_nonce() -> bytes:
    return os.urandom(NONCE_SIZE)


def encrypt(plaintext: bytes, master_password: str) -> bytes:
    """Encrypt plaintext bytes, returning salt || nonce || ciphertext(+tag)."""
    salt = generate_salt()
    key = derive_key(master_password, salt)
    nonce = generate_nonce()
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    return salt + nonce + ciphertext


def decrypt(blob: bytes, master_password: str) -> bytes:
    """Decrypt a salt || nonce || ciphertext(+tag) blob.

    Raises DecryptionError on a wrong master password or corrupted data
    (AES-GCM authentication tag mismatch) instead of returning garbage.
    """
    if len(blob) < SALT_SIZE + NONCE_SIZE:
        raise DecryptionError("Vault file is truncated or corrupt.")

    salt = blob[:SALT_SIZE]
    nonce = blob[SALT_SIZE : SALT_SIZE + NONCE_SIZE]
    ciphertext = blob[SALT_SIZE + NONCE_SIZE :]

    key = derive_key(master_password, salt)
    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    except InvalidTag as exc:
        raise DecryptionError(
            "Failed to decrypt vault: wrong master password or corrupted file."
        ) from exc
