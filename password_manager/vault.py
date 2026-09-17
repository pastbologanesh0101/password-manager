"""Vault: encrypted-at-rest storage of password entries.

On disk a vault is a single binary file:

    +----------------+-----------------+---------------------------+
    | salt (16 bytes) | nonce (12 bytes) | AES-256-GCM ciphertext+tag |
    +----------------+-----------------+---------------------------+

The ciphertext, once decrypted with the key derived from the master
password and salt, is UTF-8 JSON: a list of entry objects. There is no
plaintext anywhere on disk -- not even partial entries -- the entire
entry list is encrypted as a single blob.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from . import crypto

DecryptionError = crypto.DecryptionError


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Entry:
    site: str
    username: str
    password: str
    notes: str = ""
    created_at: str = field(default_factory=_now_iso)
    updated_at: str = field(default_factory=_now_iso)

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(data: dict) -> "Entry":
        return Entry(
            site=data["site"],
            username=data.get("username", ""),
            password=data.get("password", ""),
            notes=data.get("notes", ""),
            created_at=data.get("created_at", _now_iso()),
            updated_at=data.get("updated_at", _now_iso()),
        )


class VaultError(Exception):
    """Generic vault error (e.g. vault already exists / does not exist)."""


class Vault:
    """In-memory representation of a decrypted vault, bound to a file path."""

    def __init__(self, path: str | Path, master_password: str, entries: Optional[list[Entry]] = None):
        self.path = Path(path)
        self.master_password = master_password
        self.entries: list[Entry] = entries if entries is not None else []

    # -- construction / persistence -------------------------------------------------

    @classmethod
    def create(cls, path: str | Path, master_password: str) -> "Vault":
        """Create a brand-new, empty vault file. Fails if one already exists."""
        path = Path(path)
        if path.exists():
            raise VaultError(f"Vault already exists at {path}")
        vault = cls(path, master_password, entries=[])
        vault.save()
        return vault

    @classmethod
    def open(cls, path: str | Path, master_password: str) -> "Vault":
        """Open (decrypt) an existing vault file."""
        path = Path(path)
        if not path.exists():
            raise VaultError(f"No vault found at {path}")

        blob = path.read_bytes()
        plaintext = crypto.decrypt(blob, master_password)  # raises DecryptionError
        data = json.loads(plaintext.decode("utf-8"))
        entries = [Entry.from_dict(e) for e in data]
        return cls(path, master_password, entries=entries)

    def save(self) -> None:
        """Encrypt the current entry list and write it to disk atomically."""
        plaintext = json.dumps([e.to_dict() for e in self.entries]).encode("utf-8")
        blob = crypto.encrypt(plaintext, self.master_password)

        tmp_path = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp_path.write_bytes(blob)
        os.replace(tmp_path, self.path)

    # -- entry operations -------------------------------------------------------------

    def find(self, site: str) -> Optional[Entry]:
        for entry in self.entries:
            if entry.site.lower() == site.lower():
                return entry
        return None

    def add_or_update(
        self,
        site: str,
        username: str,
        password: str,
        notes: str = "",
    ) -> Entry:
        """Add a new entry, or update in place if `site` already exists."""
        existing = self.find(site)
        if existing is not None:
            existing.username = username
            existing.password = password
            existing.notes = notes
            existing.updated_at = _now_iso()
            return existing

        entry = Entry(site=site, username=username, password=password, notes=notes)
        self.entries.append(entry)
        return entry

    def delete(self, site: str) -> bool:
        existing = self.find(site)
        if existing is None:
            return False
        self.entries.remove(existing)
        return True

    def search(self, query: str) -> list[Entry]:
        q = query.lower()
        return [
            e
            for e in self.entries
            if q in e.site.lower() or q in e.username.lower() or q in e.notes.lower()
        ]

    def list_entries(self) -> list[Entry]:
        return sorted(self.entries, key=lambda e: e.site.lower())
