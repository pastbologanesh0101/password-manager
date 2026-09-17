"""Unit tests for the encrypted password vault CLI."""

from __future__ import annotations

import string
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from password_manager import crypto
from password_manager.generator import PasswordPolicy, generate_password
from password_manager.vault import Vault, VaultError

MASTER_PASSWORD = "correct horse battery staple"
WRONG_PASSWORD = "definitely the wrong password"


class VaultTestCase(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.vault_path = Path(self.tmpdir.name) / "test_vault.db"

    def tearDown(self):
        self.tmpdir.cleanup()

    # 1. init creates an encrypted file with no plaintext leakage.
    def test_init_creates_encrypted_file_no_plaintext_leak(self):
        vault = Vault.create(self.vault_path, MASTER_PASSWORD)
        secret_password = "super-secret-plaintext-password-12345"
        vault.add_or_update("example.com", "alice", secret_password, "some notes")
        vault.save()

        raw_bytes = self.vault_path.read_bytes()

        # The vault file must not contain the plaintext password anywhere.
        self.assertNotIn(secret_password.encode("utf-8"), raw_bytes)
        self.assertNotIn(b"example.com", raw_bytes)
        self.assertNotIn(b"alice", raw_bytes)
        self.assertNotIn(b"some notes", raw_bytes)
        # Sanity: the JSON key names themselves must not appear as plaintext
        # (they would if the file were unencrypted JSON).
        self.assertNotIn(b'"password"', raw_bytes)
        self.assertNotIn(b'"site"', raw_bytes)

    # 2. add + get round-trips an entry correctly.
    def test_add_and_get_round_trip(self):
        vault = Vault.create(self.vault_path, MASTER_PASSWORD)
        vault.add_or_update("github.com", "bob", "s3cret!", "personal account")
        vault.save()

        reopened = Vault.open(self.vault_path, MASTER_PASSWORD)
        entry = reopened.find("github.com")
        self.assertIsNotNone(entry)
        self.assertEqual(entry.username, "bob")
        self.assertEqual(entry.password, "s3cret!")
        self.assertEqual(entry.notes, "personal account")

    # 3. wrong master password fails cleanly (auth tag mismatch), not garbage.
    def test_wrong_master_password_fails_cleanly(self):
        vault = Vault.create(self.vault_path, MASTER_PASSWORD)
        vault.add_or_update("site.com", "user", "pw", "")
        vault.save()

        with self.assertRaises(crypto.DecryptionError):
            Vault.open(self.vault_path, WRONG_PASSWORD)

    # 4. list never exposes passwords.
    def test_list_never_exposes_passwords(self):
        vault = Vault.create(self.vault_path, MASTER_PASSWORD)
        vault.add_or_update("site-a.com", "user-a", "password-a-secret", "")
        vault.add_or_update("site-b.com", "user-b", "password-b-secret", "")
        vault.save()

        entries = vault.list_entries()
        rendered = "\n".join(f"{e.site} ({e.username})" for e in entries)

        self.assertIn("site-a.com", rendered)
        self.assertIn("user-a", rendered)
        self.assertNotIn("password-a-secret", rendered)
        self.assertNotIn("password-b-secret", rendered)

    # 5. delete removes an entry.
    def test_delete_removes_entry(self):
        vault = Vault.create(self.vault_path, MASTER_PASSWORD)
        vault.add_or_update("deleteme.com", "user", "pw", "")
        vault.save()

        removed = vault.delete("deleteme.com")
        self.assertTrue(removed)
        self.assertIsNone(vault.find("deleteme.com"))

        vault.save()
        reopened = Vault.open(self.vault_path, MASTER_PASSWORD)
        self.assertIsNone(reopened.find("deleteme.com"))

    def test_delete_nonexistent_returns_false(self):
        vault = Vault.create(self.vault_path, MASTER_PASSWORD)
        self.assertFalse(vault.delete("nope.com"))

    # 6. search matches correctly across fields.
    def test_search_matches_across_fields(self):
        vault = Vault.create(self.vault_path, MASTER_PASSWORD)
        vault.add_or_update("news.example.com", "reader1", "pw1", "daily news site")
        vault.add_or_update("bank.example.com", "financeguy", "pw2", "checking account")
        vault.add_or_update("forum.other.com", "poster99", "pw3", "hobby forum")
        vault.save()

        by_site = vault.search("example")
        self.assertEqual({e.site for e in by_site}, {"news.example.com", "bank.example.com"})

        by_username = vault.search("financeguy")
        self.assertEqual({e.site for e in by_username}, {"bank.example.com"})

        by_notes = vault.search("hobby")
        self.assertEqual({e.site for e in by_notes}, {"forum.other.com"})

        no_match = vault.search("nonexistent-query-xyz")
        self.assertEqual(no_match, [])

    # 7. generated passwords respect length and character-class settings.
    def test_generated_password_respects_length(self):
        for length in (8, 16, 32, 64):
            pw = generate_password(PasswordPolicy(length=length))
            self.assertEqual(len(pw), length)

    def test_generated_password_respects_character_classes(self):
        policy = PasswordPolicy(
            length=24,
            use_lowercase=False,
            use_uppercase=True,
            use_digits=True,
            use_symbols=False,
        )
        pw = generate_password(policy)
        self.assertTrue(all(c in string.ascii_uppercase + string.digits for c in pw))
        self.assertFalse(any(c in string.ascii_lowercase for c in pw))
        self.assertTrue(any(c in string.ascii_uppercase for c in pw))
        self.assertTrue(any(c in string.digits for c in pw))

    def test_generated_password_digits_only(self):
        policy = PasswordPolicy(
            length=12,
            use_lowercase=False,
            use_uppercase=False,
            use_digits=True,
            use_symbols=False,
        )
        pw = generate_password(policy)
        self.assertEqual(len(pw), 12)
        self.assertTrue(all(c in string.digits for c in pw))

    def test_generated_password_excludes_ambiguous_characters(self):
        policy = PasswordPolicy(length=200, exclude_ambiguous=True)
        pw = generate_password(policy)
        for ambiguous_char in "Il1O0":
            self.assertNotIn(ambiguous_char, pw)

    # 8. updating an existing site's entry overwrites rather than duplicates.
    def test_update_existing_entry_overwrites_not_duplicates(self):
        vault = Vault.create(self.vault_path, MASTER_PASSWORD)
        vault.add_or_update("service.com", "olduser", "oldpassword", "old notes")
        vault.save()

        vault.add_or_update("service.com", "newuser", "newpassword", "new notes")
        vault.save()

        matching = [e for e in vault.entries if e.site == "service.com"]
        self.assertEqual(len(matching), 1)
        self.assertEqual(matching[0].username, "newuser")
        self.assertEqual(matching[0].password, "newpassword")

        reopened = Vault.open(self.vault_path, MASTER_PASSWORD)
        matching_reopened = [e for e in reopened.entries if e.site == "service.com"]
        self.assertEqual(len(matching_reopened), 1)
        self.assertEqual(matching_reopened[0].username, "newuser")

    # 9. persistence survives across separate CLI invocations (reopen the vault file).
    def test_persistence_across_separate_cli_invocations(self):
        script = str(Path(__file__).resolve().parent.parent / "main.py")
        vault_path = str(self.vault_path)

        subprocess.run(
            [sys.executable, script, "--vault", vault_path, "--master-password", MASTER_PASSWORD, "init"],
            check=True, capture_output=True, text=True,
        )
        subprocess.run(
            [
                sys.executable, script, "--vault", vault_path,
                "--master-password", MASTER_PASSWORD,
                "add", "cli-site.com", "--username", "cliuser", "--password", "cli-password-xyz",
            ],
            check=True, capture_output=True, text=True,
        )

        result = subprocess.run(
            [
                sys.executable, script, "--vault", vault_path,
                "--master-password", MASTER_PASSWORD,
                "get", "cli-site.com",
            ],
            check=True, capture_output=True, text=True,
        )
        self.assertIn("cliuser", result.stdout)
        self.assertIn("cli-password-xyz", result.stdout)

        list_result = subprocess.run(
            [sys.executable, script, "--vault", vault_path, "--master-password", MASTER_PASSWORD, "list"],
            check=True, capture_output=True, text=True,
        )
        self.assertIn("cli-site.com", list_result.stdout)
        self.assertNotIn("cli-password-xyz", list_result.stdout)

    # 10. creating a vault that already exists raises an error (no silent overwrite).
    def test_create_existing_vault_raises(self):
        Vault.create(self.vault_path, MASTER_PASSWORD)
        with self.assertRaises(VaultError):
            Vault.create(self.vault_path, MASTER_PASSWORD)

    # 11. opening a nonexistent vault raises an error.
    def test_open_nonexistent_vault_raises(self):
        missing_path = Path(self.tmpdir.name) / "does_not_exist.db"
        with self.assertRaises(VaultError):
            Vault.open(missing_path, MASTER_PASSWORD)

    # 12. crypto round trip at the primitive level, and tamper detection.
    def test_crypto_encrypt_decrypt_round_trip_and_tamper_detection(self):
        plaintext = b'{"hello": "world"}'
        blob = crypto.encrypt(plaintext, MASTER_PASSWORD)
        self.assertEqual(crypto.decrypt(blob, MASTER_PASSWORD), plaintext)

        with self.assertRaises(crypto.DecryptionError):
            crypto.decrypt(blob, WRONG_PASSWORD)

        # Flip a byte in the ciphertext -> tag mismatch -> DecryptionError.
        tampered = bytearray(blob)
        tampered[-1] ^= 0xFF
        with self.assertRaises(crypto.DecryptionError):
            crypto.decrypt(bytes(tampered), MASTER_PASSWORD)


if __name__ == "__main__":
    unittest.main()
