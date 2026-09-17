"""Command-line interface for the local encrypted password vault."""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from . import crypto
from .generator import PasswordPolicy, generate_password
from .vault import Entry, Vault, VaultError

DEFAULT_VAULT_PATH = str(Path.home() / ".password_manager_vault")


def _get_master_password(args, confirm: bool = False) -> str:
    if args.master_password:
        return args.master_password

    password = getpass.getpass("Master password: ")
    if confirm:
        again = getpass.getpass("Confirm master password: ")
        if password != again:
            print("Passwords do not match.", file=sys.stderr)
            sys.exit(1)
    return password


def cmd_init(args) -> int:
    master_password = _get_master_password(args, confirm=True)
    if not master_password:
        print("Master password cannot be empty.", file=sys.stderr)
        return 1
    try:
        Vault.create(args.vault, master_password)
    except VaultError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    print(f"Initialized new vault at {args.vault}")
    return 0


def _open_vault(args) -> Vault | None:
    master_password = _get_master_password(args, confirm=False)
    try:
        return Vault.open(args.vault, master_password)
    except VaultError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return None
    except crypto.DecryptionError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return None


def cmd_add(args) -> int:
    vault = _open_vault(args)
    if vault is None:
        return 1

    if args.generate:
        policy = PasswordPolicy(
            length=args.length,
            use_lowercase=not args.no_lowercase,
            use_uppercase=not args.no_uppercase,
            use_digits=not args.no_digits,
            use_symbols=not args.no_symbols,
            exclude_ambiguous=args.exclude_ambiguous,
        )
        password = generate_password(policy)
    elif args.password:
        password = args.password
    else:
        password = getpass.getpass("Password for entry: ")

    username = args.username or ""
    notes = args.notes or ""

    existing = vault.find(args.site)
    action = "Updated" if existing else "Added"
    vault.add_or_update(args.site, username, password, notes)
    vault.save()

    print(f"{action} entry for '{args.site}'.")
    if args.generate or args.show:
        print(f"Password: {password}")
    return 0


def cmd_get(args) -> int:
    vault = _open_vault(args)
    if vault is None:
        return 1

    entry = vault.find(args.site)
    if entry is None:
        print(f"No entry found for '{args.site}'.", file=sys.stderr)
        return 1

    print(f"Site:     {entry.site}")
    print(f"Username: {entry.username}")
    print(f"Password: {entry.password}")
    if entry.notes:
        print(f"Notes:    {entry.notes}")
    print(f"Created:  {entry.created_at}")
    print(f"Updated:  {entry.updated_at}")
    return 0


def cmd_list(args) -> int:
    vault = _open_vault(args)
    if vault is None:
        return 1

    entries = vault.list_entries()
    if not entries:
        print("Vault is empty.")
        return 0

    for entry in entries:
        print(f"{entry.site}  ({entry.username})")
    return 0


def cmd_delete(args) -> int:
    vault = _open_vault(args)
    if vault is None:
        return 1

    removed = vault.delete(args.site)
    if not removed:
        print(f"No entry found for '{args.site}'.", file=sys.stderr)
        return 1

    vault.save()
    print(f"Deleted entry for '{args.site}'.")
    return 0


def cmd_search(args) -> int:
    vault = _open_vault(args)
    if vault is None:
        return 1

    results = vault.search(args.query)
    if not results:
        print("No matches.")
        return 0

    for entry in results:
        print(f"{entry.site}  ({entry.username})")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="password-manager",
        description="A local, encrypted password vault CLI.",
    )
    parser.add_argument(
        "--vault",
        default=DEFAULT_VAULT_PATH,
        help=f"Path to the vault file (default: {DEFAULT_VAULT_PATH})",
    )
    parser.add_argument(
        "--master-password",
        default=None,
        help="Master password (avoid in interactive use; intended for scripting/tests).",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    p_init = subparsers.add_parser("init", help="Create a new vault.")
    p_init.set_defaults(func=cmd_init)

    p_add = subparsers.add_parser("add", help="Add or update an entry.")
    p_add.add_argument("site", help="Site or service name.")
    p_add.add_argument("--username", default="", help="Username for this entry.")
    p_add.add_argument("--password", default=None, help="Password (omit to be prompted, or use --generate).")
    p_add.add_argument("--notes", default="", help="Free-text notes.")
    p_add.add_argument("--generate", action="store_true", help="Auto-generate a strong password.")
    p_add.add_argument("--length", type=int, default=16, help="Length of generated password (default: 16).")
    p_add.add_argument("--no-lowercase", action="store_true", help="Exclude lowercase letters from generated password.")
    p_add.add_argument("--no-uppercase", action="store_true", help="Exclude uppercase letters from generated password.")
    p_add.add_argument("--no-digits", action="store_true", help="Exclude digits from generated password.")
    p_add.add_argument("--no-symbols", action="store_true", help="Exclude symbols from generated password.")
    p_add.add_argument("--exclude-ambiguous", action="store_true", help="Exclude ambiguous characters (Il1O0).")
    p_add.add_argument("--show", action="store_true", help="Print the password after saving.")
    p_add.set_defaults(func=cmd_add)

    p_get = subparsers.add_parser("get", help="Retrieve and display one entry.")
    p_get.add_argument("site", help="Site or service name.")
    p_get.set_defaults(func=cmd_get)

    p_list = subparsers.add_parser("list", help="List all site names and usernames (no passwords).")
    p_list.set_defaults(func=cmd_list)

    p_delete = subparsers.add_parser("delete", help="Delete an entry.")
    p_delete.add_argument("site", help="Site or service name.")
    p_delete.set_defaults(func=cmd_delete)

    p_search = subparsers.add_parser("search", help="Search entries by site, username, or notes.")
    p_search.add_argument("query", help="Substring to search for.")
    p_search.set_defaults(func=cmd_search)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
