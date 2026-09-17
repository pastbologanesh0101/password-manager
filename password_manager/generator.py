"""Cryptographically secure password generator."""

from __future__ import annotations

import secrets
import string
from dataclasses import dataclass

AMBIGUOUS_CHARS = "Il1O0"


@dataclass
class PasswordPolicy:
    length: int = 16
    use_lowercase: bool = True
    use_uppercase: bool = True
    use_digits: bool = True
    use_symbols: bool = True
    exclude_ambiguous: bool = False
    symbols: str = "!@#$%^&*()-_=+[]{};:,.<>?/"

    def character_pool(self) -> str:
        pool = ""
        if self.use_lowercase:
            pool += string.ascii_lowercase
        if self.use_uppercase:
            pool += string.ascii_uppercase
        if self.use_digits:
            pool += string.digits
        if self.use_symbols:
            pool += self.symbols

        if not pool:
            raise ValueError("At least one character class must be enabled.")

        if self.exclude_ambiguous:
            pool = "".join(c for c in pool if c not in AMBIGUOUS_CHARS)

        return pool

    def required_classes(self) -> list[str]:
        classes = []
        if self.use_lowercase:
            classes.append(string.ascii_lowercase)
        if self.use_uppercase:
            classes.append(string.ascii_uppercase)
        if self.use_digits:
            classes.append(string.digits)
        if self.use_symbols:
            classes.append(self.symbols)
        return classes


def generate_password(policy: PasswordPolicy | None = None) -> str:
    """Generate a random password satisfying the given policy.

    Uses the `secrets` module (a CSPRNG) exclusively for all random choices.
    Guarantees at least one character from each enabled character class,
    provided length is sufficient.
    """
    policy = policy or PasswordPolicy()
    if policy.length < 1:
        raise ValueError("Password length must be at least 1.")

    pool = policy.character_pool()
    required = policy.required_classes()
    if policy.exclude_ambiguous:
        required = [
            "".join(c for c in cls if c not in AMBIGUOUS_CHARS) for cls in required
        ]
        required = [cls for cls in required if cls]

    if len(required) > policy.length:
        raise ValueError(
            "Password length is too short to include one of every required "
            "character class."
        )

    # Guarantee representation of each enabled class, then fill the rest.
    password_chars = [secrets.choice(cls) for cls in required]
    remaining = policy.length - len(password_chars)
    password_chars.extend(secrets.choice(pool) for _ in range(remaining))

    # Shuffle using a CSPRNG (Fisher-Yates with secrets.randbelow).
    for i in range(len(password_chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        password_chars[i], password_chars[j] = password_chars[j], password_chars[i]

    return "".join(password_chars)
