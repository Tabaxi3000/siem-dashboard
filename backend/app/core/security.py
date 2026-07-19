"""
security.py

Password strength analysis

Scores a password and returns human-readable feedback so registration can
warn users about weak choices (Challenge 2: password strength reporting). The
analysis is informational and does not change the authentication rules
enforced elsewhere. It combines length, character-class variety, a Shannon
entropy estimate, a bundled common-password list, and pattern detection
(repeated characters, keyboard walks, and sequential runs).

Key exports:
  check_password_strength - returns {strength, score, entropy_bits, feedback}
  password_entropy_bits - Shannon entropy estimate in bits

Connects to:
  controllers/auth_ctrl.py - logs a warning when a registered password is weak
"""

from __future__ import annotations

import math
import re
from typing import Any

# A compact list of the most common passwords, enough to catch the worst
# choices without shipping a full wordlist. Swap in a rockyou-style file for
# broader coverage; the check only needs a membership set of lowercased values.
COMMON_PASSWORDS: frozenset[str] = frozenset(
    {
        "123456", "password", "12345678", "qwerty", "123456789", "12345",
        "1234", "111111", "1234567", "dragon", "123123", "baseball",
        "abc123", "football", "monkey", "letmein", "shadow", "master",
        "666666", "qwertyuiop", "123321", "mustang", "1234567890",
        "michael", "654321", "superman", "1qaz2wsx", "7777777", "121212",
        "000000", "qazwsx", "123qwe", "killer", "trustno1", "jordan",
        "asdfgh", "hunter", "buster", "soccer", "harley", "batman",
        "andrew", "tigger", "sunshine", "iloveyou", "charlie", "robert",
        "thomas", "hockey", "ranger", "daniel", "starwars", "112233",
        "george", "computer", "michelle", "jessica", "pepper", "1111",
        "zxcvbn", "555555", "11111111", "131313", "freedom", "777777",
        "passw0rd", "p@ssw0rd", "password1", "password123", "admin",
        "welcome", "login", "guest", "changeme", "secret", "qwerty123",
    }
)

# Left-to-right keyboard runs used as pattern seeds. A password containing any
# of these (in either direction) is treated as a keyboard walk.
_KEYBOARD_ROWS: tuple[str, ...] = (
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "1234567890",
    "qazwsx",
    "1qaz2wsx",
)

_REPEATED_RUN = re.compile(r"(.)\1{2,}")

_STRONG_THRESHOLD = 5
_MEDIUM_THRESHOLD = 3
_LONG_PASSWORD = 12
_MIN_PASSWORD = 8
_KEYBOARD_WALK_MIN = 4


def password_entropy_bits(password: str) -> float:
    """
    Estimate password entropy in bits as ``length * log2(charset_size)``,
    where the charset size is inferred from the character classes present.
    """
    if not password:
        return 0.0

    charset = 0
    if re.search(r"[a-z]", password):
        charset += 26
    if re.search(r"[A-Z]", password):
        charset += 26
    if re.search(r"[0-9]", password):
        charset += 10
    if re.search(r"[^A-Za-z0-9]", password):
        charset += 32

    if charset == 0:
        return 0.0
    return round(len(password) * math.log2(charset), 2)


def _has_keyboard_walk(lowered: str) -> bool:
    for row in _KEYBOARD_ROWS:
        for length in range(len(row), _KEYBOARD_WALK_MIN - 1, -1):
            for start in range(len(row) - length + 1):
                run = row[start : start + length]
                if run in lowered or run[::-1] in lowered:
                    return True
    return False


def _has_sequential_run(lowered: str) -> bool:
    run = 1
    for i in range(1, len(lowered)):
        if ord(lowered[i]) - ord(lowered[i - 1]) == 1:
            run += 1
            if run >= _KEYBOARD_WALK_MIN:
                return True
        else:
            run = 1
    return False


def check_password_strength(password: str) -> dict[str, Any]:
    """
    Score a password and return ``{strength, score, entropy_bits, feedback}``.

    ``score`` runs from 0 upward; ``strength`` is ``weak`` (< 3), ``medium``
    (< 5), or ``strong``. ``feedback`` is a list of specific, actionable
    suggestions. A password on the common-password list scores 0 regardless of
    its shape.
    """
    feedback: list[str] = []
    score = 0

    if len(password) >= _LONG_PASSWORD:
        score += 2
    elif len(password) >= _MIN_PASSWORD:
        score += 1
    else:
        feedback.append(
            f"Use at least {_LONG_PASSWORD} characters"
        )

    if re.search(r"[A-Z]", password):
        score += 1
    else:
        feedback.append("Add an uppercase letter")
    if re.search(r"[a-z]", password):
        score += 1
    if re.search(r"[0-9]", password):
        score += 1
    else:
        feedback.append("Add a digit")
    if re.search(r"[^A-Za-z0-9]", password):
        score += 1
    else:
        feedback.append("Add a symbol")

    lowered = password.lower()

    if lowered in COMMON_PASSWORDS:
        feedback.append("This is a commonly used password")
        entropy = password_entropy_bits(password)
        return {
            "strength": "weak",
            "score": 0,
            "entropy_bits": entropy,
            "feedback": feedback,
        }

    if _REPEATED_RUN.search(password):
        score -= 1
        feedback.append("Avoid repeated characters")

    if _has_keyboard_walk(lowered) or _has_sequential_run(lowered):
        score -= 1
        feedback.append("Avoid keyboard or sequential patterns")

    score = max(0, score)

    # A password shorter than the minimum length can never be more than weak,
    # however much character variety it packs into those few characters.
    if len(password) < _MIN_PASSWORD:
        score = min(score, _MEDIUM_THRESHOLD - 1)

    entropy = password_entropy_bits(password)

    if score >= _STRONG_THRESHOLD:
        strength = "strong"
    elif score >= _MEDIUM_THRESHOLD:
        strength = "medium"
    else:
        strength = "weak"

    return {
        "strength": strength,
        "score": score,
        "entropy_bits": entropy,
        "feedback": feedback,
    }
