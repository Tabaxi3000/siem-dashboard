"""
test_security.py

Tests for password strength analysis (Challenge 2).

The module is loaded directly from its file so the suite needs only pytest and
the standard library, not the full Flask/Mongo/Redis application stack.
"""

import importlib.util
import pathlib

_CORE = pathlib.Path(__file__).resolve().parent.parent / "app" / "core"


def _load(name):
    spec = importlib.util.spec_from_file_location(name, _CORE / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


security = _load("security")


def test_common_password_scores_zero():
    result = security.check_password_strength("password")
    assert result["strength"] == "weak"
    assert result["score"] == 0
    assert any("common" in f.lower() for f in result["feedback"])


def test_meets_requirements_but_common_is_weak():
    # "P@ssw0rd" satisfies the character classes but is a known password.
    result = security.check_password_strength("P@ssw0rd")
    assert result["strength"] == "weak"
    assert result["score"] == 0


def test_too_short_is_weak():
    result = security.check_password_strength("Ab1!")
    assert result["strength"] == "weak"
    assert any("characters" in f.lower() for f in result["feedback"])


def test_full_variety_long_password_is_strong():
    result = security.check_password_strength("Xk9#mP2vL5nQ8w")
    assert result["strength"] == "strong"
    assert result["score"] >= 5
    assert result["feedback"] == []


def test_long_passphrase_is_at_least_medium():
    result = security.check_password_strength("correct-horse-battery-staple")
    assert result["strength"] in ("medium", "strong")


def test_repeated_characters_flagged():
    result = security.check_password_strength("aaaaAAAA1111!!!!")
    assert any("repeated" in f.lower() for f in result["feedback"])


def test_keyboard_walk_flagged():
    result = security.check_password_strength("Qwerty12345!")
    assert any(
        "keyboard" in f.lower() or "sequential" in f.lower()
        for f in result["feedback"]
    )


def test_entropy_increases_with_length_and_variety():
    low = security.password_entropy_bits("aaaa")
    high = security.password_entropy_bits("Xk9#mP2vL5nQ8w")
    assert high > low
    assert security.password_entropy_bits("") == 0.0
