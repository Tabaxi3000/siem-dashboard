"""
test_webhook.py

Tests for HMAC-SHA256 webhook signing and verification.

Loaded directly from the module file so the suite needs only pytest and the
standard library.
"""

import importlib.util
import pathlib

import pytest

_CORE = pathlib.Path(__file__).resolve().parent.parent / "app" / "core"


def _load(name):
    spec = importlib.util.spec_from_file_location(name, _CORE / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


webhook = _load("webhook")


def signer():
    return webhook.WebhookSigner("s3cr3t-signing-key")


def test_sign_is_deterministic_hex():
    s = signer()
    sig = s.sign('{"alert":"brute_force"}')
    assert len(sig) == 64
    assert all(c in "0123456789abcdef" for c in sig)
    assert s.sign('{"alert":"brute_force"}') == sig


def test_verify_accepts_valid_signature():
    s = signer()
    payload = '{"alert":"dns_tunnel"}'
    assert s.verify(payload, s.sign(payload))


def test_verify_rejects_tampered_payload():
    s = signer()
    sig = s.sign('{"amount":10}')
    assert not s.verify('{"amount":1000}', sig)


def test_verify_rejects_wrong_secret():
    payload = '{"alert":"x"}'
    sig = webhook.WebhookSigner("key-a").sign(payload)
    assert not webhook.WebhookSigner("key-b").verify(payload, sig)


def test_header_form_round_trips():
    s = signer()
    payload = '{"alert":"phishing"}'
    header = s.sign_header(payload)
    assert header.startswith("sha256=")
    assert s.verify_header(payload, header)
    assert s.verify(payload, header)  # verify also accepts the header form


def test_empty_secret_rejected():
    with pytest.raises(ValueError):
        webhook.WebhookSigner("")


def test_bytes_and_str_payloads_match():
    s = signer()
    assert s.sign("hello") == s.sign(b"hello")
