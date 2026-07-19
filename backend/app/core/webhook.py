"""
webhook.py

HMAC-SHA256 signing and verification for outbound webhooks

Signs webhook payloads (for example, alert notifications shipped to an
external system) so receivers can confirm the request came from this SIEM and
was not tampered with in transit (Challenge: webhook signature verification).
Verification is constant-time to avoid leaking the signature through timing.

Key exports:
  WebhookSigner - sign / verify a payload, and header helpers matching the
  common ``sha256=<hex>`` convention

Connects to:
  (utility) any alert-notification path that ships payloads to an external URL
"""

from __future__ import annotations

import hashlib
import hmac

_HEADER_PREFIX = "sha256="


def _as_bytes(value: str | bytes) -> bytes:
    return value.encode("utf-8") if isinstance(value, str) else value


class WebhookSigner:
    """
    Signs and verifies webhook payloads with a shared secret using
    HMAC-SHA256.
    """

    def __init__(self, secret: str | bytes) -> None:
        secret_bytes = _as_bytes(secret)
        if not secret_bytes:
            raise ValueError("webhook signing secret must not be empty")
        self._secret = secret_bytes

    def sign(self, payload: str | bytes) -> str:
        """
        Return the hex-encoded HMAC-SHA256 signature of the payload.
        """
        return hmac.new(
            self._secret, _as_bytes(payload), hashlib.sha256
        ).hexdigest()

    def verify(self, payload: str | bytes, signature: str) -> bool:
        """
        Constant-time check that ``signature`` is the hex digest for the
        payload. Accepts either a bare hex digest or a ``sha256=<hex>`` header.
        """
        candidate = signature
        if candidate.startswith(_HEADER_PREFIX):
            candidate = candidate[len(_HEADER_PREFIX) :]
        return hmac.compare_digest(self.sign(payload), candidate)

    def sign_header(self, payload: str | bytes) -> str:
        """
        Return the signature formatted as an ``X-Signature`` header value,
        ``sha256=<hex>``, matching the GitHub/Stripe webhook convention.
        """
        return f"{_HEADER_PREFIX}{self.sign(payload)}"

    def verify_header(self, payload: str | bytes, header: str) -> bool:
        """
        Verify a ``sha256=<hex>`` header value against the payload.
        """
        return self.verify(payload, header)
