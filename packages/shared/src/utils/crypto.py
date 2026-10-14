import hashlib
import hmac
import json
import secrets
from typing import Any, Dict


def generate_api_key(prefix: str = "aegis_live_") -> tuple[str, str]:
    """
    Generates a secure API key with high entropy and returns (plaintext_key, key_hash).
    The plaintext_key is shown ONLY ONCE to the user.
    The key_hash is stored in the database.
    """
    token = secrets.token_urlsafe(32)
    plaintext = f"{prefix}{token}"
    key_hash = hashlib.sha256(plaintext.encode("utf-8")).hexdigest()
    return plaintext, key_hash


def verify_api_key(plaintext_key: str, expected_hash: str) -> bool:
    """Constant-time verification of an API key against its SHA-256 hash."""
    calculated_hash = hashlib.sha256(plaintext_key.encode("utf-8")).hexdigest()
    return hmac.compare_digest(calculated_hash, expected_hash)


def compute_audit_hash(
    record_id: str,
    timestamp_iso: str,
    client_id: str,
    action: str,
    risk_score: float,
    details: Dict[str, Any],
    prev_hash: str,
    hmac_secret: str = "aegis-default-audit-secret-change-in-prod"
) -> str:
    """
    Computes a cryptographic SHA-256 HMAC for the audit chain:
    H_n = HMAC_K(H_{n-1} || record_id || timestamp || client_id || action || risk_score || canonical_json(details))
    """
    canonical_details = json.dumps(details, sort_keys=True, separators=(',', ':'))
    payload = f"{prev_hash}|{record_id}|{timestamp_iso}|{client_id}|{action}|{risk_score:.4f}|{canonical_details}"
    return hmac.new(
        hmac_secret.encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()
