"""
security.py - all cryptography and input-validation helpers.

QR payload format:   CNSQR1.<token>.<signature>
  token     = 43-character random string from Python's `secrets` module
  signature = HMAC-SHA256(secret_key, token) written as 64 hex characters

The QR code never contains a name, department, or any other personal data.
"""
import hashlib
import hmac
import os
import re
import secrets
import time
from collections import defaultdict, deque
from datetime import date, timedelta

PAYLOAD_PREFIX = "CNSQR1"
MAX_PAYLOAD_LENGTH = 200

USER_ID_RE = re.compile(r"[A-Za-z0-9_-]{3,32}")
NAME_RE = re.compile(r"[A-Za-z][A-Za-z .'-]{1,59}")
DEPT_RE = re.compile(r"[A-Za-z0-9 &.,'()-]{2,60}")
TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{43}")
SIGNATURE_RE = re.compile(r"[0-9a-f]{64}")


# ---------------------------------------------------------------- secret key
def get_hmac_key():
    """Read the HMAC secret from the environment (never hard-coded)."""
    key = os.environ.get("QR_HMAC_KEY", "")
    if len(key) < 32:
        raise RuntimeError(
            "QR_HMAC_KEY is missing or too short (need at least 32 characters). "
            "Copy .env.example to .env and set it."
        )
    return key.encode("utf-8")


# -------------------------------------------------------------- token + HMAC
def generate_token():
    """Cryptographically secure random token (256 bits of randomness)."""
    return secrets.token_urlsafe(32)  # always 43 URL-safe characters


def sign_token(token, key=None):
    """HMAC-SHA256 signature of the token, as a lowercase hex string."""
    key = key or get_hmac_key()
    return hmac.new(key, token.encode("utf-8"), hashlib.sha256).hexdigest()


def hash_token(token):
    """SHA-256 hash of the token. Only this hash is stored in the database,
    so a stolen database does not reveal usable QR tokens."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def build_payload(token, key=None):
    return f"{PAYLOAD_PREFIX}.{token}.{sign_token(token, key)}"


def parse_payload(text):
    """Return (token, signature) if the text has the right shape, else None."""
    if not isinstance(text, str) or len(text) > MAX_PAYLOAD_LENGTH:
        return None
    parts = text.strip().split(".")
    if len(parts) != 3 or parts[0] != PAYLOAD_PREFIX:
        return None
    _, token, signature = parts
    if not TOKEN_RE.fullmatch(token) or not SIGNATURE_RE.fullmatch(signature):
        return None
    return token, signature


def verify_signature(token, signature, key=None):
    """Constant-time comparison, so timing differences leak nothing."""
    expected = sign_token(token, key)
    return hmac.compare_digest(expected.encode("utf-8"), signature.encode("utf-8"))


# --------------------------------------------------------------------- CSRF
def get_csrf_token(session):
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


def validate_csrf(session, sent_token):
    expected = session.get("csrf_token")
    if not expected or not sent_token:
        return False
    return hmac.compare_digest(expected.encode("utf-8"), str(sent_token).encode("utf-8"))


# ---------------------------------------------------------- input validation
def validate_registration(name, user_id, department, expiry_text, today=None):
    """Return a list of error messages (empty list = everything is valid)."""
    errors = []
    today = today or date.today()
    if not NAME_RE.fullmatch(name or ""):
        errors.append("Name must be 2-60 characters (letters, spaces, . ' - only).")
    if not USER_ID_RE.fullmatch(user_id or ""):
        errors.append("User ID must be 3-32 characters (letters, digits, _ or - only).")
    if not DEPT_RE.fullmatch(department or ""):
        errors.append("Department must be 2-60 characters (letters, digits and basic punctuation).")
    try:
        expiry = date.fromisoformat(expiry_text or "")
        if expiry <= today:
            errors.append("Expiry date must be in the future.")
        elif expiry > today + timedelta(days=3650):
            errors.append("Expiry date cannot be more than 10 years away.")
    except ValueError:
        errors.append("Expiry date must be a valid date.")
    return errors


# ------------------------------------------------------------- rate limiting
class RateLimiter:
    """Very small in-memory limiter: max_calls per period_seconds for each key."""

    def __init__(self, max_calls, period_seconds):
        self.max_calls = max_calls
        self.period = period_seconds
        self._hits = defaultdict(deque)

    def allow(self, key):
        now = time.monotonic()
        hits = self._hits[key]
        while hits and now - hits[0] > self.period:
            hits.popleft()
        if len(hits) >= self.max_calls:
            return False
        hits.append(now)
        return True
