import os
from datetime import date, timedelta

import pytest

os.environ.setdefault("QR_HMAC_KEY", "k" * 40)
import security  # noqa: E402

KEY = b"unit-test-secret-key-0123456789abcdef"


def test_tokens_are_random_and_long_enough():
    tokens = {security.generate_token() for _ in range(200)}
    assert len(tokens) == 200
    assert all(len(t) == 43 for t in tokens)


def test_signature_is_hmac_sha256_hex():
    sig = security.sign_token("abc", KEY)
    assert len(sig) == 64 and int(sig, 16) >= 0
    assert sig == security.sign_token("abc", KEY)  # deterministic


def test_signature_changes_with_token_or_key():
    assert security.sign_token("abc", KEY) != security.sign_token("abd", KEY)
    assert security.sign_token("abc", KEY) != security.sign_token("abc", b"another-key-another-key-another-key")


def test_verify_signature_accepts_good_and_rejects_bad():
    token = security.generate_token()
    good = security.sign_token(token, KEY)
    assert security.verify_signature(token, good, KEY)
    bad = ("0" if good[0] != "0" else "1") + good[1:]
    assert not security.verify_signature(token, bad, KEY)
    assert not security.verify_signature(token + "x", good, KEY)


def test_payload_round_trip_and_tampering():
    token = security.generate_token()
    payload = security.build_payload(token, KEY)
    assert payload.startswith("CNSQR1.")
    assert security.parse_payload(payload) == (token, security.sign_token(token, KEY))
    assert "name" not in payload.lower()  # no personal data inside the QR


@pytest.mark.parametrize("bad", [None, "", "hello", "CNSQR1.abc.def", "XXXX.a.b", "A" * 500,
                                 "CNSQR1." + "a" * 43 + ".ZZZZ", "CNSQR1.a.b.c", 12345])
def test_parse_payload_rejects_malformed_input(bad):
    assert security.parse_payload(bad) is None


def test_token_hash_is_sha256_and_not_the_token():
    token = security.generate_token()
    h = security.hash_token(token)
    assert len(h) == 64 and h != token and h == security.hash_token(token)


def test_missing_or_short_hmac_key_is_refused(monkeypatch):
    monkeypatch.setenv("QR_HMAC_KEY", "short")
    with pytest.raises(RuntimeError):
        security.get_hmac_key()
    monkeypatch.delenv("QR_HMAC_KEY")
    with pytest.raises(RuntimeError):
        security.get_hmac_key()


def test_validation_accepts_good_and_rejects_unsafe_input():
    future = (date.today() + timedelta(days=30)).isoformat()
    assert security.validate_registration("Asha Rao", "CS-2026_01", "Computer Science", future) == []
    assert security.validate_registration("<script>x</script>", "CS-01", "CSE", future)
    assert security.validate_registration("Asha", "x'; DROP TABLE users;--", "CSE", future)
    assert security.validate_registration("Asha", "CS-01", "CSE", "2000-01-01")
    assert security.validate_registration("Asha", "CS-01", "CSE", "not-a-date")
    far = (date.today() + timedelta(days=4000)).isoformat()
    assert security.validate_registration("Asha", "CS-01", "CSE", far)


def test_rate_limiter_blocks_after_limit():
    limiter = security.RateLimiter(max_calls=3, period_seconds=60)
    assert [limiter.allow("ip") for _ in range(4)] == [True, True, True, False]
    assert limiter.allow("other-ip")
