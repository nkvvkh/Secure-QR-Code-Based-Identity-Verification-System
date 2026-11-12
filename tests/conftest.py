import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ADMIN_USER = "admin"
ADMIN_PASS = "TestPass@123"


@pytest.fixture
def client(monkeypatch, tmp_path):
    """A test client using a throw-away database and test-only secret keys."""
    monkeypatch.setenv("FLASK_SECRET_KEY", "a" * 40)
    monkeypatch.setenv("QR_HMAC_KEY", "b" * 40)
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "test.db"))
    monkeypatch.setenv("ADMIN_USERNAME", ADMIN_USER)
    monkeypatch.setenv("ADMIN_PASSWORD", ADMIN_PASS)

    import app as app_module

    captured = []  # the QR payloads the app generated (so tests can "scan" them)
    real_make_qr = app_module.make_qr_data_uri

    def spy(payload):
        captured.append(payload)
        return real_make_qr(payload)

    monkeypatch.setattr(app_module, "make_qr_data_uri", spy)
    flask_app = app_module.create_app()
    flask_app.config["TESTING"] = True
    test_client = flask_app.test_client()
    test_client.captured = captured
    return test_client
