from datetime import date, timedelta

import database
import security
from tests.conftest import ADMIN_PASS, ADMIN_USER

FUTURE = (date.today() + timedelta(days=60)).isoformat()


def csrf(client):
    client.get("/verify")  # any page that renders the base template creates a CSRF token
    with client.session_transaction() as sess:
        return sess["csrf_token"]


def login(client, password=ADMIN_PASS):
    return client.post("/login", data={"username": ADMIN_USER, "password": password, "csrf_token": csrf(client)})


def register(client, user_id="CS-001", name="Asha Rao", expiry=FUTURE):
    return client.post("/register", data={
        "name": name, "user_id": user_id, "department": "Computer Science",
        "expiry_date": expiry, "csrf_token": csrf(client)})


def verify(client, payload):
    return client.post("/api/verify", json={"payload": payload}, headers={"X-CSRF-Token": csrf(client)}).get_json()


# ---------------------------------------------------------------- admin access
def test_admin_pages_require_login(client):
    for url in ("/dashboard", "/register", "/history"):
        response = client.get(url)
        assert response.status_code == 302 and "/login" in response.headers["Location"]


def test_login_wrong_password_fails_and_right_password_works(client):
    assert login(client, "wrong-password").status_code == 401
    assert login(client).status_code == 302
    assert client.get("/dashboard").status_code == 200


def test_admin_password_is_stored_hashed(client):
    admin = database.get_admin_by_username(ADMIN_USER)
    assert admin["password_hash"] != ADMIN_PASS and "$" in admin["password_hash"]


def test_post_without_csrf_token_is_rejected(client):
    assert client.post("/login", data={"username": ADMIN_USER, "password": ADMIN_PASS}).status_code == 400
    assert client.post("/api/verify", json={"payload": "x"}).status_code == 400


def test_logout_ends_session(client):
    login(client)
    client.post("/logout", data={"csrf_token": csrf(client)})
    assert client.get("/dashboard").status_code == 302


# ------------------------------------------------------ registration + verify
def test_register_then_verify_valid(client):
    login(client)
    response = register(client)
    assert response.status_code == 200 and b"data:image/png;base64" in response.data
    payload = client.captured[-1]
    assert "Asha" not in payload and "CS-001" not in payload  # QR holds no personal data
    result = verify(client, payload)
    assert result["result"] == "VALID"
    assert result["user"]["name"] == "Asha Rao" and result["user"]["user_id"] == "CS-001"


def test_database_stores_only_token_hash(client):
    login(client)
    register(client)
    token = client.captured[-1].split(".")[1]
    user = database.list_users()[0]
    assert user["token_hash"] == security.hash_token(token) and token not in user.values()


def test_duplicate_user_id_and_bad_input_rejected(client):
    login(client)
    register(client)
    assert register(client, name="Someone Else").status_code == 400
    assert register(client, user_id="x'; DROP TABLE users;--").status_code == 400
    assert register(client, expiry="2001-01-01").status_code == 400
    assert len(database.list_users()) == 1


def test_tampered_and_forged_qr_codes_are_invalid(client):
    login(client)
    register(client)
    _, token, sig = client.captured[-1].split(".")
    flipped = ("0" if sig[0] != "0" else "1") + sig[1:]
    assert verify(client, f"CNSQR1.{token}.{flipped}")["result"] == "INVALID"
    assert verify(client, "random text")["result"] == "INVALID"
    # correctly signed token that was never registered
    fake = security.generate_token()
    assert verify(client, security.build_payload(fake))["result"] == "INVALID"
    # attacker invents name data and keeps the token
    assert verify(client, f"CNSQR1.{token}.{sig}.name=Admin")["result"] == "INVALID"


def test_expired_identity(client):
    token = security.generate_token()
    past = (date.today() - timedelta(days=1)).isoformat()
    database.create_user("OLD-1", "Old User", "CSE", past, security.hash_token(token))
    assert verify(client, security.build_payload(token))["result"] == "EXPIRED"


def test_revoked_identity(client):
    login(client)
    register(client)
    payload = client.captured[-1]
    pk = database.list_users()[0]["id"]
    assert verify(client, payload)["result"] == "VALID"
    client.post(f"/users/{pk}/revoke", data={"csrf_token": csrf(client)})
    assert verify(client, payload)["result"] == "REVOKED"
    assert database.get_user(pk)["effective_status"] == "REVOKED"


def test_revoke_requires_admin(client):
    token = security.generate_token()
    pk = database.create_user("U-1", "User One", "CSE", FUTURE, security.hash_token(token))
    response = client.post(f"/users/{pk}/revoke", data={"csrf_token": csrf(client)})
    assert response.status_code == 302 and "/login" in response.headers["Location"]
    assert verify(client, security.build_payload(token))["result"] == "VALID"


def test_new_qr_invalidates_old_qr(client):
    login(client)
    register(client)
    old_payload = client.captured[-1]
    pk = database.list_users()[0]["id"]
    client.post(f"/users/{pk}/regenerate", data={"csrf_token": csrf(client)})
    new_payload = client.captured[-1]
    assert old_payload != new_payload
    assert verify(client, old_payload)["result"] == "INVALID"
    assert verify(client, new_payload)["result"] == "VALID"


def test_every_verification_is_logged(client):
    login(client)
    register(client)
    verify(client, client.captured[-1])
    verify(client, "garbage")
    results = [log["result"] for log in database.list_logs()]
    assert sorted(results) == ["INVALID", "VALID"]
    assert client.get("/history?result=VALID").status_code == 200


def test_security_headers_present(client):
    response = client.get("/")
    assert "default-src 'self'" in response.headers["Content-Security-Policy"]
    assert "img-src 'self' data: blob:" in response.headers["Content-Security-Policy"]
    assert response.headers["X-Frame-Options"] == "DENY"
