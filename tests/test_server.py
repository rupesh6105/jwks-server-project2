"""Tests for the HTTP endpoints, which now read from SQLite."""

from __future__ import annotations

import base64
import json

import jwt
import pytest
from jwt.algorithms import RSAAlgorithm

from jwks_server.db import KeyDatabase
from jwks_server.server import (
    AUTH_PATH,
    ISSUER,
    JWKS_ALT_PATH,
    JWKS_PATH,
    MOCK_SUBJECT,
    TOKEN_TTL,
    create_app,
)

from .conftest import NOW, TEST_KEY_SIZE


def published_key(client, kid):
    """Rebuild the public key the JWKS publishes under ``kid``, or None."""
    for jwk in client.get(JWKS_PATH).get_json()["keys"]:
        if jwk["kid"] == kid:
            return RSAAlgorithm.from_jwk(json.dumps(jwk))
    return None


# --- JWKS ------------------------------------------------------------------


def test_jwks_ok_json(client):
    resp = client.get(JWKS_PATH)
    assert resp.status_code == 200
    assert resp.mimetype == "application/json"
    assert resp.headers["Cache-Control"] == "no-store"


def test_jwks_serves_only_unexpired_keys(client, seeded_db):
    expected = seeded_db.valid_keys(NOW)[0].jwk_kid
    kids = [k["kid"] for k in client.get(JWKS_PATH).get_json()["keys"]]
    assert kids == [expected]


def test_jwks_reflects_a_key_added_to_the_database(client, seeded_db):
    before = len(client.get(JWKS_PATH).get_json()["keys"])
    seeded_db.generate_and_save(NOW + 7200, TEST_KEY_SIZE)
    after = client.get(JWKS_PATH).get_json()["keys"]
    assert len(after) == before + 1


def test_jwks_alt_path(client):
    assert client.get(JWKS_ALT_PATH).get_json() == client.get(JWKS_PATH).get_json()


def test_jwks_head_is_allowed(client):
    assert client.head(JWKS_PATH).status_code == 200


@pytest.mark.parametrize("method", ["post", "put", "delete", "patch"])
def test_jwks_rejects_other_methods(client, method):
    resp = getattr(client, method)(JWKS_PATH)
    assert resp.status_code == 405
    assert "GET" in resp.headers["Allow"]


def test_jwks_empties_as_keys_expire(empty_db, rsa_key):
    empty_db.save_key(rsa_key, NOW + 60)
    now = [NOW]
    c = create_app(empty_db, clock=lambda: now[0]).test_client()

    assert len(c.get(JWKS_PATH).get_json()["keys"]) == 1
    now[0] = NOW + 120
    assert c.get(JWKS_PATH).get_json()["keys"] == []


# --- /auth -----------------------------------------------------------------


def test_auth_returns_raw_jwt(client):
    resp = client.post(AUTH_PATH)
    assert resp.status_code == 200
    assert resp.headers["Cache-Control"] == "no-store"
    assert resp.get_data(as_text=True).count(".") == 2


def test_auth_token_verifies_against_published_jwks(client):
    token = client.post(AUTH_PATH).get_data(as_text=True)
    header = jwt.get_unverified_header(token)
    assert header["alg"] == "RS256"

    key = published_key(client, header["kid"])
    assert key is not None, "signing kid must be in the JWKS"

    claims = jwt.decode(token, key, algorithms=["RS256"],
                        options={"verify_exp": False, "verify_iat": False})
    assert claims["sub"] == MOCK_SUBJECT
    assert claims["iss"] == ISSUER
    assert claims["iat"] == NOW
    assert claims["exp"] == NOW + TOKEN_TTL


def test_auth_uses_the_key_the_database_returns(client, seeded_db):
    expected = seeded_db.signing_key(NOW).jwk_kid
    token = client.post(AUTH_PATH).get_data(as_text=True)
    assert jwt.get_unverified_header(token)["kid"] == expected


def test_auth_expired_issues_expired_token(client, seeded_db):
    expired_key = seeded_db.signing_key(NOW, expired=True)
    token = client.post(AUTH_PATH + "?expired=true").get_data(as_text=True)

    assert jwt.get_unverified_header(token)["kid"] == expired_key.jwk_kid

    # The signature is genuine — the token is stale, not forged...
    claims = jwt.decode(token, expired_key.public_key, algorithms=["RS256"],
                        options={"verify_exp": False})
    assert claims["exp"] == expired_key.exp <= NOW
    assert claims["iat"] < claims["exp"]

    # ...and a normal verification rejects it as expired.
    with pytest.raises(jwt.ExpiredSignatureError):
        jwt.decode(token, expired_key.public_key, algorithms=["RS256"])


def test_auth_expired_kid_absent_from_jwks(client):
    token = client.post(AUTH_PATH + "?expired=true").get_data(as_text=True)
    kid = jwt.get_unverified_header(token)["kid"]
    assert published_key(client, kid) is None


@pytest.mark.parametrize(
    "query", ["?expired", "?expired=", "?expired=true", "?expired=1", "?expired=x"]
)
def test_auth_expired_parameter_presence(client, seeded_db, query):
    expected = seeded_db.signing_key(NOW, expired=True).jwk_kid
    token = client.post(AUTH_PATH + query).get_data(as_text=True)
    assert jwt.get_unverified_header(token)["kid"] == expected


def test_auth_ignores_unrelated_parameters(client, seeded_db):
    expected = seeded_db.signing_key(NOW).jwk_kid
    token = client.post(AUTH_PATH + "?other=expired").get_data(as_text=True)
    assert jwt.get_unverified_header(token)["kid"] == expected


# The gradebot authenticates in two different ways; both are ignored but
# neither may break the request.


def test_auth_accepts_http_basic_auth(client):
    credentials = base64.b64encode(b"userABC:password123").decode("ascii")
    resp = client.post(AUTH_PATH, headers={"Authorization": f"Basic {credentials}"})
    assert resp.status_code == 200
    assert resp.get_data(as_text=True).count(".") == 2


def test_auth_accepts_json_credentials(client):
    resp = client.post(AUTH_PATH,
                       json={"username": "userABC", "password": "password123"})
    assert resp.status_code == 200
    assert resp.get_data(as_text=True).count(".") == 2


@pytest.mark.parametrize(
    "body", ["", "not json at all", '{"username": "x"}', '{"broken": '],
)
def test_auth_ignores_any_body(client, body):
    resp = client.post(AUTH_PATH, data=body,
                       headers={"Content-Type": "application/json"})
    assert resp.status_code == 200


@pytest.mark.parametrize("method", ["get", "put", "delete", "patch", "head"])
def test_auth_rejects_other_methods(client, method):
    resp = getattr(client, method)(AUTH_PATH)
    assert resp.status_code == 405
    assert "POST" in resp.headers["Allow"]


@pytest.mark.parametrize("path", [AUTH_PATH, AUTH_PATH + "?expired=true"])
def test_auth_500_when_database_has_no_such_key(empty_db, path):
    c = create_app(empty_db, clock=lambda: NOW).test_client()
    assert c.post(path).status_code == 500


@pytest.mark.parametrize("path", ["/", "/nope", "/.well-known/", "/auth/extra"])
def test_unknown_paths_404(client, path):
    assert client.get(path).status_code == 404


def test_default_clock_is_wall_time(tmp_path, rsa_key, other_rsa_key):
    import time

    now = int(time.time())
    database = KeyDatabase(str(tmp_path / "clock.db"))
    database.initialize()
    valid = database.save_key(rsa_key, now + 3600)
    database.save_key(other_rsa_key, now - 3600)

    c = create_app(database).test_client()
    kids = [k["kid"] for k in c.get(JWKS_PATH).get_json()["keys"]]
    assert kids == [str(valid)]
