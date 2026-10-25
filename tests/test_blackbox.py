"""Tests for the blackbox client, run against real HTTP servers."""

from __future__ import annotations

import sqlite3
from contextlib import closing
import time

import pytest
from flask import Flask, Response

import blackbox
from jwks_server.db import KeyDatabase
from jwks_server.keys import KeyPair
from jwks_server.server import create_app

from .conftest import TEST_KEY_SIZE, serve


def test_all_checks_pass_against_a_correct_server(live_server, capsys):
    base, db_path = live_server
    results = blackbox.Results()
    blackbox.run_checks(results, base, db_path)
    assert results.failed == 0, capsys.readouterr().out
    assert results.passed >= 20


def test_main_exit_code_success(live_server):
    base, db_path = live_server
    assert blackbox.main(["--base", base, "--db", db_path]) == 0


def test_main_exit_code_failure():
    assert blackbox.main(["--base", "http://127.0.0.1:1", "--db", ""]) == 1


def test_detects_a_server_that_publishes_its_expired_key(tmp_path, rsa_key,
                                                         other_rsa_key):
    # A clock pinned in the past makes the server think neither key has
    # expired yet, so it publishes both.
    now = int(time.time())
    database = KeyDatabase(str(tmp_path / "bug.db"))
    database.initialize()
    database.save_key(rsa_key, now + 3600)
    database.save_key(other_rsa_key, now - 3600)

    base, shutdown = serve(create_app(database, clock=lambda: now - 7200))
    try:
        results = blackbox.Results()
        blackbox.run_checks(results, base)
        assert results.failed > 0
    finally:
        shutdown()


# --- database inspection ---------------------------------------------------


def test_inspect_database_passes_on_a_good_file(live_server):
    _, db_path = live_server
    results = blackbox.Results()
    blackbox.inspect_database(results, db_path)
    assert results.failed == 0


def test_inspect_database_reports_a_missing_file(tmp_path):
    results = blackbox.Results()
    blackbox.inspect_database(results, str(tmp_path / "nope.db"))
    assert results.failed == 1


def test_inspect_database_reports_a_missing_table(tmp_path):
    """A real SQLite file with no 'keys' table at all."""
    path = str(tmp_path / "notable.db")
    with closing(sqlite3.connect(path)) as conn, conn:
        conn.execute("CREATE TABLE unrelated(x INTEGER)")

    results = blackbox.Results()
    blackbox.inspect_database(results, path)
    assert results.failed > 0


def test_inspect_database_reports_a_wrong_schema(tmp_path):
    path = str(tmp_path / "wrong.db")
    with closing(sqlite3.connect(path)) as conn, conn:
        conn.execute("CREATE TABLE keys(id INTEGER PRIMARY KEY, blob BLOB)")

    results = blackbox.Results()
    blackbox.inspect_database(results, path)
    assert results.failed > 0


def test_inspect_database_reports_an_empty_table(empty_db):
    results = blackbox.Results()
    blackbox.inspect_database(results, empty_db.path)
    assert results.failed > 0


def test_inspect_database_reports_keys_that_are_not_pem(tmp_path):
    path = str(tmp_path / "notpem.db")
    now = int(time.time())
    with closing(sqlite3.connect(path)) as conn, conn:
        conn.execute(
            "CREATE TABLE keys(kid INTEGER PRIMARY KEY AUTOINCREMENT, "
            "key BLOB NOT NULL, exp INTEGER NOT NULL)"
        )
        conn.execute("INSERT INTO keys (key, exp) VALUES (?, ?)",
                     (b"\x00binary junk", now + 3600))
        conn.execute("INSERT INTO keys (key, exp) VALUES (?, ?)",
                     (b"\x00binary junk", now - 3600))

    results = blackbox.Results()
    blackbox.inspect_database(results, path)
    assert results.failed > 0


# --- HTTP helpers ----------------------------------------------------------


def make_fake(auth_body="", auth_status=200, jwks_body='{"keys": []}',
              jwks_status=200):
    app = Flask("fake")

    @app.get("/.well-known/jwks.json")
    def jwks():
        return Response(jwks_body, status=jwks_status, mimetype="application/json")

    @app.post("/auth")
    def auth():
        return Response(auth_body, status=auth_status)

    return app


@pytest.mark.parametrize(
    "fake",
    [
        make_fake(jwks_status=500),
        make_fake(jwks_body='["not", "a", "set"]'),
        make_fake(auth_status=500),
        make_fake(auth_body="no token"),
    ],
    ids=["jwks-500", "jwks-not-a-set", "auth-500", "auth-no-token"],
)
def test_reports_failures_from_broken_servers(fake):
    base, shutdown = serve(fake)
    try:
        results = blackbox.Results()
        blackbox.run_checks(results, base)
        assert results.failed > 0
    finally:
        shutdown()


def test_reports_a_token_signed_by_an_unpublished_key(rsa_key):
    import jwt as pyjwt

    token = pyjwt.encode({"exp": int(time.time()) + 60}, rsa_key,
                         algorithm="RS256", headers={"kid": "unpublished"})
    base, shutdown = serve(make_fake(auth_body=token))
    try:
        results = blackbox.Results()
        blackbox.run_checks(results, base)
        assert results.failed > 0
    finally:
        shutdown()


def test_post_auth_sends_basic_auth_and_json(live_server):
    base, _ = live_server
    with_basic = blackbox.post_auth(base + "/auth", auth=("userABC", "password123"))
    with_json = blackbox.post_auth(base + "/auth",
                                   payload=blackbox.GRADEBOT_CREDENTIALS)
    assert with_basic.count(".") == 2
    assert with_json.count(".") == 2


@pytest.mark.parametrize(
    "body",
    ['{"token": "a.b.c"}', '{"access_token": "a.b.c"}', '{"jwt": "a.b.c"}',
     "a.b.c", "a.b.c\n"],
)
def test_extract_token_shapes(body):
    assert blackbox.extract_token(body) == "a.b.c"


@pytest.mark.parametrize("body", ["", "hello world", '{"message": "x"}', "a.b"])
def test_extract_token_rejects(body):
    with pytest.raises(RuntimeError):
        blackbox.extract_token(body)


def test_public_key_for(rsa_key):
    jwk = KeyPair(5, rsa_key, int(time.time()) + 3600).to_jwk()
    jwks = {"keys": [jwk]}

    key = blackbox.public_key_for(jwks, "5")
    assert key.public_numbers() == rsa_key.public_key().public_numbers()
    assert blackbox.public_key_for(jwks, "absent") is None
    assert blackbox.public_key_for(
        {"keys": [{"kid": "bad", "kty": "RSA"}]}, "bad") is None


def test_fetch_jwks_errors(live_server):
    base, _ = live_server
    with pytest.raises(Exception):
        blackbox.fetch_jwks("http://127.0.0.1:1/jwks.json")
    with pytest.raises(RuntimeError):
        blackbox.fetch_jwks(base + "/not-a-real-path")


def test_post_auth_unreachable():
    with pytest.raises(Exception):
        blackbox.post_auth("http://127.0.0.1:1/auth")


def test_status_of_unreachable():
    assert blackbox.status_of("GET", "http://127.0.0.1:1/") == 0


def test_results_counts(capsys):
    r = blackbox.Results()
    assert r.check("ok", True) is True
    assert r.check("bad", False, "why") is False
    assert (r.passed, r.failed) == (1, 1)
    assert "why" in capsys.readouterr().out


def test_test_key_size_is_small_enough_to_be_fast():
    assert TEST_KEY_SIZE <= 1024
