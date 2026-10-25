"""Tests for the SQLite storage layer."""

from __future__ import annotations

import sqlite3
from contextlib import closing

import pytest

from jwks_server import db as db_module
from jwks_server.db import KeyDatabase
from jwks_server.keys import deserialize_private_key

from .conftest import NOW, TEST_KEY_SIZE


def test_default_db_path_matches_the_assignment():
    assert db_module.DEFAULT_DB_PATH == "totally_not_my_privateKeys.db"


def test_initialize_creates_the_required_schema(empty_db):
    with closing(sqlite3.connect(empty_db.path)) as conn, conn:
        columns = conn.execute("PRAGMA table_info(keys)").fetchall()

    names = [column[1] for column in columns]
    types = [column[2] for column in columns]
    assert names == ["kid", "key", "exp"]
    assert types == ["INTEGER", "BLOB", "INTEGER"]
    # kid is the primary key; key and exp are NOT NULL.
    assert columns[0][5] == 1, "kid should be the primary key"
    assert columns[1][3] == 1, "key should be NOT NULL"
    assert columns[2][3] == 1, "exp should be NOT NULL"


def test_initialize_is_idempotent_and_keeps_rows(empty_db, rsa_key):
    empty_db.save_key(rsa_key, NOW + 3600)
    empty_db.initialize()
    assert empty_db.count() == 1


def test_save_key_returns_autoincrementing_kids(empty_db, rsa_key, other_rsa_key):
    first = empty_db.save_key(rsa_key, NOW + 3600)
    second = empty_db.save_key(other_rsa_key, NOW + 7200)
    assert isinstance(first, int)
    assert second > first


def test_save_key_stores_pem_that_round_trips(empty_db, rsa_key):
    kid = empty_db.save_key(rsa_key, NOW + 3600)

    with closing(sqlite3.connect(empty_db.path)) as conn, conn:
        stored = conn.execute("SELECT key FROM keys WHERE kid = ?", (kid,)).fetchone()[0]

    assert b"BEGIN RSA PRIVATE KEY" in bytes(stored)
    restored = deserialize_private_key(stored)
    assert (restored.private_numbers().p == rsa_key.private_numbers().p)


def test_save_key_coerces_float_expiry(empty_db, rsa_key):
    kid = empty_db.save_key(rsa_key, NOW + 10.9)
    assert empty_db.get(kid).exp == NOW + 10


def test_generate_and_save(empty_db):
    kid = empty_db.generate_and_save(NOW + 3600, TEST_KEY_SIZE)
    key = empty_db.get(kid)
    assert key is not None
    assert key.private_key.key_size == TEST_KEY_SIZE


def test_persistence_across_connections(tmp_path, rsa_key):
    path = str(tmp_path / "persist.db")
    first = KeyDatabase(path)
    first.initialize()
    kid = first.save_key(rsa_key, NOW + 3600)

    # A brand-new object, as if the server had been restarted.
    reopened = KeyDatabase(path)
    restored = reopened.get(kid)
    assert restored is not None
    assert restored.private_key.private_numbers().p == rsa_key.private_numbers().p


def test_valid_and_expired_partition(seeded_db):
    valid = seeded_db.valid_keys(NOW)
    expired = seeded_db.expired_keys(NOW)
    assert len(valid) == 1
    assert len(expired) == 1
    assert valid[0].kid != expired[0].kid
    assert valid[0].exp > NOW >= expired[0].exp


def test_expiry_boundary_counts_as_expired(empty_db, rsa_key):
    empty_db.save_key(rsa_key, NOW)
    assert empty_db.valid_keys(NOW) == []
    assert len(empty_db.expired_keys(NOW)) == 1


def test_queries_follow_the_clock(seeded_db):
    later = NOW + 48 * 3600
    assert seeded_db.valid_keys(later) == []
    assert len(seeded_db.expired_keys(later)) == 2


def test_get_returns_none_for_unknown_kid(seeded_db):
    assert seeded_db.get(9999) is None


def test_signing_key_selection(seeded_db):
    valid = seeded_db.signing_key(NOW)
    expired = seeded_db.signing_key(NOW, expired=True)
    assert valid.exp > NOW
    assert expired.exp <= NOW


def test_signing_key_returns_none_when_absent(empty_db, rsa_key):
    assert empty_db.signing_key(NOW) is None
    assert empty_db.signing_key(NOW, expired=True) is None

    empty_db.save_key(rsa_key, NOW + 3600)
    assert empty_db.signing_key(NOW) is not None
    assert empty_db.signing_key(NOW, expired=True) is None


def test_count(empty_db, rsa_key):
    assert empty_db.count() == 0
    empty_db.save_key(rsa_key, NOW + 3600)
    assert empty_db.count() == 1


def test_jwks_omits_expired_keys(seeded_db):
    valid_kid = seeded_db.valid_keys(NOW)[0].jwk_kid
    published = [jwk["kid"] for jwk in seeded_db.jwks(NOW)["keys"]]
    assert published == [valid_kid]


def test_jwks_on_empty_database(empty_db):
    assert empty_db.jwks(NOW) == {"keys": []}


# --- SQL injection -------------------------------------------------------


def test_every_statement_uses_placeholders():
    """No SQL in the module interpolates a value into the statement text."""
    statements = [
        db_module.INSERT_KEY,
        db_module.SELECT_VALID_KEYS,
        db_module.SELECT_EXPIRED_KEYS,
        db_module.SELECT_ONE_VALID_KEY,
        db_module.SELECT_ONE_EXPIRED_KEY,
        db_module.SELECT_KEY_BY_KID,
    ]
    for sql in statements:
        assert "?" in sql, f"{sql!r} binds no parameters"
        assert "%" not in sql and "{" not in sql, f"{sql!r} looks interpolated"


def test_injection_payload_in_kid_is_treated_as_a_value(seeded_db):
    """A classic injection string must be data, not SQL.

    If the kid were formatted into the query, this would drop the table.
    Because it is a bound parameter, it is simply a value that matches
    nothing.
    """
    payload = "1; DROP TABLE keys; --"
    assert seeded_db.get(payload) is None
    # The table survived and still holds both keys.
    assert seeded_db.count() == 2


def test_injection_payload_in_timestamp_is_treated_as_a_value(seeded_db):
    """A non-numeric 'timestamp' must not be able to alter the query."""
    with pytest.raises((ValueError, TypeError)):
        seeded_db.valid_keys("0 OR 1=1")
    assert seeded_db.count() == 2
