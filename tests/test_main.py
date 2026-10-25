"""Tests for start-up wiring in main.py."""

from __future__ import annotations

import time

import main
from jwks_server.db import DEFAULT_DB_PATH, KeyDatabase

from .conftest import TEST_KEY_SIZE


def test_seed_database_creates_one_valid_and_one_expired_key(tmp_path):
    now = time.time()
    database = main.seed_database(
        KeyDatabase(str(tmp_path / "seed.db")), now, TEST_KEY_SIZE
    )

    valid = database.valid_keys(now)
    expired = database.expired_keys(now)
    assert len(valid) == 1
    assert len(expired) == 1
    assert valid[0].kid != expired[0].kid
    assert valid[0].exp == int(now) + main.VALID_KEY_TTL
    assert expired[0].exp == int(now) - main.EXPIRED_KEY_AGE


def test_seed_database_is_idempotent(tmp_path):
    """A restart must reuse the stored keys rather than adding more."""
    now = time.time()
    path = str(tmp_path / "restart.db")

    first = main.seed_database(KeyDatabase(path), now, TEST_KEY_SIZE)
    kids = {key.kid for key in first.valid_keys(now) + first.expired_keys(now)}
    assert first.count() == 2

    second = main.seed_database(KeyDatabase(path), now, TEST_KEY_SIZE)
    assert second.count() == 2
    assert {k.kid for k in second.valid_keys(now) + second.expired_keys(now)} == kids


def test_seed_database_tops_up_a_missing_kind(tmp_path, rsa_key):
    """A database with only an expired key gains a valid one, and vice versa."""
    now = time.time()
    database = KeyDatabase(str(tmp_path / "topup.db"))
    database.initialize()
    database.save_key(rsa_key, int(now) - 3600)

    main.seed_database(database, now, TEST_KEY_SIZE)
    assert len(database.valid_keys(now)) == 1
    assert len(database.expired_keys(now)) == 1
    assert database.count() == 2


def test_parse_args_defaults():
    args = main.parse_args([])
    assert args.port == 8080
    assert args.host == "127.0.0.1"
    assert args.db == DEFAULT_DB_PATH
    assert args.key_size == 2048


def test_parse_args_overrides():
    args = main.parse_args(
        ["--port", "9000", "--host", "0.0.0.0", "--db", "other.db",
         "--key-size", "4096"]
    )
    assert (args.port, args.host, args.db, args.key_size) == (
        9000, "0.0.0.0", "other.db", 4096
    )
