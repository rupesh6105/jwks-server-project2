"""Shared fixtures: pre-generated keys, a pinned clock, and seeded databases."""

from __future__ import annotations

import threading

import pytest
from werkzeug.serving import make_server

from jwks_server.db import KeyDatabase
from jwks_server.keys import generate_private_key
from jwks_server.server import create_app

#: A fixed "now" so expiry behaviour never depends on wall-clock time.
NOW = 1_735_732_800  # 2025-01-01T12:00:00Z

#: Small keys keep the suite fast; the production default is 2048 bits.
TEST_KEY_SIZE = 1024


@pytest.fixture(scope="session")
def rsa_key():
    """One RSA key reused across tests, since generation is the slow part."""
    return generate_private_key(TEST_KEY_SIZE)


@pytest.fixture(scope="session")
def other_rsa_key():
    """A second, unrelated RSA key."""
    return generate_private_key(TEST_KEY_SIZE)


@pytest.fixture
def empty_db(tmp_path):
    """An initialized but empty database in a temporary directory."""
    database = KeyDatabase(str(tmp_path / "totally_not_my_privateKeys.db"))
    database.initialize()
    return database


@pytest.fixture
def seeded_db(empty_db, rsa_key, other_rsa_key):
    """A database holding one unexpired key and one expired key."""
    empty_db.save_key(rsa_key, NOW + 3600)
    empty_db.save_key(other_rsa_key, NOW - 3600)
    return empty_db


@pytest.fixture
def client(seeded_db):
    """A Flask test client whose clock is pinned to NOW."""
    app = create_app(seeded_db, clock=lambda: NOW)
    app.testing = True
    return app.test_client()


def serve(app):
    """Run ``app`` on an ephemeral port in a background thread.

    Returns ``(base_url, shutdown)``.
    """
    server = make_server("127.0.0.1", 0, app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def shutdown():
        server.shutdown()
        thread.join(timeout=5)

    return f"http://127.0.0.1:{server.server_port}", shutdown


@pytest.fixture
def live_server(tmp_path, rsa_key, other_rsa_key):
    """A real HTTP server on wall-clock time, for blackbox tests.

    Returns ``(base_url, db_path)``.
    """
    import time

    now = int(time.time())
    path = str(tmp_path / "totally_not_my_privateKeys.db")
    database = KeyDatabase(path)
    database.initialize()
    database.save_key(rsa_key, now + 3600)
    database.save_key(other_rsa_key, now - 3600)

    base, shutdown = serve(create_app(database))
    yield base, path
    shutdown()
