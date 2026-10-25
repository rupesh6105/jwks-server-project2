"""Run the SQLite-backed JWKS server on port 8080.

On start-up the database file is created if it does not exist, and the server
makes sure it holds at least one expired key and one unexpired key so that
both ``POST /auth`` and ``POST /auth?expired=true`` can be exercised. Keys
already stored by an earlier run are kept: that persistence is the point of
Project 2.

This is an educational project. A real deployment would encrypt the stored
keys, rotate them on a schedule, serve TLS, and authenticate users for real.
"""

from __future__ import annotations

import argparse
import logging
import time

from jwks_server.db import DEFAULT_DB_PATH, KeyDatabase
from jwks_server.keys import DEFAULT_KEY_SIZE
from jwks_server.server import create_app

#: How long a freshly generated signing key remains valid, in seconds.
VALID_KEY_TTL = 60 * 60

#: How far in the past the expired key's expiry is set, in seconds.
EXPIRED_KEY_AGE = 60 * 60

log = logging.getLogger("jwks-server")


def seed_database(database: KeyDatabase, now: float,
                  key_size: int = DEFAULT_KEY_SIZE) -> KeyDatabase:
    """Create the schema and ensure both kinds of key are present.

    A key is generated only when the database has none of that kind, so
    restarting the server does not pile up redundant rows.
    """
    database.initialize()

    if not database.valid_keys(now):
        kid = database.generate_and_save(int(now) + VALID_KEY_TTL, key_size)
        log.info("stored new valid key kid=%s", kid)

    if not database.expired_keys(now):
        kid = database.generate_and_save(int(now) - EXPIRED_KEY_AGE, key_size)
        log.info("stored new expired key kid=%s", kid)

    log.info("database %s holds %d key(s)", database.path, database.count())
    return database


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line options."""
    parser = argparse.ArgumentParser(
        description="Run the SQLite-backed JWKS server."
    )
    parser.add_argument("--host", default="127.0.0.1", help="interface to bind")
    parser.add_argument("--port", type=int, default=8080, help="port to listen on")
    parser.add_argument("--db", default=DEFAULT_DB_PATH,
                        help="path to the SQLite database file")
    parser.add_argument("--key-size", type=int, default=DEFAULT_KEY_SIZE,
                        help="RSA modulus size in bits")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:  # pragma: no cover
    """Entry point: prepare the database and serve until interrupted."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    args = parse_args(argv)
    database = seed_database(KeyDatabase(args.db), time.time(), args.key_size)
    app = create_app(database)
    app.run(host=args.host, port=args.port, threaded=True)


if __name__ == "__main__":  # pragma: no cover
    main()
