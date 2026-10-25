"""SQLite-backed storage for private keys.

Project 1 held keys in memory, so they vanished whenever the server restarted.
Here they live in a SQLite file instead, which means a restarted (or moved)
server keeps issuing and verifying tokens with the same key material.

**Every** SQL statement in this module is a fixed string with ``?``
placeholders, and all values travel in the parameter tuple passed to
``execute``. Nothing from a row, a timestamp, or a request is ever formatted
into the SQL text. That is what makes the queries injection-proof: the driver
sends the statement and its parameters to SQLite separately, so a parameter
is always treated as a value and can never be parsed as SQL. Building the same
query with an f-string or ``%``-formatting would reintroduce exactly the
vulnerability this project is about.
"""

from __future__ import annotations

import sqlite3
from contextlib import closing

from cryptography.hazmat.primitives.asymmetric import rsa

from .keys import (
    KeyPair,
    deserialize_private_key,
    generate_private_key,
    serialize_private_key,
)

#: The database file name required by the assignment.
DEFAULT_DB_PATH = "totally_not_my_privateKeys.db"

#: Schema for the key table, exactly as the assignment specifies.
SCHEMA = """
CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
)
"""

# Statements are module-level constants so it is obvious at a glance that no
# query is assembled from runtime values.
INSERT_KEY = "INSERT INTO keys (key, exp) VALUES (?, ?)"
SELECT_VALID_KEYS = "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY kid"
SELECT_EXPIRED_KEYS = "SELECT kid, key, exp FROM keys WHERE exp <= ? ORDER BY kid"
SELECT_ONE_VALID_KEY = (
    "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY kid LIMIT 1"
)
SELECT_ONE_EXPIRED_KEY = (
    "SELECT kid, key, exp FROM keys WHERE exp <= ? ORDER BY kid LIMIT 1"
)
SELECT_KEY_BY_KID = "SELECT kid, key, exp FROM keys WHERE kid = ?"
COUNT_KEYS = "SELECT COUNT(*) FROM keys"


class KeyDatabase:
    """The ``keys`` table, wrapped in a small API.

    A new connection is opened for each operation and closed again. SQLite
    connections may not be shared between threads, and the server handles
    requests on several threads at once, so a short-lived per-operation
    connection is both the simplest and the safest arrangement at this scale.
    """

    def __init__(self, path: str = DEFAULT_DB_PATH) -> None:
        self.path = path

    def _connect(self) -> sqlite3.Connection:
        """Open a connection to the database file."""
        return sqlite3.connect(self.path)

    def initialize(self) -> None:
        """Create the key table if it does not already exist.

        Safe to call on every start-up: an existing database keeps its rows,
        which is the point of persisting keys in the first place.
        """
        with closing(self._connect()) as conn, conn:
            conn.execute(SCHEMA)

    def save_key(self, private_key: rsa.RSAPrivateKey, exp: int) -> int:
        """Store a private key with its expiry and return the assigned kid.

        The key is serialized to PKCS#1 PEM and passed as a bound parameter,
        never interpolated into the statement.
        """
        pem = serialize_private_key(private_key)
        with closing(self._connect()) as conn, conn:
            cursor = conn.execute(INSERT_KEY, (pem, int(exp)))
            kid = cursor.lastrowid
        if kid is None:  # pragma: no cover - SQLite always assigns a rowid
            raise RuntimeError("database did not assign a kid")
        return int(kid)

    def generate_and_save(self, exp: int, key_size: int) -> int:
        """Generate a fresh RSA key, store it, and return its kid."""
        return self.save_key(generate_private_key(key_size), exp)

    def _query(self, sql: str, params: tuple) -> list[KeyPair]:
        """Run a parameterized SELECT and rebuild KeyPairs from the rows."""
        with closing(self._connect()) as conn:
            rows = conn.execute(sql, params).fetchall()
        return [
            KeyPair(kid=row[0], private_key=deserialize_private_key(row[1]), exp=row[2])
            for row in rows
        ]

    def valid_keys(self, now: float) -> list[KeyPair]:
        """Every stored key that has not yet expired."""
        return self._query(SELECT_VALID_KEYS, (int(now),))

    def expired_keys(self, now: float) -> list[KeyPair]:
        """Every stored key whose expiry has passed."""
        return self._query(SELECT_EXPIRED_KEYS, (int(now),))

    def get(self, kid: int) -> KeyPair | None:
        """Fetch one key by its kid, expired or not."""
        found = self._query(SELECT_KEY_BY_KID, (kid,))
        return found[0] if found else None

    def signing_key(self, now: float, expired: bool = False) -> KeyPair | None:
        """Read the key that should sign a new token, or ``None``.

        With ``expired=False`` this is the oldest unexpired key; with
        ``expired=True`` it is the oldest expired key, which is how ``/auth``
        honours the ``expired`` query parameter. ``LIMIT 1`` keeps the server
        from deserializing key material it is not going to use.
        """
        sql = SELECT_ONE_EXPIRED_KEY if expired else SELECT_ONE_VALID_KEY
        found = self._query(sql, (int(now),))
        return found[0] if found else None

    def count(self) -> int:
        """Return the number of stored keys."""
        with closing(self._connect()) as conn:
            return int(conn.execute(COUNT_KEYS).fetchone()[0])

    def jwks(self, now: float) -> dict:
        """Build the JWK Set from the unexpired keys in the database.

        Expired keys are deliberately left out: a relying party must never be
        handed a key that would let it accept a token signed with retired
        material.
        """
        return {"keys": [key.to_jwk() for key in self.valid_keys(now)]}
