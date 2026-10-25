# JWKS Server — Project 2 (SQLite-backed)

A RESTful JWKS server in Python, extending Project 1 to persist its RSA
private keys in a SQLite database. Keys now survive a restart, and every
database query is parameterized so that no value can ever be parsed as SQL.

This is an educational project. A real deployment would encrypt the stored
keys, rotate them on a schedule, serve TLS, and authenticate users for real.

**Author:** Rupesh Pokharel

## What changed since Project 1

| Project 1 | Project 2 |
| --- | --- |
| Keys held in an in-memory `KeyStore` | Keys stored in `totally_not_my_privateKeys.db` |
| Keys lost on restart | Keys reloaded from disk on restart |
| `kid` was a random hex string | `kid` is the database row's `INTEGER PRIMARY KEY` |
| — | Private keys serialized to PKCS#1 PEM for storage |
| — | All SQL uses bound `?` parameters |

## Stack

- **Flask** for HTTP. It answers a wrong method with `405` plus an `Allow`
  header and an unknown path with `404`.
- **sqlite3** from the standard library for storage.
- **cryptography** to generate and serialize the RSA keys.
- **PyJWT** to sign the tokens.
- **pytest**, **pytest-cov** and **flake8** for testing and linting.

Requires Python 3.9 or newer.

## Setup and running

```sh
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt

python main.py                     # serves http://127.0.0.1:8080
```

On start-up the server creates `totally_not_my_privateKeys.db` in the current
directory if it does not exist, then makes sure the table holds at least one
unexpired key and one expired key. Keys written by an earlier run are kept and
reused, so restarting does not invalidate tokens already issued or pile up
redundant rows.

Options: `--host`, `--port`, `--db` (database path), `--key-size`.

The database file is listed in `.gitignore`. It holds unencrypted private
keys, so it is a runtime artifact rather than something to commit; the server
recreates it on first run.

## The database

File: `totally_not_my_privateKeys.db`, in the current working directory, which
is where the grading client looks for it.

```sql
CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
)
```

- **`kid`** — assigned by SQLite. It is an integer in the database and is
  published as a string in the JWKS, because RFC 7517 requires `kid` to be a
  string.
- **`key`** — the private key in PKCS#1 PEM form (`BEGIN RSA PRIVATE KEY`).
  SQLite has no RSA key type, so the key is serialized on save and
  deserialized on read.
- **`exp`** — the expiry as a Unix timestamp. A key counts as expired once
  `now >= exp`.

### Avoiding SQL injection

Every statement in `jwks_server/db.py` is a module-level constant containing
`?` placeholders, and values are passed in the parameter tuple:

```python
SELECT_ONE_VALID_KEY = (
    "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY kid LIMIT 1"
)
...
conn.execute(SELECT_ONE_VALID_KEY, (int(now),))
```

The driver sends the statement and its parameters to SQLite separately, so a
parameter is always a value and can never be parsed as SQL. Building the same
query with an f-string would reintroduce exactly the vulnerability this
project is about. Two tests in `tests/test_db.py` assert this directly: one
checks that no statement contains interpolation syntax, and another passes
`"1; DROP TABLE keys; --"` as a `kid` and confirms the table survives.

## Endpoints

### `GET /.well-known/jwks.json`

Reads all unexpired keys from the database and returns them as a JWK Set.
Expired keys are never published, so a verifier cannot accept a token signed
with retired key material. `GET /jwks.json` is an alias.

```json
{"keys": [{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "1",
           "n": "yuRqdr5YvvGde0cmvEzsOpTNB-2h10Yg...", "e": "AQAB"}]}
```

### `POST /auth`

Reads a private key from the database, signs a JWT with it, and returns the
token as the raw response body.

```sh
curl -X POST http://localhost:8080/auth
```

- Header: `{"alg": "RS256", "typ": "JWT", "kid": "1"}`
- Claims: `{"sub": "userABC", "iss": "jwks-server", "iat": ..., "exp": ...}`

Authentication is mocked. The grading client sends HTTP Basic credentials on
one request and a JSON body of `{"username": "userABC", "password":
"password123"}` on another; both are accepted and ignored. The request body is
never parsed, so even a malformed one cannot fail the request.

If the **`expired`** query parameter is present, the server reads an *expired*
key from the database instead and sets the token's `exp` to that key's past
expiry. The signature is genuine — the token is stale, not forged — but the
signing `kid` is absent from the JWKS, so a verifier following the key set
cannot accept it.

Any method other than `POST` returns `405`.

## Layout

```
main.py               start-up: create/seed the database, run on :8080
blackbox.py           external test client (see below)
jwks_server/
  keys.py             RSA generation, PEM serialization, JWK encoding
  db.py               the SQLite layer — schema and all parameterized queries
  server.py           Flask app: JWKS endpoint and /auth
tests/                pytest suite
docs/                 screenshots
```

A new SQLite connection is opened per operation and closed again, because
connections cannot be shared between threads and the server handles requests
on several threads at once.

## Tests and coverage

```sh
pytest --cov                      # enforces >= 80% via setup.cfg
pytest --cov --cov-report=html    # annotated report in htmlcov/
```

115 tests; line and branch coverage are both **100%**. The two
`if __name__ == "__main__"` entry points and `main.main()` (which only calls
`app.run()`) are marked `# pragma: no cover`; the logic they call,
`seed_database` and `parse_args`, is tested directly.

Beyond the happy paths, the suite covers the schema itself (column names,
types, NOT NULL and primary-key flags), PEM round-tripping through the
database, restart persistence via a second `KeyDatabase` object over the same
file, `seed_database` being idempotent and topping up a missing key kind, the
expiry boundary, both gradebot authentication styles, and the two SQL
injection cases described above.

## Blackbox test client

`blackbox.py` checks the server over HTTP and inspects the database file the
way the gradebot does:

```sh
python main.py        # terminal 1
python blackbox.py    # terminal 2
```

It verifies the database file, schema, and contents; that issued tokens verify
against the published JWKS; that both gradebot authentication styles work;
that the expired token's `kid` is not published; and the status codes. It
exits non-zero on any failure. Options: `--base`, `--db`, `--student`.

## Linting

```sh
flake8        # clean; configured in setup.cfg (max line length 100)
```

## Acknowledgment of AI use

This project was built using Claude (Anthropic). Claude wrote the code in this
repository — the SQLite storage layer, the key serialization and JWK encoding,
the Flask endpoints, the test suite, and the blackbox client — as well as this README. I revised and did some edits in this README.
My prompts were brief: I attached the Project 2 assignment description
along with my Project 1 files and asked Claude to extend the server to use
SQLite. I ran the server and the test suite on my own machine, verified the
database and the restart behaviour, and captured the screenshots in `docs/`
myself. A fuller account, including the specific prompts, is in
[AI_USE.md](AI_USE.md).
