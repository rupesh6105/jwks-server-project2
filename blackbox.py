"""Blackbox test client for a running SQLite-backed JWKS server.

It talks to the server over HTTP the way an external grader does, and also
inspects the database file the way the course's gradebot does, checking:

* the SQLite file exists, uses the required schema, and holds both an expired
  and an unexpired key, stored as PEM;
* ``POST /auth`` returns a JWT whose ``kid`` is published in the JWKS and
  whose signature verifies against that published key;
* ``POST /auth`` works with HTTP Basic auth and with a JSON credential body,
  which is what the gradebot sends;
* ``POST /auth?expired=true`` returns an already-expired JWT whose signing
  ``kid`` is absent from the JWKS;
* wrong methods get 405 and unknown paths 404.

Usage::

    python blackbox.py --base http://localhost:8080
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
import time
from datetime import datetime

import jwt
import requests
from jwt.algorithms import RSAAlgorithm

GREEN, RED, DIM, BOLD, RESET = "\033[32m", "\033[31m", "\033[2m", "\033[1m", "\033[0m"
TIMEOUT = 5

#: Credentials the gradebot sends. They are ignored by the server.
GRADEBOT_CREDENTIALS = {"username": "userABC", "password": "password123"}


class Results:
    """Accumulates and prints pass/fail outcomes."""

    def __init__(self) -> None:
        self.passed = 0
        self.failed = 0

    def check(self, name: str, ok: bool, detail: str = "") -> bool:
        if ok:
            self.passed += 1
            print(f"  {GREEN}PASS{RESET}  {name}")
        else:
            self.failed += 1
            print(f"  {RED}FAIL{RESET}  {name}\n        {DIM}{detail}{RESET}")
        return ok


def fetch_jwks(url: str) -> dict:
    """GET and decode the key set; raise on any problem."""
    resp = requests.get(url, timeout=TIMEOUT)
    if resp.status_code != 200:
        raise RuntimeError(f"status {resp.status_code}")
    data = resp.json()
    if not isinstance(data, dict) or not isinstance(data.get("keys"), list):
        raise RuntimeError("response is not a JWK Set")
    return data


def extract_token(body: str) -> str:
    """Pull a JWT out of a response body, raw or wrapped in JSON."""
    text = body.strip()
    try:
        data = json.loads(text)
    except ValueError:
        data = None
    if isinstance(data, dict):
        for field in ("token", "access_token", "jwt"):
            value = data.get(field)
            if isinstance(value, str) and value.count(".") == 2:
                return value
    if text.count(".") == 2 and " " not in text:
        return text
    raise RuntimeError(f"no JWT found in response {text[:80]!r}")


def post_auth(url: str, *, auth=None, payload=None) -> str:
    """POST to /auth and return the issued token.

    ``auth`` sends HTTP Basic credentials and ``payload`` sends a JSON body;
    the gradebot tries both, and the server must accept either.
    """
    resp = requests.post(url, auth=auth, json=payload, timeout=TIMEOUT)
    if resp.status_code != 200:
        raise RuntimeError(f"status {resp.status_code}")
    return extract_token(resp.text)


def public_key_for(jwks: dict, kid: str):
    """Rebuild the published public key with ``kid``, or return ``None``."""
    for jwk in jwks.get("keys", []):
        if jwk.get("kid") == kid:
            try:
                return RSAAlgorithm.from_jwk(json.dumps(jwk))
            except Exception:  # malformed JWK
                return None
    return None


def status_of(method: str, url: str) -> int:
    """Return the status code of a bare request, or 0 if it failed."""
    try:
        return requests.request(method, url, timeout=TIMEOUT).status_code
    except requests.RequestException:
        return 0


def inspect_database(results: Results, db_path: str) -> None:
    """Check the SQLite file the server persists its keys to."""
    print("SQLite storage")
    if not results.check(f"the database file {db_path} exists",
                         os.path.isfile(db_path), "file not found"):
        return

    conn = sqlite3.connect(db_path)
    try:
        columns = conn.execute("PRAGMA table_info(keys)").fetchall()
        names = [column[1] for column in columns]
        if not results.check("a 'keys' table exists", bool(columns),
                             "no such table"):
            return
        # Without the expected columns the queries below cannot run at all,
        # so stop here rather than letting SQLite raise.
        if not results.check("its columns are kid, key, exp",
                             names == ["kid", "key", "exp"], str(names)):
            return

        rows = conn.execute("SELECT kid, key, exp FROM keys ORDER BY kid").fetchall()
        results.check("it holds at least one key", len(rows) > 0, "table is empty")

        now = time.time()
        results.check("it holds an unexpired key",
                      any(row[2] > now for row in rows), "none found")
        results.check("it holds an expired key",
                      any(row[2] <= now for row in rows), "none found")

        pem_ok = all(b"PRIVATE KEY" in bytes(row[1]) for row in rows)
        results.check("every stored key is serialized as PEM", pem_ok,
                      "a row does not look like PEM")
    finally:
        conn.close()


def run_checks(results: Results, base: str, db_path: str | None = None) -> None:
    """Run every check against the server at ``base``."""
    if db_path:
        inspect_database(results, db_path)
        print()

    print("JWKS endpoint")
    try:
        jwks = fetch_jwks(base + "/.well-known/jwks.json")
    except Exception as exc:  # noqa: BLE001 - report any failure
        results.check("GET /.well-known/jwks.json returns a JWK Set", False, str(exc))
        return
    results.check("GET /.well-known/jwks.json returns a JWK Set", True)
    results.check("the set contains at least one key", len(jwks["keys"]) > 0,
                  "empty set")
    for jwk in jwks["keys"]:
        complete = (jwk.get("kty") == "RSA" and jwk.get("alg") == "RS256"
                    and all(jwk.get(f) for f in ("kid", "n", "e")))
        results.check(f"key {jwk.get('kid')} is a complete RSA signing JWK",
                      complete, str(jwk))

    print("\nValid JWT authentication")
    try:
        token = post_auth(base + "/auth")
        results.check("POST /auth returns 200 and a JWT", True)
    except Exception as exc:  # noqa: BLE001
        results.check("POST /auth returns 200 and a JWT", False, str(exc))
        token = None
    if token:
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        results.check("the JWT header carries a kid", bool(kid), "no kid")
        results.check("the JWT header declares RS256",
                      header.get("alg") == "RS256", str(header.get("alg")))
        key = public_key_for(jwks, kid)
        if results.check("the signing kid is published in the JWKS",
                         key is not None, f"kid {kid!r} not in set"):
            try:
                jwt.decode(token, key, algorithms=["RS256"])
                results.check("the JWT verifies and is unexpired", True)
            except jwt.PyJWTError as exc:
                results.check("the JWT verifies and is unexpired", False, str(exc))

    print("\nGradebot authentication styles")
    for label, kwargs in (
        ("HTTP Basic auth", {"auth": ("userABC", "password123")}),
        ("a JSON credential body", {"payload": GRADEBOT_CREDENTIALS}),
    ):
        try:
            issued = post_auth(base + "/auth", **kwargs)
            ok = issued.count(".") == 2
            results.check(f"POST /auth with {label} returns a JWT", ok, issued[:60])
        except Exception as exc:  # noqa: BLE001
            results.check(f"POST /auth with {label} returns a JWT", False, str(exc))

    print("\nExpired JWT authentication")
    try:
        expired = post_auth(base + "/auth?expired=true")
        results.check("POST /auth?expired=true returns 200 and a JWT", True)
    except Exception as exc:  # noqa: BLE001
        results.check("POST /auth?expired=true returns 200 and a JWT", False, str(exc))
        expired = None
    if expired:
        claims = jwt.decode(expired, options={"verify_signature": False})
        results.check("its exp claim is in the past",
                      claims.get("exp", 0) < time.time(),
                      f"exp={claims.get('exp')}")
        kid = jwt.get_unverified_header(expired).get("kid")
        results.check("its signing kid is absent from the JWKS",
                      public_key_for(jwks, kid) is None,
                      f"kid {kid!r} is published")

    print("\nHTTP methods and status codes")
    for method in ("GET", "PUT", "DELETE", "PATCH"):
        code = status_of(method, base + "/auth")
        results.check(f"{method} /auth is 405", code == 405, f"got {code}")
    for method in ("POST", "PUT", "DELETE"):
        code = status_of(method, base + "/.well-known/jwks.json")
        results.check(f"{method} /.well-known/jwks.json is 405", code == 405,
                      f"got {code}")
    code = status_of("GET", base + "/not-a-real-endpoint")
    results.check("an unknown path is 404", code == 404, f"got {code}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Blackbox-test a JWKS server.")
    parser.add_argument("--base", default="http://localhost:8080")
    parser.add_argument("--db", default="totally_not_my_privateKeys.db",
                        help="SQLite file to inspect; pass '' to skip")
    parser.add_argument("--student",
                        default="Rupesh Pokharel <rupesh.pokharel61@gmail.com>")
    args = parser.parse_args(argv)

    print(f"{BOLD}JWKS server blackbox test client — Project 2 (SQLite){RESET}")
    print(f"  student : {args.student}")
    print(f"  target  : {args.base}")
    print(f"  database: {args.db or '(not checked)'}")
    print(f"  run at  : {datetime.now().astimezone():%a, %d %b %Y %H:%M:%S %Z}\n")

    results = Results()
    run_checks(results, args.base.rstrip("/"), args.db or None)
    print(f"\n{BOLD}{results.passed} passed, {results.failed} failed{RESET}")
    return 1 if results.failed else 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
