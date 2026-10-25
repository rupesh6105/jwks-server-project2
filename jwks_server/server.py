"""The Flask application: the well-known JWKS endpoint and mock ``/auth``.

Both handlers now read their key material from SQLite rather than from an
in-memory store, so the server can be restarted without invalidating any
token it has already issued.
"""

from __future__ import annotations

import time
from typing import Callable

import jwt
from flask import Flask, Response, jsonify, request

from .db import KeyDatabase

#: The idiomatic well-known URI for a JWK Set (RFC 8615).
JWKS_PATH = "/.well-known/jwks.json"

#: Convenience alias for clients that look for the set at the server root.
JWKS_ALT_PATH = "/jwks.json"

#: The mock authentication endpoint.
AUTH_PATH = "/auth"

#: ``iss`` claim on every issued token.
ISSUER = "jwks-server"

#: ``sub`` claim. Authentication is faked, so every caller gets this user.
MOCK_SUBJECT = "userABC"

#: How long a normally issued token stays valid, in seconds.
TOKEN_TTL = 15 * 60


def create_app(database: KeyDatabase,
               clock: Callable[[], float] = time.time) -> Flask:
    """Build the application around ``database``.

    ``clock`` supplies the current Unix time. It is injectable so tests can
    drive expiry behaviour without sleeping.
    """
    app = Flask(__name__)

    # Flask answers a wrong method with 405 (and an Allow header) and an
    # unknown path with 404, so the handlers only deal with the happy path.

    @app.get(JWKS_PATH)
    @app.get(JWKS_ALT_PATH)
    def jwks() -> Response:
        """Serve a JWK Set built from the unexpired keys in the database."""
        response = jsonify(database.jwks(clock()))
        # The set changes as keys expire, so it must not be cached.
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.post(AUTH_PATH)
    def auth() -> Response:
        """Read a private key from the database and issue a signed JWT.

        Authentication is mocked: no credentials are checked. The grading
        client sends HTTP Basic auth on one request and a JSON body of
        ``{"username": ..., "password": ...}`` on another, and both are
        accepted and ignored — the request body is never parsed, so a
        malformed one cannot fail the request either.

        If the ``expired`` query parameter is present, the token is signed
        with an expired key from the database and carries that key's past
        expiry as its ``exp`` claim.
        """
        now = clock()
        want_expired = "expired" in request.args

        key = database.signing_key(now, expired=want_expired)
        if key is None:
            # No key of the requested kind is stored; a server-side problem,
            # not the caller's fault.
            return Response("no signing key available\n", status=500,
                            mimetype="text/plain")

        if want_expired:
            exp = key.exp
            iat = key.exp - TOKEN_TTL
        else:
            exp = int(now) + TOKEN_TTL
            iat = int(now)

        token = jwt.encode(
            {"sub": MOCK_SUBJECT, "iss": ISSUER, "iat": iat, "exp": exp},
            key.private_key,
            algorithm="RS256",
            # The kid lets a verifier pick this key out of the JWKS.
            headers={"kid": key.jwk_kid},
        )

        # The token is returned as the raw response body, the form the
        # course's test client reads.
        response = Response(token, status=200, mimetype="text/plain")
        response.headers["Cache-Control"] = "no-store"
        return response

    return app
