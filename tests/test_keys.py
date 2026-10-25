"""Tests for key generation, PEM serialization, and JWK encoding."""

from __future__ import annotations

import base64

import pytest

from jwks_server.keys import (
    DEFAULT_KEY_SIZE,
    KeyPair,
    b64url_to_uint,
    b64url_uint,
    deserialize_private_key,
    generate_private_key,
    serialize_private_key,
)

from .conftest import NOW, TEST_KEY_SIZE


def test_generate_private_key(rsa_key):
    assert rsa_key.key_size == TEST_KEY_SIZE
    assert rsa_key.public_key().public_numbers().e == 65537


def test_default_key_size_is_2048():
    assert DEFAULT_KEY_SIZE == 2048


def test_generate_rejects_unusable_size():
    with pytest.raises(ValueError):
        generate_private_key(256)


def test_pem_round_trip(rsa_key):
    pem = serialize_private_key(rsa_key)
    assert pem.startswith(b"-----BEGIN RSA PRIVATE KEY-----")
    restored = deserialize_private_key(pem)
    assert restored.private_numbers().p == rsa_key.private_numbers().p


def test_deserialize_accepts_str(rsa_key):
    pem = serialize_private_key(rsa_key).decode("ascii")
    assert deserialize_private_key(pem).key_size == rsa_key.key_size


def test_deserialize_rejects_garbage():
    with pytest.raises(ValueError):
        deserialize_private_key(b"not a pem file")


def test_deserialize_rejects_non_rsa_key():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    pem = ed25519.Ed25519PrivateKey.generate().private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with pytest.raises(ValueError, match="not an RSA private key"):
        deserialize_private_key(pem)


@pytest.mark.parametrize(
    "value, encoded",
    [(0, "AA"), (1, "AQ"), (65537, "AQAB"), (255, "_w"), (256, "AQA")],
)
def test_b64url_uint_known_values(value, encoded):
    assert b64url_uint(value) == encoded
    assert b64url_to_uint(encoded) == value


def test_b64url_uint_rejects_negative():
    with pytest.raises(ValueError):
        b64url_uint(-1)


def test_b64url_to_uint_rejects_empty():
    with pytest.raises(ValueError):
        b64url_to_uint("")


def test_is_expired(rsa_key):
    assert KeyPair(1, rsa_key, NOW + 1).is_expired(NOW) is False
    assert KeyPair(1, rsa_key, NOW - 1).is_expired(NOW) is True
    assert KeyPair(1, rsa_key, NOW).is_expired(NOW) is True, "boundary is expired"


def test_jwk_kid_is_the_row_id_as_a_string(rsa_key):
    assert KeyPair(42, rsa_key, NOW).jwk_kid == "42"


def test_jwk_members(rsa_key):
    jwk = KeyPair(7, rsa_key, NOW + 3600).to_jwk()
    assert set(jwk) == {"kty", "use", "alg", "kid", "n", "e"}
    assert jwk["kty"] == "RSA"
    assert jwk["use"] == "sig"
    assert jwk["alg"] == "RS256"
    assert jwk["kid"] == "7"
    assert jwk["e"] == "AQAB"


def test_jwk_is_unpadded_base64url_without_leading_zero(rsa_key):
    jwk = KeyPair(1, rsa_key, NOW + 3600).to_jwk()
    for member in ("n", "e"):
        assert not set(jwk[member]) & set("=+/")
    raw_n = base64.urlsafe_b64decode(jwk["n"] + "=" * (-len(jwk["n"]) % 4))
    assert raw_n[0] != 0, "RFC 7518 forbids a leading zero octet"


def test_jwk_round_trips_to_the_same_public_key(rsa_key):
    jwk = KeyPair(1, rsa_key, NOW + 3600).to_jwk()
    numbers = rsa_key.public_key().public_numbers()
    assert b64url_to_uint(jwk["n"]) == numbers.n
    assert b64url_to_uint(jwk["e"]) == numbers.e


def test_repr_does_not_leak_private_key(rsa_key):
    assert "private_key" not in repr(KeyPair(1, rsa_key, NOW))
