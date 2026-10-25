"""RSA key material: generation, PEM serialization, and JWK encoding.

This module knows nothing about storage. Project 2 moved persistence into
``jwks_server.db``; what is left here is the cryptography and the JOSE
encoding rules, which are the same whether a key came from memory or from
SQLite.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

#: Modulus size for generated keys. 2048 bits is the minimum sensible for RS256.
DEFAULT_KEY_SIZE = 2048

#: Public exponent. 65537 is the universal standard choice.
PUBLIC_EXPONENT = 65537


def b64url_uint(value: int) -> str:
    """Encode a non-negative integer as unpadded base64url, per RFC 7518.

    The integer is written as big-endian octets with no leading zero octets;
    zero itself is written as a single zero octet.
    """
    if value < 0:
        raise ValueError("value must be non-negative")
    length = max(1, (value.bit_length() + 7) // 8)
    raw = value.to_bytes(length, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64url_to_uint(text: str) -> int:
    """Decode an unpadded base64url string back into an integer."""
    padded = text + "=" * (-len(text) % 4)
    raw = base64.urlsafe_b64decode(padded.encode("ascii"))
    if not raw:
        raise ValueError("empty integer encoding")
    return int.from_bytes(raw, "big")


def generate_private_key(key_size: int = DEFAULT_KEY_SIZE) -> rsa.RSAPrivateKey:
    """Generate a fresh RSA private key."""
    return rsa.generate_private_key(
        public_exponent=PUBLIC_EXPONENT, key_size=key_size
    )


def serialize_private_key(private_key: rsa.RSAPrivateKey) -> bytes:
    """Serialize a private key to PKCS#1 PEM for storage in the database.

    SQLite has no RSA key type, so the key is stored as a BLOB. PKCS#1 PEM
    ("BEGIN RSA PRIVATE KEY") is a compact, well-defined text encoding that
    round-trips exactly. The key is written unencrypted because this is a
    teaching project; a real system would wrap it with a KMS-held key or
    store only a reference to an HSM.
    """
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


def deserialize_private_key(pem: bytes | str) -> rsa.RSAPrivateKey:
    """Load a private key back from its stored PEM representation."""
    if isinstance(pem, str):
        pem = pem.encode("utf-8")
    key = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ValueError("stored key is not an RSA private key")
    return key


@dataclass
class KeyPair:
    """A private key loaded from the database, with its row metadata.

    ``kid`` is the database row's primary key. SQLite assigns it, which is why
    it is an integer here while the JWKS publishes it as a string: RFC 7517
    requires ``kid`` to be a string.
    """

    kid: int
    private_key: rsa.RSAPrivateKey = field(repr=False)
    #: Unix timestamp (seconds) at which this key stops being valid.
    exp: int

    def is_expired(self, now: float) -> bool:
        """Report whether the key has expired at ``now``.

        The boundary is inclusive: a key is expired the instant it reaches
        its expiry.
        """
        return now >= self.exp

    @property
    def public_key(self) -> rsa.RSAPublicKey:
        """The public half of the pair. Only this half is ever published."""
        return self.private_key.public_key()

    @property
    def jwk_kid(self) -> str:
        """The Key ID as published in the JWKS and in JWT headers."""
        return str(self.kid)

    def to_jwk(self) -> dict:
        """Return the public key as a JSON Web Key (RFC 7517 / 7518 §6.3)."""
        numbers = self.public_key.public_numbers()
        return {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": self.jwk_kid,
            "n": b64url_uint(numbers.n),
            "e": b64url_uint(numbers.e),
        }
