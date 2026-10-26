from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def octets32(path: Path, name: str) -> bytes:
    data = path.read_bytes()
    if len(data) != 32:
        raise ValueError(name)
    return data


def load_secret(path: Path) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(octets32(path, "identity"))


def public_octets(secret: Ed25519PrivateKey) -> bytes:
    return secret.public_key().public_bytes_raw()


def store_key(path: Path, secret, public_of) -> bytes:
    path.write_bytes(secret.private_bytes_raw())
    return public_of(secret)


def write_identity(path: Path) -> bytes:
    return store_key(path, Ed25519PrivateKey.generate(), public_octets)
