from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from nodo.identity import octets32, store_key


def load_box(path: Path) -> X25519PrivateKey:
    return X25519PrivateKey.from_private_bytes(octets32(path, "box"))


def box_public(secret: X25519PrivateKey) -> bytes:
    return secret.public_key().public_bytes_raw()


def write_box(path: Path) -> bytes:
    return store_key(path, X25519PrivateKey.generate(), box_public)
