from __future__ import annotations

import hashlib

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from nodo.domain import PREFIX


class AssociationError(Exception):
    pass


def _digest(tag: int, secret: bytes, extra: bytes) -> bytes:
    return hashlib.sha256(bytes([tag]) + secret + extra).digest()


def generate_ephemeral() -> tuple[X25519PrivateKey, bytes]:
    secret = X25519PrivateKey.generate()
    return secret, secret.public_key().public_bytes_raw()


def shared_secret(local: X25519PrivateKey, peer_public: bytes) -> bytes:
    try:
        public = X25519PublicKey.from_public_bytes(peer_public)
    except ValueError as exc:
        raise AssociationError("eph") from exc
    secret = local.exchange(public)
    if secret == bytes(32):
        raise AssociationError("zero")
    return secret


def derive_keys(
    secret: bytes,
    initiator: bytes,
    acceptor: bytes,
    eph_initiator: bytes,
    eph_acceptor: bytes,
) -> tuple[bytes, bytes]:
    info = PREFIX + initiator + acceptor + eph_initiator + eph_acceptor
    return _digest(1, secret, info), _digest(2, secret, info)


def handshake_key(eph: X25519PrivateKey, peer_box: bytes, recipient: bytes) -> bytes:
    return _digest(3, shared_secret(eph, peer_box), PREFIX + recipient)


def seal_handshake(eph: X25519PrivateKey, peer_box: bytes, recipient: bytes, plaintext: bytes) -> bytes:
    key = handshake_key(eph, peer_box, recipient)
    public = eph.public_key().public_bytes_raw()
    return public + ChaCha20Poly1305(key).encrypt(bytes(12), plaintext, PREFIX)


def open_handshake(box: X25519PrivateKey, recipient: bytes, body: bytes) -> bytes:
    if len(body) < 32 + 16:
        raise AssociationError("short")
    public = body[:32]
    key = handshake_key(box, public, recipient)
    try:
        return ChaCha20Poly1305(key).decrypt(bytes(12), body[32:], PREFIX)
    except InvalidTag as exc:
        raise AssociationError("seal") from exc
