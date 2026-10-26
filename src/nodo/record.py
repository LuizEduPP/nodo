from __future__ import annotations

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from nodo.domain import PREFIX


def _parts(packed: bytes) -> tuple[bytes, bytes]:
    return bytes(4) + packed, PREFIX + packed


def seal(key: bytes, seq: int, plaintext: bytes) -> bytes:
    packed = seq.to_bytes(8, "big")
    nonce, aad = _parts(packed)
    return packed + ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)


def open_record(key: bytes, body: bytes) -> tuple[int, bytes] | None:
    if len(body) < 8 + 16:
        return None
    packed = body[:8]
    nonce, aad = _parts(packed)
    try:
        return int.from_bytes(packed, "big"), ChaCha20Poly1305(key).decrypt(nonce, body[8:], aad)
    except InvalidTag:
        return None
