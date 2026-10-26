from __future__ import annotations

from nodo.domain import PREFIX


class FrameError(Exception):
    pass


def wrap(body: bytes) -> bytes:
    sequence = PREFIX + body
    if not complete(sequence):
        raise FrameError("frame")
    return sequence


def unwrap(sequence: bytes) -> bytes | None:
    if not complete(sequence):
        return None
    return sequence[len(PREFIX) :]


def complete(sequence: bytes) -> bool:
    if not isinstance(sequence, bytes):
        return False
    if len(sequence) < len(PREFIX) + 1:
        return False
    return sequence[: len(PREFIX)] == PREFIX
