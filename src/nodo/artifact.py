from __future__ import annotations

from pathlib import Path

from nodo.composition import listing_id
from nodo.domain import CARRY, KIND_COMPLETE, VOCABULARY
from nodo.slice import Held, apply as apply_role, inspect, inspect_file


def occupy(path: Path, reservation: int) -> Held | None:
    if not path.is_file():
        return None
    return _hold(inspect_file(path), reservation, path)


def occupy_octets(data: bytes, reservation: int) -> Held | None:
    meta = inspect(data)
    if meta is None or meta["kind"] == KIND_COMPLETE:
        return None
    return _hold(meta, reservation, data)


def _hold(meta: dict[str, object] | None, reservation: int, source: Path | bytes) -> Held | None:
    if reservation < 1 or meta is None:
        return None
    return Held(meta, bytearray(reservation), source)


def store_path(state: Path, declarant: bytes, capability: bytes, name: str) -> Path:
    return state / "publication" / listing_id(declarant, capability) / name


def read_carry(path: Path, offset: int) -> tuple[bytes, int] | None:
    if not path.is_file() or offset < 0:
        return None
    size = path.stat().st_size
    if offset >= size:
        return None
    with path.open("rb") as src:
        src.seek(offset)
        body = src.read(min(CARRY, size - offset))
    if not body:
        return None
    return body, size - offset - len(body)


def append_carry(path: Path, offset: int, body: bytes) -> int | None:
    if not body:
        return None
    have = path.stat().st_size if path.is_file() else 0
    if offset != have:
        return None
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("ab") as out:
        out.write(body)
    return have + len(body)
