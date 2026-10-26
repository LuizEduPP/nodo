from __future__ import annotations

from typing import Any, Callable

from nodo.domain import (
    CLASSES,
    CODE_TYPE,
    CONDITIONS,
    REJECTION,
    SUSPENSION,
    TYPE_CODE,
    VERSION,
    Cause,
)


class ItemError(Cause):
    pass


def encode_item(message: dict[str, Any]) -> bytes:
    kind = message.get("type")
    if kind not in TYPE_CODE:
        raise ItemError("item")
    if message.get("version") != VERSION:
        raise ItemError("version")
    return bytes([TYPE_CODE[kind], VERSION]) + _encode_body(kind, message)


def decode_item(data: bytes) -> tuple[dict[str, Any], bytes]:
    if len(data) < 2:
        raise ItemError("item")
    code, version = data[0], data[1]
    if version != VERSION:
        raise ItemError("version")
    kind = CODE_TYPE.get(code)
    if kind is None:
        raise ItemError("item")
    message, rest = _decode_body(kind, data[2:])
    message["type"] = kind
    message["version"] = VERSION
    return message, rest


def fields_of(kind: str) -> set[str]:
    if kind == "offer":
        return {"participant", "condition", "commitments"}
    spec = LAYOUT.get(kind)
    if spec is None:
        return set()
    return {name for name, _kind in spec}


def _encode_body(kind: str, message: dict[str, Any]) -> bytes:
    if kind == "offer":
        return _encode_offer(message)
    spec = LAYOUT.get(kind)
    if spec is None:
        raise ItemError("item")
    return _dump(message, spec)


def _decode_body(kind: str, data: bytes) -> tuple[dict[str, Any], bytes]:
    if kind == "offer":
        return _decode_offer(data)
    spec = LAYOUT.get(kind)
    if spec is None:
        raise ItemError("item")
    return _load(data, spec)


def _codec(kind: Any) -> tuple[Callable[[Any], bytes], Callable[[bytes], tuple[Any, bytes]]]:
    if isinstance(kind, int):
        return (lambda value, size=kind: _put_fixed(value, size), lambda data, size=kind: _fixed(data, size))
    if kind == "u32":
        return _put_u32, _u32
    if kind == "u64":
        return _put_u64, _u64
    if kind == "text":
        return _put_text, _text
    if kind == "bin":
        return _put_bin, _bin
    if kind == "bool":
        return _put_bool, _bool
    if isinstance(kind, tuple) and kind[0] == "enum":
        table = kind[1]
        return (lambda value, held=table: _put_enum(value, held), lambda data, held=table: _enum(data, held))
    if isinstance(kind, tuple) and kind[0] == "list":
        writer, reader = kind[1], kind[2]
        return (lambda value, write=writer: _put_list(value, write), lambda data, read=reader: _list(data, read))
    raise ItemError("item")


def _dump(message: dict[str, Any], spec: tuple[tuple[str, Any], ...]) -> bytes:
    return b"".join(_codec(kind)[0](message[name]) for name, kind in spec)


def _load(data: bytes, spec: tuple[tuple[str, Any], ...]) -> tuple[dict[str, Any], bytes]:
    message: dict[str, Any] = {}
    for name, kind in spec:
        message[name], data = _codec(kind)[1](data)
    return message, data


def _need(data: bytes, size: int) -> None:
    if len(data) < size:
        raise ItemError("item")


def _u8(data: bytes) -> tuple[int, bytes]:
    return _u(data, 1)


def _u16(data: bytes) -> tuple[int, bytes]:
    return _u(data, 2)


def _u32(data: bytes) -> tuple[int, bytes]:
    return _u(data, 4)


def _u64(data: bytes) -> tuple[int, bytes]:
    return _u(data, 8)


def _u(data: bytes, size: int) -> tuple[int, bytes]:
    _need(data, size)
    return int.from_bytes(data[:size], "big"), data[size:]


def _fixed(data: bytes, size: int) -> tuple[bytes, bytes]:
    _need(data, size)
    return data[:size], data[size:]


def _text(data: bytes) -> tuple[str, bytes]:
    length, rest = _u16(data)
    if length < 1:
        raise ItemError("item")
    _need(rest, length)
    try:
        return rest[:length].decode("utf-8"), rest[length:]
    except UnicodeDecodeError as exc:
        raise ItemError("item") from exc


def _bin(data: bytes) -> tuple[bytes, bytes]:
    length, rest = _u32(data)
    _need(rest, length)
    return rest[:length], rest[length:]


def _bool(data: bytes) -> tuple[bool, bytes]:
    value, rest = _u8(data)
    if value == 0:
        return False, rest
    if value == 1:
        return True, rest
    raise ItemError("item")


def _enum(data: bytes, table: tuple[str, ...]) -> tuple[str, bytes]:
    code, rest = _u8(data)
    if code >= len(table):
        raise ItemError("item")
    return table[code], rest


def _list(data: bytes, reader: Any) -> tuple[list[Any], bytes]:
    count, rest = _u16(data)
    items = []
    for _ in range(count):
        item, rest = reader(rest)
        items.append(item)
    return items, rest


def _put_u8(value: int) -> bytes:
    return _put_u(value, 1)


def _put_u16(value: int) -> bytes:
    return _put_u(value, 2)


def _put_u32(value: int) -> bytes:
    return _put_u(value, 4)


def _put_u64(value: int) -> bytes:
    return _put_u(value, 8)


def _put_u(value: int, size: int) -> bytes:
    limit = (1 << (size * 8)) - 1
    if not isinstance(value, int) or isinstance(value, bool) or value < 0 or value > limit:
        raise ItemError("item")
    if size == 1:
        return bytes([value])
    return value.to_bytes(size, "big")


def _put_fixed(value: bytes, size: int) -> bytes:
    if not isinstance(value, bytes) or len(value) != size:
        raise ItemError("item")
    return value


def _put_text(value: str) -> bytes:
    if not isinstance(value, str):
        raise ItemError("item")
    data = value.encode("utf-8")
    if len(data) < 1:
        raise ItemError("item")
    return _put_u16(len(data)) + data


def _put_bin(value: bytes) -> bytes:
    if not isinstance(value, bytes):
        raise ItemError("item")
    return _put_u32(len(value)) + value


def _put_bool(value: bool) -> bytes:
    if value is True:
        return b"\x01"
    if value is False:
        return b"\x00"
    raise ItemError("item")


def _put_enum(value: str, table: tuple[str, ...]) -> bytes:
    try:
        return _put_u8(table.index(value))
    except ValueError as exc:
        raise ItemError("item") from exc


def _put_list(items: list[Any], writer: Any) -> bytes:
    if not isinstance(items, list):
        raise ItemError("item")
    return _put_u16(len(items)) + b"".join(writer(item) for item in items)


OFFER_COMMIT = (("id", 16), ("reservation", "u64"))
ROLE_HEAD = (("name", "text"), ("reservation", "u64"))
COMMIT = (("id", 16), ("role", "text"), ("participant", 32), ("reservation", "u64"))


def _encode_offer_commitment(item: dict[str, Any]) -> bytes:
    return _dump(item, OFFER_COMMIT)


def _decode_offer_commitment(data: bytes) -> tuple[dict[str, Any], bytes]:
    return _load(data, OFFER_COMMIT)


def _encode_role(item: dict[str, Any]) -> bytes:
    body = _dump(item, ROLE_HEAD)
    if "class" in item:
        return body + b"\x01" + _put_enum(item["class"], CLASSES)
    return body + b"\x00"


def _decode_role(data: bytes) -> tuple[dict[str, Any], bytes]:
    role, data = _load(data, ROLE_HEAD)
    present, data = _u8(data)
    if present == 1:
        role["class"], data = _enum(data, CLASSES)
        return role, data
    if present == 0:
        return role, data
    raise ItemError("item")


def _encode_commitment(item: dict[str, Any]) -> bytes:
    return _dump(item, COMMIT)


def _decode_commitment(data: bytes) -> tuple[dict[str, Any], bytes]:
    return _load(data, COMMIT)


OFFER_HEAD = (
    ("participant", 32),
    ("condition", ("enum", CONDITIONS)),
    ("commitments", ("list", _encode_offer_commitment, _decode_offer_commitment)),
)


def _encode_offer(message: dict[str, Any]) -> bytes:
    body = _dump(message, OFFER_HEAD)
    classes = message["classes"]
    if classes == ["cpu"]:
        return body + _put_enum("cpu", CLASSES) + _put_u64(message["ram_host"]) + _put_u64(message["ram_limit"])
    if classes == ["gpu"]:
        body = body + _put_enum("gpu", CLASSES) + _put_u64(message["vram_host"]) + _put_u64(message["vram_limit"])
        if "vram_device" in message:
            return body + b"\x01" + _put_text(message["vram_device"])
        return body + b"\x00"
    raise ItemError("item")


def _decode_offer(data: bytes) -> tuple[dict[str, Any], bytes]:
    message, data = _load(data, OFFER_HEAD)
    host, data = _enum(data, CLASSES)
    message["classes"] = [host]
    if host == "cpu":
        message["ram_host"], data = _u64(data)
        message["ram_limit"], data = _u64(data)
        return message, data
    message["vram_host"], data = _u64(data)
    message["vram_limit"], data = _u64(data)
    present, data = _u8(data)
    if present == 1:
        message["vram_device"], data = _text(data)
        return message, data
    if present == 0:
        return message, data
    raise ItemError("item")


LAYOUT: dict[str, tuple[tuple[str, Any], ...]] = {
    "association-open": (("participant", 32), ("eph", 32), ("box", 32)),
    "association-accept": (("participant", 32), ("eph", 32), ("box", 32)),
    "association-close": (("participant", 32),),
    "presence": (("participant", 32), ("box", 32)),
    "introduction": (("participant", 32), ("subject", 32)),
    "convey": (("participant", 32), ("subject", 32), ("body", "bin")),
    "offer-withdrawal": (("participant", 32),),
    "capability": (
        ("id", 16),
        ("participant", 32),
        ("name", "text"),
        ("width", "u32"),
        ("bound", "u32"),
        ("span", "u32"),
        ("roles", ("list", _encode_role, _decode_role)),
    ),
    "composition": (
        ("declarant", 32),
        ("capability", 16),
        ("complete", "bool"),
        ("commitments", ("list", _encode_commitment, _decode_commitment)),
    ),
    "session-open": (
        ("id", 16),
        ("participant", 32),
        ("declarant", 32),
        ("capability", 16),
        ("commitments", ("list", _encode_commitment, _decode_commitment)),
    ),
    "session-progress": (("participant", 32), ("session", 16), ("sequence", "u64")),
    "session-suspend": (("participant", 32), ("session", 16), ("cause", ("enum", SUSPENSION))),
    "session-close": (("participant", 32), ("session", 16)),
    "rejection": (("cause", ("enum", REJECTION)),),
    "step-in": (
        ("participant", 32),
        ("session", 16),
        ("commitment", 16),
        ("sequence", "u64"),
        ("token", "u32"),
    ),
    "step-carry": (
        ("participant", 32),
        ("session", 16),
        ("commitment", 16),
        ("sequence", "u64"),
        ("body", "bin"),
    ),
    "step-out": (("participant", 32), ("session", 16), ("sequence", "u64"), ("token", "u32")),
    "role-need": (
        ("participant", 32),
        ("holder", 32),
        ("declarant", 32),
        ("capability", 16),
        ("role", "text"),
    ),
    "role-carry": (
        ("participant", 32),
        ("holder", 32),
        ("declarant", 32),
        ("capability", 16),
        ("role", "text"),
        ("offset", "u64"),
        ("remain", "u64"),
        ("body", "bin"),
    ),
}
