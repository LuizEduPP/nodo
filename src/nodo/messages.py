from __future__ import annotations

from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from nodo.domain import (
    CLASSES,
    CLEAR_TYPES,
    CONDITIONS,
    PREFIX,
    REJECTION,
    SIGNED,
    SUSPENSION,
    VERSION,
    Cause,
)
from nodo.item import ItemError, decode_item, encode_item, fields_of


class MessageError(Cause):
    pass


def _item(data: bytes) -> tuple[dict[str, Any], bytes]:
    try:
        return decode_item(data)
    except ItemError as exc:
        raise MessageError(exc.cause) from exc


def encode_message(message: dict[str, Any], secret: Ed25519PrivateKey | None) -> bytes:
    validate(message)
    try:
        payload = encode_item(message)
    except ItemError as exc:
        raise MessageError(exc.cause) from exc
    if message["type"] in SIGNED:
        if secret is None:
            raise MessageError("signature")
        return payload + secret.sign(PREFIX + payload)
    return payload


def decode_message(item: bytes, author: Ed25519PublicKey | None) -> dict[str, Any]:
    message, rest = _item(item)
    if message["type"] in SIGNED:
        if author is None:
            raise MessageError("signature")
        if len(rest) != 64:
            raise MessageError("item")
        payload = item[: len(item) - 64]
        try:
            author.verify(rest, PREFIX + payload)
        except InvalidSignature as exc:
            raise MessageError("signature") from exc
    elif rest:
        raise MessageError("frame")
    validate(message)
    if message["type"] in SIGNED:
        if message.get("participant") != author.public_bytes_raw():
            raise MessageError("signature")
    return message


def decode_clear(item: bytes) -> dict[str, Any]:
    message, rest = _item(item)
    kind = message.get("type")
    if kind not in CLEAR_TYPES:
        raise MessageError("association")
    if kind == "rejection":
        if rest:
            raise MessageError("frame")
        validate(message)
        return message
    return decode_signed(item)


def decode_signed(item: bytes) -> dict[str, Any]:
    message, _rest = _item(item)
    participant = message.get("participant")
    if not isinstance(participant, bytes):
        raise MessageError("identifier-missing")
    try:
        public = Ed25519PublicKey.from_public_bytes(participant)
    except ValueError as exc:
        raise MessageError("signature") from exc
    return decode_message(item, public)


def validate(message: dict[str, Any]) -> None:
    if message.get("version") != VERSION:
        raise MessageError("version")
    kind = message.get("type")
    if not isinstance(kind, str):
        raise MessageError("item")
    required = _fields(kind)
    keys = set(message)
    extra = keys - required - _optional(kind) - {"version", "type"}
    missing = required - keys
    if extra or missing:
        if missing & {
            "participant",
            "id",
            "session",
            "commitment",
            "declarant",
            "capability",
            "subject",
        }:
            raise MessageError("identifier-missing")
        raise MessageError("item")
    checker = {
        "association-open": _association,
        "association-accept": _association,
        "association-close": _association_close,
        "offer": _offer,
        "offer-withdrawal": _offer_withdrawal,
        "capability": _capability,
        "presence": _presence,
        "introduction": _introduction,
        "convey": _convey,
        "composition": _composition,
        "session-open": _session_open,
        "session-progress": _session_progress,
        "session-suspend": _session_suspend,
        "session-close": _session_close,
        "rejection": _rejection,
        "step-in": _step_in,
        "step-carry": _step_carry,
        "step-out": _step_out,
        "role-need": _role_need,
        "role-carry": _role_carry,
    }.get(kind)
    if checker is None:
        raise MessageError("item")
    checker(message)


def _fields(kind: str) -> set[str]:
    return fields_of(kind)


def _optional(kind: str) -> set[str]:
    if kind == "offer":
        return {"classes", "ram_host", "ram_limit", "vram_host", "vram_limit", "vram_device"}
    return set()


def _bstr(value: Any, size: int) -> None:
    if not isinstance(value, bytes) or len(value) != size:
        raise MessageError("item")


def _tstr(value: Any) -> None:
    if not isinstance(value, str) or len(value) < 1:
        raise MessageError("item")


def _uint(value: Any, minimum: int = 0) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise MessageError("item")


_ID_SIZE = {
    "participant": 32,
    "eph": 32,
    "box": 32,
    "subject": 32,
    "holder": 32,
    "declarant": 32,
    "id": 16,
    "session": 16,
    "commitment": 16,
    "capability": 16,
}


def _ids(message: dict[str, Any], *names: str) -> None:
    for name in names:
        _bstr(message[name], _ID_SIZE[name])


def _association(message: dict[str, Any]) -> None:
    _ids(message, "participant", "eph", "box")


def _association_close(message: dict[str, Any]) -> None:
    _ids(message, "participant")


def _presence(message: dict[str, Any]) -> None:
    _ids(message, "participant", "box")


def _introduction(message: dict[str, Any]) -> None:
    _ids(message, "participant", "subject")


def _convey(message: dict[str, Any]) -> None:
    _ids(message, "participant", "subject")
    body = message["body"]
    if not isinstance(body, bytes) or len(body) < len(PREFIX) + 1:
        raise MessageError("item")
    if body[: len(PREFIX)] != PREFIX:
        raise MessageError("frame")


def _offer_commitment(item: Any) -> None:
    if not isinstance(item, dict) or set(item) != {"id", "reservation"}:
        raise MessageError("item")
    _ids(item, "id")
    _uint(item["reservation"], 1)


def _offer(message: dict[str, Any]) -> None:
    _ids(message, "participant")
    if message["condition"] not in CONDITIONS:
        raise MessageError("item")
    _each(message["commitments"], _offer_commitment)
    classes = message.get("classes")
    if classes == ["cpu"]:
        extra = {"classes", "ram_host", "ram_limit"}
        if set(message) - {"version", "type", "participant", "condition", "commitments"} != extra:
            raise MessageError("item")
        _uint(message["ram_host"])
        _uint(message["ram_limit"])
        return
    if classes == ["gpu"]:
        allowed = {"classes", "vram_host", "vram_limit", "vram_device"}
        present = set(message) - {"version", "type", "participant", "condition", "commitments"}
        if present - allowed or not {"classes", "vram_host", "vram_limit"} <= present:
            raise MessageError("item")
        _uint(message["vram_host"])
        _uint(message["vram_limit"])
        if "vram_device" in message:
            _tstr(message["vram_device"])
        return
    raise MessageError("item")


_offer_withdrawal = _association_close


def _role(item: Any) -> None:
    if not isinstance(item, dict):
        raise MessageError("item")
    keys = set(item)
    if keys - {"name", "reservation", "class"} or not {"name", "reservation"} <= keys:
        raise MessageError("item")
    _tstr(item["name"])
    _uint(item["reservation"], 1)
    if "class" in item and item["class"] not in CLASSES:
        raise MessageError("item")


def _capability(message: dict[str, Any]) -> None:
    _ids(message, "id", "participant")
    _tstr(message["name"])
    _uint(message["width"], 1)
    _uint(message["bound"], 1)
    _uint(message["span"], 1)
    if message["span"] < message["bound"]:
        raise MessageError("item")
    _each(message["roles"], _role, True)


def _commitment(item: Any) -> None:
    if not isinstance(item, dict) or set(item) != {"id", "role", "participant", "reservation"}:
        raise MessageError("item")
    _ids(item, "id", "participant")
    _tstr(item["role"])
    _uint(item["reservation"], 1)


def _composition(message: dict[str, Any]) -> None:
    _ids(message, "declarant", "capability")
    if not isinstance(message["complete"], bool):
        raise MessageError("item")
    _each(message["commitments"], _commitment)


def _session_open(message: dict[str, Any]) -> None:
    _ids(message, "id", "participant", "declarant", "capability")
    _each(message["commitments"], _commitment, True)


def _session_progress(message: dict[str, Any]) -> None:
    _session(message)
    _uint(message["sequence"])


def _session_suspend(message: dict[str, Any]) -> None:
    _session(message)
    if message["cause"] not in SUSPENSION:
        raise MessageError("item")


def _session_close(message: dict[str, Any]) -> None:
    _session(message)


def _rejection(message: dict[str, Any]) -> None:
    if message["cause"] not in REJECTION:
        raise MessageError("item")


def _step(message: dict[str, Any], commitment: bool = False) -> None:
    _session(message)
    if commitment:
        _ids(message, "commitment")
    _uint(message["sequence"])


def _step_in(message: dict[str, Any]) -> None:
    _step(message, True)
    _uint(message["token"])


def _step_carry(message: dict[str, Any]) -> None:
    _step(message, True)
    _body(message["body"])


def _step_out(message: dict[str, Any]) -> None:
    _step(message)
    _uint(message["token"])


def _role_need(message: dict[str, Any]) -> None:
    _role_ids(message)


def _role_carry(message: dict[str, Any]) -> None:
    _role_ids(message)
    _uint(message["offset"])
    _uint(message["remain"])
    _body(message["body"])


def _session(message: dict[str, Any]) -> None:
    _ids(message, "participant", "session")


def _role_ids(message: dict[str, Any]) -> None:
    _ids(message, "participant", "holder", "declarant", "capability")
    _tstr(message["role"])


def _each(value: Any, reader: Any, nonempty: bool = False) -> None:
    if not isinstance(value, list) or (nonempty and not value):
        raise MessageError("item")
    for item in value:
        reader(item)


def _body(value: Any) -> None:
    if not isinstance(value, (bytes, bytearray)) or len(value) < 1:
        raise MessageError("item")
