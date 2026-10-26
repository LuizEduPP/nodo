from __future__ import annotations

import uuid
from typing import Any, NoReturn

from nodo.composition import listing_id
from nodo.domain import Cause


class SessionError(Cause):
    pass


def open_allowed(request: bytes) -> None:
    if len(request) < 1:
        raise SessionError("request")


def _missing(exc: BaseException | None = None) -> NoReturn:
    if exc is None:
        raise SessionError("identifier-missing")
    raise SessionError("identifier-missing") from exc


def parse_listing(text: str) -> tuple[bytes, bytes]:
    if text.count("-") < 1 or text[64:65] != "-":
        _missing()
    try:
        declarant = bytes.fromhex(text[:64])
        identifier = _uuid_bytes(text[65:])
    except ValueError as exc:
        _missing(exc)
    if len(declarant) != 32 or len(identifier) != 16:
        _missing()
    return declarant, identifier


def find_complete(complete: list[dict[str, Any]], text: str) -> dict[str, Any]:
    declarant, identifier = parse_listing(text)
    for item in complete:
        if item["declarant"] == declarant and item["capability"] == identifier:
            if listing_id(declarant, identifier) != text:
                _missing()
            return item
    _missing()


def _uuid_bytes(text: str) -> bytes:
    return uuid.UUID(text).bytes
