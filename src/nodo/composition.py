from __future__ import annotations

import hashlib
import uuid
from typing import Any

from nodo.domain import VERSION, uuid_shape
from nodo.measure import cap


def commitment_id(capability_id: bytes, role_name: str, participant: bytes) -> bytes:
    name = role_name.encode("utf-8") + participant
    return uuid_shape(hashlib.sha1(capability_id + name).digest()[:16], 5)


def _dimension(kind: str | list[str] | None) -> str:
    if kind == "gpu" or kind == ["gpu"]:
        return "vram"
    return "ram"


def role_dimension(role: dict[str, Any]) -> str:
    return _dimension(role.get("class"))


def offer_dimension(offer: dict[str, Any]) -> str:
    return _dimension(offer["classes"])


def effective_budget(offer: dict[str, Any]) -> int:
    if offer_dimension(offer) == "vram":
        quantity = offer["vram_host"]
        limit = offer["vram_limit"]
    else:
        quantity = offer["ram_host"]
        limit = offer["ram_limit"]
    ceiling = cap(quantity)
    if limit > ceiling:
        return -1
    return min(limit, ceiling)


def compose(
    declaration: dict[str, Any],
    offers: dict[bytes, dict[str, Any]],
    previous: list[dict[str, Any]] | None,
) -> dict[str, Any]:
    capability_id = declaration["id"]
    previous_by_role = {}
    if previous:
        for item in previous:
            previous_by_role[item["role"]] = item
    holders: list[dict[str, Any]] = []
    complete = True
    for role in declaration["roles"]:
        dimension = role_dimension(role) if role.get("class") else None
        holder = role.get("holder")
        eligible: list[bytes] = []
        candidates = [holder] if isinstance(holder, bytes) else list(offers)
        for participant in candidates:
            offer = offers.get(participant)
            if offer is None or offer["condition"] != "accepted":
                continue
            if dimension is not None and offer_dimension(offer) != dimension:
                continue
            if not _has_reservations(offer):
                continue
            if _free_for(capability_id, declaration["roles"], offer, holders, participant) < role["reservation"]:
                continue
            eligible.append(participant)
        current = previous_by_role.get(role["name"])
        chosen: bytes | None = None
        if current and current["participant"] in eligible:
            chosen = current["participant"]
        elif eligible:
            chosen = min(eligible, key=lambda item: hashlib.sha256(item + capability_id).digest())
        if chosen is None:
            complete = False
            continue
        assigned = {
            "id": commitment_id(capability_id, role["name"], chosen),
            "role": role["name"],
            "participant": chosen,
            "reservation": role["reservation"],
        }
        holders.append(assigned)
    return {
        "version": VERSION,
        "type": "composition",
        "declarant": declaration["participant"],
        "capability": capability_id,
        "complete": complete and _parts_apart(holders),
        "commitments": holders,
    }


def _holder(holders: list[dict[str, Any]], role: str) -> bytes | None:
    return next((item["participant"] for item in holders if item["role"] == role), None)


def _parts_apart(holders: list[dict[str, Any]]) -> bool:
    embed = _holder(holders, "embed")
    head = _holder(holders, "head")
    return embed is not None and head is not None and embed != head


def _has_reservations(offer: dict[str, Any]) -> bool:
    return all("reservation" in item for item in offer["commitments"])


def _free_for(
    capability_id: bytes,
    roles: list[dict[str, Any]],
    offer: dict[str, Any],
    assigned: list[dict[str, Any]],
    participant: bytes,
) -> int:
    matching_ids = {commitment_id(capability_id, role["name"], offer["participant"]) for role in roles}
    debit = 0
    for item in offer["commitments"]:
        if item["id"] not in matching_ids:
            debit += item["reservation"]
    free = effective_budget(offer) - debit
    for item in assigned:
        if item["participant"] == participant:
            free -= item["reservation"]
    return free


def listing_id(declarant: bytes, capability_id: bytes) -> str:
    return declarant.hex() + "-" + str(uuid.UUID(bytes=capability_id))
