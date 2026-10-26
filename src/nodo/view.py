from __future__ import annotations

from typing import Any

from nodo.composition import compose, effective_budget, offer_dimension
from nodo.domain import VERSION


class View:
    def __init__(self) -> None:
        self.offers: dict[bytes, dict[str, Any]] = {}
        self.declarations: dict[tuple[bytes, bytes], dict[str, Any]] = {}
        self.previous: dict[bytes, list[dict[str, Any]]] = {}

    def store_offer(self, offer: dict[str, Any]) -> str | None:
        if effective_budget(offer) < 0:
            return "budget"
        reserved = sum(item["reservation"] for item in offer["commitments"])
        limit = offer["vram_limit"] if offer_dimension(offer) == "vram" else offer["ram_limit"]
        if reserved > limit:
            return "budget"
        self.offers[offer["participant"]] = offer
        return None

    def withdraw(self, participant: bytes) -> None:
        self.offers.pop(participant, None)

    def store_declaration(self, declaration: dict[str, Any]) -> None:
        self.declarations[(declaration["participant"], declaration["id"])] = declaration

    def accepted(self) -> dict[bytes, dict[str, Any]]:
        return {
            participant: offer
            for participant, offer in self.offers.items()
            if offer["condition"] == "accepted"
        }

    def merge(self, capability: bytes) -> dict[str, Any] | None:
        frags = [item for (participant, ident), item in self.declarations.items() if ident == capability]
        if not frags:
            return None
        available = self.accepted()
        embed = None
        head = None
        banks: list[dict[str, Any]] = []
        width = bound = span = None
        name = frags[0]["name"]
        for frag in frags:
            holder = frag["participant"]
            if width is None:
                width, bound, span = frag["width"], frag["bound"], frag["span"]
            if any(role["name"] == "head" for role in frag["roles"]):
                bound, span = frag["bound"], frag["span"]
            for role in frag["roles"]:
                item = dict(role)
                item["holder"] = holder
                if role["name"] == "embed":
                    if embed is None or holder < embed["holder"]:
                        embed = item
                elif role["name"] == "head":
                    if head is None or holder > head["holder"]:
                        head = item
                elif role["name"].startswith("bank-") and holder in available:
                    banks.append(item)
        roles = []
        if embed is not None:
            roles.append(embed)
        roles.extend(sorted(banks, key=lambda item: item["holder"]))
        if head is not None:
            roles.append(head)
        if not roles or width is None or bound is None or span is None:
            return None
        declarant = embed["holder"] if embed is not None else min(item["participant"] for item in frags)
        return {
            "version": VERSION,
            "type": "capability",
            "id": capability,
            "participant": declarant,
            "name": name,
            "width": width,
            "bound": bound,
            "span": span,
            "roles": roles,
        }

    def compositions(self) -> list[dict[str, Any]]:
        results = []
        accepted = self.accepted()
        seen: set[bytes] = set()
        for _participant, ident in self.declarations:
            if ident in seen:
                continue
            seen.add(ident)
            merged = self.merge(ident)
            if merged is None:
                continue
            result = compose(merged, accepted, self.previous.get(ident))
            self.previous[ident] = result["commitments"]
            results.append(result)
        return results

    def complete(self) -> list[dict[str, Any]]:
        return [item for item in self.compositions() if item["complete"]]

    def declaration(self, declarant: bytes, capability: bytes) -> dict[str, Any] | None:
        merged = self.merge(capability)
        if merged is None:
            return None
        if merged["participant"] == declarant or (declarant, capability) in self.declarations:
            return merged
        return None
