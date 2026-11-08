from __future__ import annotations

import json
from typing import Any

from nodo.composition import compose, effective_budget, offer_dimension
from nodo.domain import VERSION


class View:
    def __init__(self) -> None:
        self.offers: dict[bytes, dict[str, Any]] = {}
        self.declarations: dict[tuple[bytes, bytes], dict[str, Any]] = {}
        self.previous: dict[bytes, list[dict[str, Any]]] = {}
        self._save_path: str | None = None

    def _set_save_path(self, path: str | None) -> None:
        self._save_path = path

    def _auto_save(self) -> None:
        if self._save_path is not None:
            self.save(self._save_path)

    def _encode_offers(self) -> list[dict[str, Any]]:
        result = []
        for participant, offer in self.offers.items():
            offer_copy = {
                "version": offer.get("version", VERSION),
                "type": offer.get("type", "offer"),
                "participant": participant.hex(),
                "condition": offer["condition"],
                "commitments": [
                    {"id": item["id"].hex(), "reservation": item["reservation"]}
                    for item in offer["commitments"]
                ],
            }
            if "classes" in offer:
                offer_copy["classes"] = offer["classes"]
            if "ram_host" in offer:
                offer_copy["ram_host"] = offer["ram_host"]
            if "ram_limit" in offer:
                offer_copy["ram_limit"] = offer["ram_limit"]
            if "vram_host" in offer:
                offer_copy["vram_host"] = offer["vram_host"]
            if "vram_limit" in offer:
                offer_copy["vram_limit"] = offer["vram_limit"]
            if "vram_device" in offer:
                offer_copy["vram_device"] = offer["vram_device"]
            result.append({"participant": participant.hex(), "offer": offer_copy})
        return result

    def _decode_offers(self, data: list[dict[str, Any]]) -> None:
        self.offers = {}
        for entry in data:
            participant = bytes.fromhex(entry["participant"])
            offer = {
                "version": entry["offer"].get("version", VERSION),
                "type": entry["offer"].get("type", "offer"),
                "participant": participant,
                "condition": entry["offer"]["condition"],
                "commitments": [
                    {"id": bytes.fromhex(item["id"]), "reservation": item["reservation"]}
                    for item in entry["offer"]["commitments"]
                ],
            }
            for key in ("classes", "ram_host", "ram_limit", "vram_host", "vram_limit", "vram_device"):
                if key in entry["offer"]:
                    offer[key] = entry["offer"][key]
            self.offers[participant] = offer

    def _encode_declarations(self) -> list[dict[str, Any]]:
        result = []
        for (participant, capability), declaration in self.declarations.items():
            decl_copy = {
                "version": declaration.get("version", VERSION),
                "type": declaration.get("type", "capability"),
                "participant": participant.hex(),
                "id": capability.hex(),
                "name": declaration["name"],
                "width": declaration["width"],
                "bound": declaration["bound"],
                "span": declaration["span"],
                "roles": [
                    {"name": role["name"], "reservation": role["reservation"]}
                    for role in declaration["roles"]
                ],
            }
            result.append({
                "participant": participant.hex(),
                "capability": capability.hex(),
                "declaration": decl_copy,
            })
        return result

    def _decode_declarations(self, data: list[dict[str, Any]]) -> None:
        self.declarations = {}
        for entry in data:
            participant = bytes.fromhex(entry["participant"])
            capability = bytes.fromhex(entry["capability"])
            decl = {
                "version": entry["declaration"].get("version", VERSION),
                "type": entry["declaration"].get("type", "capability"),
                "participant": participant,
                "id": capability,
                "name": entry["declaration"]["name"],
                "width": entry["declaration"]["width"],
                "bound": entry["declaration"]["bound"],
                "span": entry["declaration"]["span"],
                "roles": [
                    {"name": role["name"], "reservation": role["reservation"]}
                    for role in entry["declaration"]["roles"]
                ],
            }
            self.declarations[(participant, capability)] = decl

    def _encode_previous(self) -> dict[str, list[dict[str, Any]]]:
        return {key.hex(): value for key, value in self.previous.items()}

    def _decode_previous(self, data: dict[str, list[dict[str, Any]]]) -> None:
        self.previous = {bytes.fromhex(key): value for key, value in data.items()}

    def save(self, path: str) -> None:
        payload = {
            "offers": self._encode_offers(),
            "declarations": self._encode_declarations(),
            "previous": self._encode_previous(),
        }
        try:
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(payload, handle)
        except (OSError, TypeError):
            pass

    def load(self, path: str) -> None:
        try:
            with open(path, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except (OSError, json.JSONDecodeError):
            return
        self._decode_offers(payload.get("offers", []))
        self._decode_declarations(payload.get("declarations", []))
        self._decode_previous(payload.get("previous", {}))

    def store_offer(self, offer: dict[str, Any]) -> str | None:
        if effective_budget(offer) < 0:
            return "budget"
        reserved = sum(item["reservation"] for item in offer["commitments"])
        limit = offer["vram_limit"] if offer_dimension(offer) == "vram" else offer["ram_limit"]
        if reserved > limit:
            return "budget"
        self.offers[offer["participant"]] = offer
        self._auto_save()
        return None

    def withdraw(self, participant: bytes) -> None:
        self.offers.pop(participant, None)

    def store_declaration(self, declaration: dict[str, Any]) -> None:
        self.declarations[(declaration["participant"], declaration["id"])] = declaration
        self._auto_save()

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
