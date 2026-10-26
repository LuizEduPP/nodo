from __future__ import annotations

import hashlib
import select
import sys
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from nodo.artifact import append_carry, apply_role, occupy, read_carry, store_path
from nodo.domain import Cause, EOS, NOTICE_WAIT, PREFIX, RECORD_TYPES, SIGNED, VERSION, VOCABULARY
from nodo.slice import Held, inspect_file
from nodo.association import (
    AssociationError,
    derive_keys,
    generate_ephemeral,
    open_handshake,
    seal_handshake,
    shared_secret,
)
from nodo.box import box_public, load_box
from nodo.access import AccessError, lock, parse_argv, reply, submit, take, unlock
from nodo.config import ConfigError, join
from nodo.frame import FrameError, unwrap, wrap
from nodo.identity import load_secret, public_octets
from nodo.measure import MeasureError, cap, gpu_devices, host_budget, host_class, ram_host
from nodo.item import ItemError, decode_item
from nodo.messages import (
    MessageError,
    decode_clear,
    decode_message,
    decode_signed,
    encode_message,
)
from nodo.placement import Placement, PlacementError, Route
from nodo.record import open_record, seal
from nodo.session import SessionError, open_allowed
from nodo.vocabulary import bytes_vocab, decode, encode
from nodo.view import View


@dataclass
class Pending:
    secret: X25519PrivateKey
    eph: bytes
    acceptor: bytes
    outer: bytes


@dataclass
class Assoc:
    initiator: bytes
    acceptor: bytes
    send_key: bytes
    recv_key: bytes
    open_eph: bytes
    accept_eph: bytes
    send_seq: int = 0
    recv_seq: int = 0
    heard: bool = False
    sent_first: bool = False
    accept_outer: bytes | None = None


@dataclass
class Opened:
    session: bytes
    declarant: bytes
    capability: bytes
    commitments: list[dict[str, Any]]
    request: bytes
    prompt: list[int]
    width: int
    bound: int
    span: int
    vocabulary: Any
    token: int
    sequence: int = 0
    generated: list[int] = field(default_factory=list)
    sent_close: bool = False
    suspended: bool = False


class LocalFailure(Cause):
    pass


def _path_rank(route: Route) -> int:
    if route.placement is not None:
        return 3
    if route.token:
        return 2
    if route.addr is not None:
        return 1
    return 0


class Participant:
    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        self.secret = load_secret(config["identity"])
        self.participant = public_octets(self.secret)
        self.box_secret = load_box(config["box"])
        self.box_public = box_public(self.box_secret)
        self.boxes: dict[bytes, bytes] = {}
        self.paths: dict[bytes, Route] = {}
        self.via: dict[bytes, bytes] = {}
        self.introducers: dict[bytes, set[bytes]] = {}
        self.signed_presence: dict[bytes, bytes] = {}
        self.accepted_presence: dict[bytes, set[bytes]] = {}
        self.view = View()
        self.pending: dict[bytes, Pending] = {}
        self.assocs: dict[tuple[bytes, bytes], Assoc] = {}
        self.opened: Opened | None = None
        self.held: dict[bytes, dict[str, Any]] = {}
        self.seen: set[tuple[bytes, bytes, int]] = set()
        self.occupied: dict[tuple[bytes, bytes, str], Held] = {}
        self.declaration = None
        self.terminal_out: list[str] = []
        self.terminal_err: list[str] = []
        self._notice_at = 0.0
        self._needed: set[tuple[bytes, bytes, str]] = set()
        self._forwarded_need: set[tuple[bytes, bytes, bytes, str]] = set()
        self._outgoing: list[tuple[bytes, dict[str, Any], Path, int]] = []
        self._pending_ask: bytes | None = None
        self._pending_steps: list[tuple[dict[str, Any], bytes, int | None, bytes | None]] = []
        self.placement = Placement(
            listen=config.get("listen"),
            peers=tuple(config.get("peers") or ()),
            peers_path=config.get("peers_path"),
        )
        self._mailbox: list[str] = []
        self._lock = None
        self._prepare()
        self.signed_presence[self.participant] = encode_message(self._presence_item(), self.secret)
        self._emit_notice()

    def _prepare(self) -> None:
        self.config["state"].mkdir(parents=True, exist_ok=True)
        if self.config["announce"]:
            self._announce()
        if self.config["declaration"] is not None:
            self._declare()
        self._bind_publication()

    def _announce(self) -> None:
        kind = host_class()
        offer: dict[str, Any] = self._msg("offer", condition=self.config["condition"], commitments=[])
        if kind == "gpu":
            devices = gpu_devices()
            if not devices:
                raise LocalFailure("announce")
            if self.config["ram_limit"] is not None:
                raise LocalFailure("class")
            if len(devices) == 1:
                if self.config["vram_device"] is not None:
                    raise LocalFailure("vram_device")
                vram_host = devices[0][1]
            else:
                if self.config["vram_device"] is None:
                    raise LocalFailure("vram_device")
                match = [item for item in devices if item[0] == self.config["vram_device"]]
                if len(match) != 1:
                    raise LocalFailure("vram_device")
                vram_host = match[0][1]
                offer["vram_device"] = self.config["vram_device"]
            offer["classes"] = ["gpu"]
            offer["vram_host"] = vram_host
            offer["vram_limit"] = self._cap("vram_limit", vram_host)
        else:
            if self.config["vram_limit"] is not None:
                raise LocalFailure("class")
            quantity = ram_host()
            offer["classes"] = ["cpu"]
            offer["ram_host"] = quantity
            offer["ram_limit"] = self._cap("ram_limit", quantity)
        cause = self.view.store_offer(offer)
        if cause:
            raise LocalFailure(cause)
        self.local_offer = offer

    def _cap(self, key: str, quantity: int) -> int:
        if self.config[key] is None:
            self.config[key] = cap(quantity)
        if self.config[key] > cap(quantity):
            raise LocalFailure("budget")
        return self.config[key]

    def _declare(self) -> None:
        configured = self.config["declaration"]
        path = self.config["state"] / "capability.id"
        if "id" in configured:
            identifier = configured["id"]
            path.write_bytes(identifier)
        elif path.exists():
            identifier = path.read_bytes()
            if len(identifier) != 16 or identifier[6] >> 4 != 7:
                raise LocalFailure("id")
        else:
            identifier = uuid.uuid7().bytes
            path.write_bytes(identifier)
        self.declaration = self._msg(
            "capability",
            id=identifier,
            name=configured["name"],
            width=configured["width"],
            bound=configured["bound"],
            span=configured["span"],
            roles=configured["roles"],
        )
        self.view.store_declaration(self.declaration)

    def _bind_publication(self) -> None:
        held = self.config.get("publication")
        if not held or self.declaration is None:
            return
        ident = self.declaration["id"]
        if not self.config["artifacts"]:
            artifacts = []
            for item in held["roles"]:
                path = Path(item["path"])
                if path.is_file():
                    artifacts.append(
                        {
                            "declarant": self.participant,
                            "capability": ident,
                            "role": item["name"],
                            "path": str(path),
                        }
                    )
            self.config["artifacts"] = artifacts
        vocab = held.get("vocabulary")
        if vocab and Path(vocab).is_file() and not self.config["vocabularies"]:
            self.config["vocabularies"] = [
                {
                    "declarant": self.participant,
                    "capability": ident,
                    "path": vocab,
                }
            ]

    def _initiate(self, subject: bytes) -> None:
        box = self.boxes.get(subject)
        if box is None:
            return
        if subject not in self.paths and not self._hops(subject):
            return
        secret, eph = generate_ephemeral()
        message = self._msg("association-open", eph=eph, box=self.box_public)
        inner = encode_message(message, self.secret)
        outer = seal_handshake(secret, box, subject, inner)
        if not self._place_id(subject, outer, False):
            return
        self.pending[subject] = Pending(secret, eph, subject, outer)

    def _emit_notice(self) -> None:
        self._notice_at = time.monotonic()
        frame = self.presence_frame()
        try:
            self.placement.notice(frame)
        except PlacementError:
            pass
        for route in list(self.paths.values()):
            try:
                self.placement.place(route, frame)
            except PlacementError:
                continue

    def _hops(self, subject: bytes) -> set[bytes]:
        hops = set(self.introducers.get(subject, set()))
        via = self.via.get(subject)
        if via is not None:
            hops.add(via)
        return {hop for hop in hops if self._assoc_for(hop) is not None}

    def _bind(self, participant: bytes, route: Route) -> None:
        if participant == self.participant:
            return
        held = self.paths.get(participant)
        if held is not None and _path_rank(held) > _path_rank(route):
            return
        self.paths[participant] = route

    def _place_id(self, participant: bytes, body: bytes, record: bool, assoc: Assoc | None = None) -> bool:
        if record:
            if assoc is None:
                raise LocalFailure("association")
            body = seal(assoc.send_key, assoc.send_seq, body)
        try:
            frame = wrap(body)
        except FrameError:
            return False
        if record:
            assoc.send_seq += 1
        path = self.paths.get(participant)
        if path is not None:
            return self._send_frame(path, frame, assoc)
        return self._convey_frame(participant, frame)

    def _send_frame(self, route: Route, frame: bytes, assoc: Assoc | None = None) -> bool:
        try:
            self.placement.place(route, frame)
        except PlacementError:
            if assoc is not None:
                self._end(assoc, False)
            return False
        return True

    def _convey_frame(self, subject: bytes, frame: bytes) -> bool:
        hops = self._hops(subject)
        sent = False
        for hop in hops:
            assoc = self._assoc_for(hop)
            if assoc is None:
                continue
            self._send_record(assoc, self._msg("convey", subject=subject, body=frame))
            sent = True
        return sent

    def _msg(self, kind: str, **fields: Any) -> dict[str, Any]:
        return {"version": VERSION, "type": kind, "participant": self.participant, **fields}

    def _tell(self, item: dict[str, Any], opened: Opened | None = None) -> None:
        holders = opened.commitments if opened is not None else []
        for entry in holders:
            assoc = self._assoc_for(entry["participant"])
            if assoc is None:
                continue
            self._send_record(assoc, item)

    def _each(self, skip: Assoc | bytes | None = None):
        for assoc in list(self.assocs.values()):
            if skip is assoc or (isinstance(skip, (bytes, bytearray)) and self._peer(assoc) == skip):
                continue
            yield assoc

    def _blast(self, item: dict[str, Any], skip: Assoc | bytes | None = None) -> None:
        for assoc in self._each(skip):
            self._send_record(assoc, item)

    def _from_peer(self, message: dict[str, Any], peer: bytes, assoc: Assoc, reject: bool = True) -> bool:
        if message["participant"] == peer:
            return True
        if reject:
            self._rejection(peer, "authorization", assoc)
        return False

    def _forget(self, session: bytes) -> None:
        self.seen = {item for item in self.seen if item[0] != session}

    def _no_model(self) -> None:
        self.terminal_err.append("no model")

    def _held_for(self, session: bytes, peer: bytes) -> dict[str, Any] | None:
        held = self.held.get(session)
        if held is None or held["opener"] != peer:
            return None
        return held

    def _work(self) -> None:
        self.step()
        self._apply_access()
        self._flush_mailbox()

    def _send_record(self, assoc: Assoc, message: dict[str, Any]) -> None:
        signed = message["type"] not in {"composition", "rejection"}
        body = encode_message(message, self.secret if signed else None)
        peer = self._peer(assoc)
        if not self._place_id(peer, body, True, assoc):
            self._end(assoc, False)

    def _rejection(self, participant: bytes, cause: str, assoc: Assoc | None) -> None:
        message = {"version": VERSION, "type": "rejection", "cause": cause}
        if assoc is None:
            body = encode_message(message, None)
            self._place_id(participant, body, False)
        else:
            self._send_record(assoc, message)

    def _waiting(self) -> list[Assoc]:
        return [assoc for assoc in self.assocs.values() if not assoc.heard]

    def _emit_waiting(self) -> None:
        waiting = self._waiting()
        if self.assocs and not self.pending and not waiting:
            return
        if time.monotonic() - self._notice_at >= NOTICE_WAIT:
            self._emit_notice()
        for subject in list(self.pending):
            self._retransmit_open(subject)

    def step(self) -> None:
        self.placement.tick()
        self._emit_waiting()
        while True:
            got = self.placement.receive()
            if got is None:
                break
            self._apply_frame(got[0], got[1])
        self._flush_carries()
        self._emit_waiting()

    def _apply_frame(self, sequence: bytes, route: Route | None) -> None:
        body = unwrap(sequence)
        if body is None:
            return
        try:
            message = decode_clear(body)
        except MessageError:
            if self._handle_sealed(body, route):
                return
            self._handle_record_body(body)
            return
        if message["type"] == "presence":
            self._on_presence(message, route, signed=body)
            return
        if message["type"] == "rejection":
            return

    def _handle_sealed(self, body: bytes, route: Route | None) -> bool:
        try:
            inner = open_handshake(self.box_secret, self.participant, body)
            message = decode_signed(inner)
        except (AssociationError, MessageError, ValueError):
            return False
        kind = message["type"]
        if kind == "association-open":
            if message["eph"] != body[:32]:
                return True
            self._on_open(message, route)
            return True
        if kind == "association-accept":
            self._on_accept(message, route)
            return True
        return False

    def _on_open(self, message: dict[str, Any], route: Route | None) -> None:
        initiator = message["participant"]
        if initiator == self.participant or initiator > self.participant:
            return
        self._via_from_route(initiator, route)
        self.boxes[initiator] = message["box"]
        pair = (initiator, self.participant)
        held = self.assocs.get(pair)
        if held is not None:
            if message["eph"] == held.open_eph:
                self._retransmit_accept(held)
                return
            self._drop(initiator)
        secret, eph = generate_ephemeral()
        try:
            shared = shared_secret(secret, message["eph"])
        except AssociationError:
            return
        accept = self._msg("association-accept", eph=eph, box=self.box_public)
        inner = encode_message(accept, self.secret)
        outer = seal_handshake(secret, message["box"], initiator, inner)
        if not self._place_id(initiator, outer, False):
            return
        k_i, k_a = derive_keys(shared, initiator, self.participant, message["eph"], eph)
        assoc = Assoc(initiator, self.participant, k_a, k_i, message["eph"], eph, accept_outer=outer)
        self.assocs[pair] = assoc
        self._after_keys(assoc)

    def _on_accept(self, message: dict[str, Any], route: Route | None) -> None:
        acceptor = message["participant"]
        pending = self.pending.get(acceptor)
        if pending is None:
            return
        self._via_from_route(acceptor, route)
        self.boxes[acceptor] = message["box"]
        try:
            shared = shared_secret(pending.secret, message["eph"])
        except AssociationError:
            del self.pending[acceptor]
            return
        k_i, k_a = derive_keys(shared, self.participant, acceptor, pending.eph, message["eph"])
        pair = (self.participant, acceptor)
        assoc = Assoc(self.participant, acceptor, k_i, k_a, pending.eph, message["eph"])
        self.assocs[pair] = assoc
        del self.pending[acceptor]
        self._after_keys(assoc)

    def _after_keys(self, assoc: Assoc) -> None:
        if assoc.initiator != self.participant:
            return
        assoc.sent_first = True
        self._first_items(assoc)

    def _first_items(self, assoc: Assoc) -> None:
        if self.config["announce"]:
            self._send_record(assoc, self.local_offer)
        if self.declaration is not None:
            self._send_record(assoc, self.declaration)
        self._send_record(assoc, self._presence_item())
        self._relay_known(assoc)
        self._spread_subject(self._peer(assoc))

    def _peer(self, assoc: Assoc) -> bytes:
        if assoc.initiator == self.participant:
            return assoc.acceptor
        return assoc.initiator

    def _presence_item(self) -> dict[str, Any]:
        return self._msg("presence", box=self.box_public)

    def presence_frame(self) -> bytes:
        return wrap(encode_message(self._presence_item(), self.secret))

    def _retransmit_open(self, subject: bytes) -> None:
        pending = self.pending.get(subject)
        if pending is None:
            return
        self._place_id(subject, pending.outer, False)

    def _retransmit_accept(self, assoc: Assoc) -> None:
        if assoc.accept_outer is None:
            return
        self._place_id(assoc.initiator, assoc.accept_outer, False)

    def _consider_subject(self, subject: bytes, clear: bool = True) -> None:
        if subject == self.participant:
            return
        held = self._assoc_for(subject)
        if held is not None:
            return
        if subject in self.pending:
            if clear:
                self._retransmit_open(subject)
            return
        if self.participant >= subject:
            return
        self._initiate(subject)

    def _via_from_route(self, subject: bytes, route: Route | None) -> None:
        if route is None or subject in self.paths:
            return
        for peer, path in self.paths.items():
            if path == route:
                self.via[subject] = peer
                self.introducers.setdefault(subject, set()).add(peer)
                return

    def _on_presence(
        self,
        message: dict[str, Any],
        route: Route | None = None,
        source: bytes | None = None,
        signed: bytes | None = None,
    ) -> None:
        subject = message["participant"]
        if subject == self.participant:
            return
        remembered = self.accepted_presence.setdefault(subject, set())
        if signed is not None and signed in remembered:
            if route is not None:
                self._bind(subject, route)
            if source is not None:
                self.introducers.setdefault(subject, set()).add(source)
                if source == subject:
                    held = self._assoc_for(subject)
                    if held is not None:
                        held.heard = True
            self._consider_subject(subject, source is None)
            return
        previous = self.boxes.get(subject)
        held = self._assoc_for(subject) is not None or subject in self.pending
        first = previous is None
        if previous is not None and previous != message["box"]:
            if source is None and held:
                return
            if held:
                self._drop(subject)
            first = True
        self.boxes[subject] = message["box"]
        if signed is not None:
            remembered.add(signed)
            self.signed_presence[subject] = signed
        if source is not None:
            self.introducers.setdefault(subject, set()).add(source)
            if source == subject:
                present = self._assoc_for(subject)
                if present is not None:
                    present.heard = True
        if route is not None:
            self._bind(subject, route)
        if first:
            self._emit_notice()
            if signed is not None:
                self._spread_subject(subject)
        self._consider_subject(subject, source is None)

    def _introduction_item(self, subject: bytes) -> dict[str, Any]:
        return self._msg("introduction", subject=subject)

    def _relay_presence(self, assoc: Assoc, subject: bytes) -> None:
        octets = self.signed_presence.get(subject)
        if octets is None:
            return
        peer = self._peer(assoc)
        if not self._place_id(peer, octets, True, assoc):
            self._end(assoc, False)

    def _relay_known(self, dest: Assoc) -> None:
        dest_peer = self._peer(dest)
        for other in list(self.assocs.values()):
            subject = self._peer(other)
            if subject == dest_peer:
                continue
            self._relay_presence(dest, subject)
            self._send_record(dest, self._introduction_item(subject))

    def _spread_subject(self, subject: bytes) -> None:
        item = self._introduction_item(subject)
        for assoc in self._each(subject):
            self._relay_presence(assoc, subject)
            self._send_record(assoc, item)

    def _on_introduction(self, assoc: Assoc, message: dict[str, Any], peer: bytes) -> None:
        if not self._from_peer(message, peer, assoc):
            return
        subject = message["subject"]
        if subject == self.participant or subject == peer:
            return
        self.introducers.setdefault(subject, set()).add(peer)
        self._consider_subject(subject, False)

    def _on_convey(self, assoc: Assoc, message: dict[str, Any], peer: bytes) -> None:
        if not self._from_peer(message, peer, assoc):
            return
        subject = message["subject"]
        body = message["body"]
        if len(body) < len(PREFIX) + 1 or body[: len(PREFIX)] != PREFIX:
            self._rejection(peer, "frame", assoc)
            return
        if subject == self.participant:
            self._apply_frame(body, None)
            return
        path = self.paths.get(subject)
        if path is None:
            self._rejection(peer, "association", assoc)
            return
        try:
            self.placement.place(path, body)
        except PlacementError:
            self._rejection(peer, "association", assoc)

    def _handle_record_body(self, body: bytes) -> None:
        for assoc in self._each():
            opened = open_record(assoc.recv_key, body)
            if opened is None:
                continue
            seq, plaintext = opened
            peer = assoc.acceptor if assoc.initiator == self.participant else assoc.initiator
            if seq < assoc.recv_seq:
                return
            if seq > assoc.recv_seq:
                self._end(assoc, False)
                return
            try:
                public = Ed25519PublicKey.from_public_bytes(peer)
                message, signed = self._decode_record(plaintext, public)
            except MessageError as exc:
                if exc.cause == "frame":
                    self._end(assoc, False)
                    return
                self._rejection(peer, exc.cause, assoc)
                if exc.cause in {"association"}:
                    self._end(assoc, False)
                return
            assoc.recv_seq += 1
            if message["type"] not in RECORD_TYPES:
                self._end(assoc, False)
                return
            if not assoc.sent_first:
                assoc.sent_first = True
                self._first_items(assoc)
            self._dispatch(assoc, message, peer, signed)
            return

    def _decode_record(self, plaintext: bytes, public: Ed25519PublicKey) -> tuple[dict[str, Any], bytes]:
        try:
            message, rest = decode_item(plaintext)
        except ItemError as exc:
            raise MessageError(exc.cause) from exc
        if rest and len(rest) != 64:
            raise MessageError("frame")
        if message["type"] == "presence":
            author = message.get("participant")
            if isinstance(author, bytes) and author != public.public_bytes_raw():
                return decode_message(plaintext, Ed25519PublicKey.from_public_bytes(author)), plaintext
            return decode_message(plaintext, public), plaintext
        if message["type"] in SIGNED:
            return decode_message(plaintext, public), plaintext
        return decode_message(plaintext, None), plaintext

    def _dispatch(self, assoc: Assoc, message: dict[str, Any], peer: bytes, signed: bytes | None = None) -> None:
        kind = message["type"]
        if kind in {"offer", "offer-withdrawal", "capability", "association-close", "step-in"}:
            if not self._from_peer(message, peer, assoc):
                return
        if kind == "offer":
            cause = self.view.store_offer(message)
            if cause:
                self._rejection(peer, cause, assoc)
                return
            self._after_view()
            return
        if kind == "offer-withdrawal":
            self.view.withdraw(peer)
            self._after_view()
            return
        if kind == "capability":
            self.view.store_declaration(message)
            self._after_view()
            return
        if kind == "association-close":
            self._end(assoc, True)
            return
        handler = {
            "presence": lambda: self._on_presence(message, source=peer, signed=signed),
            "convey": lambda: self._on_convey(assoc, message, peer),
            "introduction": lambda: self._on_introduction(assoc, message, peer),
            "session-open": lambda: self._on_session_open(assoc, message, peer),
            "step-in": lambda: self._on_step_in(assoc, message, peer),
            "step-carry": lambda: self._on_step_carry(assoc, message, peer),
            "step-out": lambda: self._on_step_out(assoc, message, peer),
            "role-need": lambda: self._on_role_need(assoc, message, peer),
            "role-carry": lambda: self._on_role_carry(assoc, message, peer),
            "session-suspend": lambda: self._on_session_suspend(assoc, message, peer),
            "session-close": lambda: self._on_session_close(assoc, message, peer),
        }.get(kind)
        if handler is not None:
            handler()

    def _on_session_open(self, assoc: Assoc, message: dict[str, Any], peer: bytes) -> None:
        cause = self._hold_open(message, peer, assoc)
        if cause:
            self._rejection(peer, cause, assoc)

    def _hold_open(self, message: dict[str, Any], peer: bytes, assoc: Assoc | None) -> str | None:
        if message["participant"] != peer:
            return "authorization"
        declaration = self.view.declaration(message["declarant"], message["capability"])
        complete = self._complete_of(message["declarant"], message["capability"])
        if declaration is None or not complete:
            return "composition-mismatch"
        composition = complete[0]
        if composition["commitments"] != message["commitments"]:
            return "composition-mismatch"
        if not any(item["participant"] == self.participant for item in composition["commitments"]):
            return "authorization"
        existing = self.held.get(message["id"])
        if existing is not None and existing.get("state") != "suspended":
            return "authorization"
        self._forget(message["id"])
        self.held[message["id"]] = {
            "opener": peer,
            "declarant": message["declarant"],
            "capability": message["capability"],
            "commitments": message["commitments"],
            "assoc": assoc,
            "state": "open",
        }
        return None

    def _on_step_in(self, assoc: Assoc, message: dict[str, Any], peer: bytes) -> None:
        reply = self._apply_step(message, peer, message["token"], None)
        if reply is None:
            return
        self._emit_step(assoc, reply)

    def _on_step_carry(self, assoc: Assoc, message: dict[str, Any], peer: bytes) -> None:
        opened = self.opened
        if opened is not None and not opened.suspended and message["session"] == opened.session:
            cause = self._forward_carry(message, peer)
            if cause:
                self._rejection(peer, cause, assoc)
            return
        if message["commitment"] not in {item["id"] for item in (self.held.get(message["session"]) or {}).get("commitments", [])}:
            self._rejection(peer, "authorization", assoc)
            return
        reply = self._apply_step(message, peer, None, message["body"])
        if reply is None:
            return
        self._emit_step(assoc, reply)

    def _on_step_out(self, assoc: Assoc, message: dict[str, Any], peer: bytes) -> None:
        cause = self._take_out(message, peer)
        if cause:
            self._rejection(peer, cause, assoc)

    def _apply_step(
        self,
        message: dict[str, Any],
        peer: bytes,
        token: int | None,
        carry: bytes | None,
    ) -> dict[str, Any] | None:
        held = self.held.get(message["session"])
        if held is None or held["opener"] != peer:
            return None
        match = [
            item
            for item in held["commitments"]
            if item["id"] == message["commitment"] and item["participant"] == self.participant
        ]
        if not match:
            return None
        seen = (message["session"], message["commitment"], message["sequence"])
        if seen in self.seen:
            return None
        declaration = self.view.declaration(held["declarant"], held["capability"])
        if declaration is None:
            return None
        width = declaration["width"]
        if carry is not None and len(carry) != width:
            return None
        index = held["commitments"].index(match[0])
        if not self._artifact(held["declarant"], held["capability"], match[0]["role"], match[0]["reservation"]):
            return None
        outcome = apply_role(
            self.occupied[(held["declarant"], held["capability"], match[0]["role"])],
            width,
            index,
            len(held["commitments"]),
            token,
            carry,
            message["sequence"],
            declaration["span"],
        )
        if outcome is None:
            return None
        self.seen.add(seen)
        kind, value = outcome
        if kind == "token":
            return self._msg("step-out", session=message["session"], sequence=message["sequence"], token=value)
        nxt = held["commitments"][index + 1]
        return self._msg(
            "step-carry",
            session=message["session"],
            commitment=nxt["id"],
            sequence=message["sequence"],
            body=value,
        )

    def _emit_step(self, assoc: Assoc | None, item: dict[str, Any]) -> None:
        if assoc is None:
            if item["type"] == "step-out":
                self._take_out(item, self.participant)
                return
            self._forward_carry(item, self.participant)
            return
        self._send_record(assoc, item)

    def _forward_carry(self, message: dict[str, Any], peer: bytes) -> str | None:
        opened = self.opened
        if opened is None or opened.suspended or message["session"] != opened.session:
            return "authorization"
        nxt = [item for item in opened.commitments if item["id"] == message["commitment"]]
        if not nxt:
            return "authorization"
        if message["sequence"] != opened.sequence:
            return "authorization"
        if len(message["body"]) != opened.width:
            self._incompatible(message["commitment"])
            return None
        if nxt[0]["participant"] == self.participant:
            reply = self._apply_step(
                {
                    "session": message["session"],
                    "commitment": message["commitment"],
                    "sequence": message["sequence"],
                },
                self.participant,
                None,
                message["body"],
            )
            if reply is None:
                return None
            self._emit_step(None, reply)
            return None
        assoc = self._assoc_for(nxt[0]["participant"])
        if assoc is None:
            return "association"
        self._send_record(
            assoc,
            self._msg(
                "step-carry",
                session=message["session"],
                commitment=message["commitment"],
                sequence=message["sequence"],
                body=message["body"],
            ),
        )
        return None

    def _take_out(self, message: dict[str, Any], peer: bytes) -> str | None:
        opened = self.opened
        if opened is None or opened.suspended:
            return "authorization"
        if message["session"] != opened.session:
            return "authorization"
        last = opened.commitments[-1]
        if last["participant"] != peer or message["participant"] != peer:
            return "authorization"
        if message["sequence"] != opened.sequence:
            return "authorization"
        seen = (message["session"], last["id"], message["sequence"])
        if seen in self.seen and peer != self.participant:
            return "authorization"
        if message["token"] >= len(opened.vocabulary.pieces):
            self._incompatible(last["id"])
            return None
        self.seen.add(seen)
        prompt = opened.prompt
        if opened.sequence >= len(prompt) - 1:
            opened.generated.append(message["token"])
        self._progress()
        if opened.generated and (opened.generated[-1] == EOS or len(opened.generated) == opened.bound):
            self._close_session()
            return None
        opened.sequence += 1
        if opened.sequence < len(prompt):
            opened.token = prompt[opened.sequence]
        else:
            opened.token = message["token"]
        self._step_in()
        return None

    def _progress(self) -> None:
        opened = self.opened
        if opened is None or opened.suspended:
            return
        self._tell(self._msg("session-progress", session=opened.session, sequence=opened.sequence), opened)

    def _close_session(self) -> None:
        opened = self.opened
        if opened is None:
            return
        result = self._result_text(opened)
        self._tell(self._msg("session-close", session=opened.session), opened)
        opened.sent_close = True
        self.held.pop(opened.session, None)
        if result is not None:
            self.terminal_out.append(result)
        else:
            self.terminal_err.append("incomplete")
        self.opened = None

    def _result_text(self, opened: Opened) -> str | None:
        tokens = opened.generated
        if not tokens:
            return None
        if tokens[-1] == EOS:
            tokens = tokens[:-1]
        elif len(tokens) != opened.bound:
            return None
        raw = decode(opened.vocabulary, tokens)
        if raw is None:
            return None
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            return None

    def _refresh_publication(self, result: dict[str, Any]) -> None:
        if self.declaration is None:
            return
        roles = [{"name": item["name"], "reservation": item["reservation"]} for item in result["roles"]]
        for dest in (self.config["declaration"], self.declaration):
            dest["roles"] = roles
            dest["width"] = result["width"]
            dest["bound"] = result["bound"]
            dest["span"] = result["span"]
        self.view.store_declaration(self.declaration)
        publication = {
            "roles": [{"name": item["name"], "path": item["path"]} for item in result["roles"]],
            "vocabulary": result["vocabulary"],
        }
        self.config["publication"] = publication
        self.config["artifacts"] = []
        self.config["vocabularies"] = []
        self._bind_publication()
        self._blast(self.declaration)

    def _ensure_parts(self) -> None:
        if self.declaration is None:
            return
        accepted = set(self.view.accepted())
        accepted.add(self.participant)
        if len(accepted) < 2:
            return
        ident = self.declaration["id"]
        names = {
            role["name"]
            for (who, cap), decl in self.view.declarations.items()
            if cap == ident
            for role in decl["roles"]
        }
        low, high = min(accepted), max(accepted)
        from nodo.config import publication_root
        from nodo.model import open_part

        result = None
        if "embed" not in names and self.participant == low:
            result = open_part(publication_root(), "embed", self.participant, host_budget())
        if "head" not in names and self.participant == high and self.participant != low:
            result = open_part(publication_root(), "head", self.participant, host_budget())
        if result is not None:
            self._refresh_publication(result)

    def _on_session_close(self, assoc: Assoc, message: dict[str, Any], peer: bytes) -> None:
        held = self._held_for(message["session"], peer)
        if held is None:
            return
        self._vacate(held)
        del self.held[message["session"]]

    def _vacate(self, held: dict[str, Any]) -> None:
        for item in held["commitments"]:
            if item["participant"] == self.participant:
                self._release((held["declarant"], held["capability"], item["role"]))

    def _incompatible(self, commitment: bytes) -> None:
        if self.opened is None:
            return
        holder = [item for item in self.opened.commitments if item["id"] == commitment]
        if holder:
            self.view.withdraw(holder[0]["participant"])
        complete = self._session_of()
        if not complete:
            self._suspend("result-incompatible")
            return
        self._adopt(complete[0])

    def _suspend(self, cause: str) -> None:
        if self.opened is None or self.opened.suspended:
            return
        self._tell(self._msg("session-suspend", session=self.opened.session, cause=cause), self.opened)
        self.opened.suspended = True
        self.terminal_err.append(cause)

    def _on_session_suspend(self, assoc: Assoc, message: dict[str, Any], peer: bytes) -> None:
        held = self._held_for(message["session"], peer)
        if held is None:
            return
        held["state"] = "suspended"
        self._forget(message["session"])

    def _apply_condition(self, condition: str) -> None:
        if not self.config["announce"] or condition not in {"accepted", "pause", "leave"}:
            self.terminal_err.append("authorization")
            return
        self.config["condition"] = condition
        self.local_offer["condition"] = condition
        if condition == "leave":
            self._release()
        self.view.store_offer(self.local_offer)
        self._blast(self.local_offer)
        self._after_view()

    def _complete_of(self, declarant: bytes, capability: bytes) -> list[dict[str, Any]]:
        return [
            item
            for item in self.view.complete()
            if item["declarant"] == declarant and item["capability"] == capability
        ]

    def _session_of(self) -> list[dict[str, Any]]:
        opened = self.opened
        if opened is None:
            return []
        return self._complete_of(opened.declarant, opened.capability)

    def _after_view(self) -> None:
        self._ensure_parts()
        opened = self.opened
        if opened is None:
            return
        complete = self._session_of()
        if not complete:
            if not opened.suspended:
                self._suspend("recomposition-incomplete")
            return
        if opened.suspended:
            self._resume(complete[0])
            return
        self._adopt(complete[0])

    def _session_open_item(self) -> dict[str, Any] | None:
        opened = self.opened
        if opened is None:
            return None
        return self._msg(
            "session-open",
            id=opened.session,
            declarant=opened.declarant,
            capability=opened.capability,
            commitments=opened.commitments,
        )

    def _open_peers(self, composition: dict[str, Any]) -> None:
        opened = self.opened
        item = self._session_open_item()
        if opened is None or item is None:
            return
        opened.commitments = composition["commitments"]
        item["commitments"] = composition["commitments"]
        peers = {entry["participant"] for entry in composition["commitments"]}
        for peer in peers:
            if peer == self.participant:
                cause = self._hold_open(item, self.participant, None)
                if cause:
                    self.terminal_err.append(cause)
                    self.opened = None
                    return
                continue
            assoc = self._assoc_for(peer)
            if assoc is None:
                continue
            self._send_record(assoc, item)

    def _step_in(self) -> None:
        opened = self.opened
        if opened is None or opened.suspended:
            return
        first = opened.commitments[0]
        item = self._msg(
            "step-in",
            session=opened.session,
            commitment=first["id"],
            sequence=opened.sequence,
            token=opened.token,
        )
        if first["participant"] == self.participant:
            reply = self._apply_step(item, self.participant, opened.token, None)
            if reply is None:
                return
            self._emit_step(None, reply)
            return
        assoc = self._assoc_for(first["participant"])
        if assoc is None:
            return
        self._send_record(assoc, item)

    def _resume(self, composition: dict[str, Any]) -> None:
        opened = self.opened
        if opened is None:
            return
        opened.suspended = False
        self._forget(opened.session)
        self._adopt(composition, True)

    def _adopt(self, composition: dict[str, Any], force: bool = False) -> None:
        opened = self.opened
        if opened is None:
            return
        if not force:
            current = {item["id"] for item in opened.commitments}
            kept = {item["id"] for item in composition["commitments"]}
            if kept == current:
                return
        opened.commitments = composition["commitments"]
        self._open_peers(composition)
        if self.opened is None:
            return
        self._step_in()

    def _request_role(
        self,
        declarant: bytes,
        capability: bytes,
        role: str,
        message: dict[str, Any],
        peer: bytes,
        token: int | None,
        carry: bytes | None,
    ) -> None:
        self._pending_steps.append((message, peer, token, carry))
        self._request_file(declarant, capability, role, peer)

    def _request_file(self, declarant: bytes, capability: bytes, name: str, peer: bytes) -> None:
        key = (declarant, capability, name)
        if key in self._needed or self._file_path(declarant, capability, name) is not None:
            return
        self._needed.add(key)
        assoc = self._assoc_for(peer)
        if assoc is None:
            return
        self._send_record(
            assoc,
            self._msg("role-need", holder=self.participant, declarant=declarant, capability=capability, role=name),
        )

    def _artifact_item(self, declarant: bytes, capability: bytes, role: str) -> dict[str, Any] | None:
        for item in self.config["artifacts"]:
            if item["declarant"] == declarant and item["capability"] == capability and item["role"] == role:
                return item
        return None

    def _file_path(self, declarant: bytes, capability: bytes, name: str) -> Path | None:
        if name == VOCABULARY:
            return None
        item = self._artifact_item(declarant, capability, name)
        if item is None:
            for held in self.config["artifacts"]:
                if held["capability"] == capability and held["role"] == name:
                    item = held
                    break
        if item is not None:
            path = self._resolve_path(item["path"])
            if path.is_file():
                return path
        return None

    def _resolve_path(self, raw: str) -> Path:
        path = Path(raw)
        if not path.is_absolute():
            path = self.config["state"].parent / path
        return path

    def _release(self, key: tuple[bytes, bytes, str] | None = None) -> None:
        if key is None:
            items = list(self.occupied.values())
            self.occupied.clear()
        else:
            held = self.occupied.pop(key, None)
            items = [held] if held is not None else []
        for held in items:
            held.close()

    def _on_role_need(self, assoc: Assoc, message: dict[str, Any], peer: bytes) -> None:
        if not self._from_peer(message, peer, assoc, False):
            return
        path = self._file_path(message["declarant"], message["capability"], message["role"])
        if path is not None:
            self._outgoing.append((message["holder"], message, path, 0))
            self._flush_carries()
            return
        key = (message["holder"], message["declarant"], message["capability"], message["role"])
        if key in self._forwarded_need:
            return
        self._forwarded_need.add(key)
        self._blast(
            self._msg(
                "role-need",
                holder=message["holder"],
                declarant=message["declarant"],
                capability=message["capability"],
                role=message["role"],
            ),
            assoc,
        )

    def _flush_carries(self) -> None:
        kept: list[tuple[bytes, dict[str, Any], Path, int]] = []
        for holder, need, path, offset in self._outgoing:
            chunk = read_carry(path, offset)
            if chunk is None:
                continue
            body, remain = chunk
            item = self._msg(
                "role-carry",
                holder=holder,
                declarant=need["declarant"],
                capability=need["capability"],
                role=need["role"],
                offset=offset,
                remain=remain,
                body=body,
            )
            dest = self._assoc_for(holder)
            if dest is not None:
                self._send_record(dest, item)
                if self._assoc_for(holder) is None:
                    continue
            else:
                self._convey_frame(holder, wrap(encode_message(item, self.secret)))
            offset += len(body)
            if remain != 0:
                kept.append((holder, need, path, offset))
        self._outgoing = kept

    def _on_role_carry(self, assoc: Assoc, message: dict[str, Any], peer: bytes) -> None:
        if not self._from_peer(message, peer, assoc, False):
            return
        if message["holder"] != self.participant:
            dest = self._assoc_for(message["holder"])
            if dest is not None:
                forwarded = dict(message)
                forwarded["participant"] = self.participant
                self._send_record(dest, forwarded)
            return
        key = (message["declarant"], message["capability"], message["role"])
        path = store_path(self.config["state"], message["declarant"], message["capability"], message["role"])
        written = append_carry(path, message["offset"], message["body"])
        if written is None or message["remain"] != 0:
            return
        self._needed.discard(key)
        self._bind_received(message["declarant"], message["capability"], message["role"], path)
        pending = self._pending_steps
        self._pending_steps = []
        for item, author, token, carry in pending:
            reply = self._apply_step(item, author, token, carry)
            if reply is None:
                continue
            dest = self._assoc_for(author)
            if dest is not None:
                self._emit_step(dest, reply)
        if self._pending_ask is not None:
            request = self._pending_ask
            self._pending_ask = None
            self._ask(request)

    def _bind_received(self, declarant: bytes, capability: bytes, name: str, path: Path) -> None:
        if name == VOCABULARY:
            if self._vocabulary(declarant, capability) is None:
                self.config["vocabularies"].append(
                    {"declarant": declarant, "capability": capability, "path": str(path)}
                )
            return
        if self._artifact_item(declarant, capability, name) is None:
            self.config["artifacts"].append(
                {"declarant": declarant, "capability": capability, "role": name, "path": str(path)}
            )

    def _artifact(self, declarant: bytes, capability: bytes, role: str, reservation: int) -> bool:
        key = (declarant, capability, role)
        held = self.occupied.get(key)
        if held is not None:
            return len(held.state) == reservation
        path = self._file_path(declarant, capability, role)
        if path is None:
            return False
        item = self._artifact_item(declarant, capability, role)
        if item is not None and "digest" in item:
            meta = inspect_file(path)
            if meta is None:
                return False
            if hashlib.sha256(path.read_bytes()).digest() != item["digest"]:
                return False
        held = occupy(path, reservation)
        if held is None:
            return False
        self.occupied[key] = held
        return True

    def _assoc_for(self, peer: bytes) -> Assoc | None:
        for assoc in self.assocs.values():
            if self._peer(assoc) == peer:
                return assoc
        return None

    def _end(self, assoc: Assoc, closed: bool) -> None:
        peer = self._peer(assoc)
        self.assocs.pop((assoc.initiator, assoc.acceptor), None)
        if not closed:
            self.view.withdraw(peer)
            self._after_view()
        for session, held in list(self.held.items()):
            if held["opener"] == peer:
                self._vacate(held)
                del self.held[session]
        self.via.pop(peer, None)
        self.introducers.pop(peer, None)
        for subject, hops in list(self.introducers.items()):
            hops.discard(peer)
            if not hops:
                del self.introducers[subject]
        if not self.assocs:
            self._emit_notice()

    def _drop(self, participant: bytes) -> None:
        for pair, assoc in list(self.assocs.items()):
            if participant in pair:
                self._end(assoc, False)
        self.view.withdraw(participant)

    def _end_pending(self, pending: Pending, cause: str) -> None:
        self._rejection(pending.acceptor, cause, None)
        self.pending.pop(pending.acceptor, None)

    def command(self, line: str) -> None:
        text = line.strip()
        if text.startswith("nodo "):
            text = text[5:].strip()
        if not text:
            return
        self._ask(text.encode("utf-8"))

    def _ask(self, request: bytes) -> None:
        if self.opened is not None:
            self._abandon()
        try:
            open_allowed(request)
        except SessionError:
            return
        composition = self._pick()
        if composition is None:
            self._no_model()
            return
        declaration = self.view.declaration(composition["declarant"], composition["capability"])
        if declaration is None:
            self._no_model()
            return
        vocabulary = bytes_vocab()
        prompt = encode(vocabulary, request)
        if prompt is None or len(prompt) + declaration["bound"] > declaration["span"]:
            self._no_model()
            return
        session = uuid.uuid7().bytes
        opened = Opened(
            session=session,
            declarant=composition["declarant"],
            capability=composition["capability"],
            commitments=composition["commitments"],
            request=request,
            prompt=prompt,
            width=declaration["width"],
            bound=declaration["bound"],
            span=declaration["span"],
            vocabulary=vocabulary,
            token=prompt[0],
        )
        self.opened = opened
        self._open_peers(composition)
        if self.opened is None:
            return
        if any(self._assoc_for(item["participant"]) is None and item["participant"] != self.participant for item in composition["commitments"]):
            self._no_model()
            self.opened = None
            return
        self._step_in()

    def _pick(self) -> dict[str, Any] | None:
        for item in self.view.complete():
            if self.view.declaration(item["declarant"], item["capability"]) is None:
                continue
            return item
        return None

    def _abandon(self) -> None:
        opened = self.opened
        if opened is None:
            return
        self._tell(self._msg("session-close", session=opened.session), opened)
        self.held.pop(opened.session, None)
        self.opened = None

    def drain(self) -> tuple[list[str], list[str]]:
        out, err = self.terminal_out, self.terminal_err
        self.terminal_out = []
        self.terminal_err = []
        return out, err

    def serve(self) -> int:
        terminal = sys.stdin.isatty()
        if terminal:
            self._prompt()
        try:
            while True:
                self._apply_access()
                offering = not self.assocs or bool(self.pending) or bool(self._waiting())
                timeout = NOTICE_WAIT
                watches = [*self.placement.files()]
                if terminal:
                    watches.append(sys.stdin)
                reads, _, _ = select.select(watches, [], [], timeout)
                if offering and not reads:
                    self._work()
                    continue
                if any(item in reads for item in self.placement.files()):
                    self._work()
                    if self._emit(sys.stdout, sys.stderr) and terminal:
                        self._prompt()
                if terminal and sys.stdin in reads:
                    line = sys.stdin.readline()
                    if line == "":
                        return 0
                    self.command(line.strip())
                    self.step()
                    self._flush_mailbox()
                    self._emit(sys.stdout, sys.stderr)
                    if terminal:
                        self._prompt()
                if not reads:
                    self._work()
                    if self._emit(sys.stdout, sys.stderr) and terminal:
                        self._prompt()
        except KeyboardInterrupt:
            return 0

    def _prompt(self) -> None:
        if self.opened is not None:
            return
        sys.stdout.write("> ")
        sys.stdout.flush()

    def _apply_access(self) -> None:
        for token, line in take(self.config["state"]):
            self.command(line.strip())
            self.step()
            if self.opened is not None:
                self._mailbox.append(token)
                continue
            out, err = self.drain()
            reply(self.config["state"], token, out, err)

    def _flush_mailbox(self) -> None:
        if not self._mailbox or self.opened is not None:
            return
        out, err = self.drain()
        for token in self._mailbox:
            reply(self.config["state"], token, out, err)
        self._mailbox.clear()

    def _emit(self, out, err) -> bool:
        lines, errors = self.drain()
        _write_lines(out, err, lines, errors)
        return bool(lines or errors)

    def _vocabulary(self, declarant: bytes, capability: bytes):
        return bytes_vocab()

    def close(self) -> None:
        self._release()
        unlock(self._lock)
        self._lock = None
        self.placement.close()


def main() -> int:
    args = sys.argv[1:]
    try:
        prompt = parse_argv(args)
        config = join()
    except (AccessError, ConfigError) as exc:
        cause = str(getattr(exc, "cause", exc) or exc)
        sys.stderr.write(cause + "\n")
        return 2 if isinstance(exc, AccessError) else 1
    if prompt:
        forwarded = _via_access(config["state"], prompt)
        if forwarded is not None:
            return forwarded
    handle = lock(config["state"])
    if handle is None:
        if prompt:
            forwarded = _via_access(config["state"], prompt)
            if forwarded is not None:
                return forwarded
            sys.stderr.write("store\n")
            return 1
        if sys.stdin.isatty():
            return _client(config["state"])
        sys.stderr.write("store\n")
        return 1
    participant = None
    try:
        participant = Participant(config)
        participant._lock = handle
        if prompt:
            participant.command(prompt)
            participant.step()
            _print(*participant.drain())
        return participant.serve()
    except (ConfigError, LocalFailure, MeasureError, OSError, PlacementError, ValueError) as exc:
        sys.stderr.write(str(getattr(exc, "cause", exc)) + "\n")
        return 1
    finally:
        if participant is not None:
            participant.close()
        else:
            unlock(handle)


def _client(state: Path) -> int:
    while True:
        try:
            sys.stdout.write("> ")
            sys.stdout.flush()
            line = sys.stdin.readline()
        except KeyboardInterrupt:
            sys.stdout.write("\n")
            return 0
        if line == "":
            return 0
        text = line.strip()
        if not text:
            continue
        held = submit(state, text)
        if held is None:
            sys.stderr.write("store\n")
            return 1
        _print(*held)


def _via_access(state: Path, prompt: str) -> int | None:
    held = submit(state, prompt)
    if held is None:
        return None
    _print(*held)
    return 1 if held[1] else 0


def _write_lines(out, err, lines: list[str], errors: list[str]) -> None:
    for line in lines:
        out.write(line + "\n")
    for line in errors:
        err.write(line + "\n")
    out.flush()
    err.flush()


def _print(out: list[str], err: list[str]) -> None:
    _write_lines(sys.stdout, sys.stderr, out, err)


if __name__ == "__main__":
    raise SystemExit(main())
