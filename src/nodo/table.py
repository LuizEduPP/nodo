from __future__ import annotations

from collections import defaultdict
from typing import Protocol
from weakref import WeakSet


class Replica(Protocol):
    identity: bytes
    token: str
    last: bytes | None

    def accept(self, frame: bytes, source: object) -> None: ...

    def route(self) -> object: ...

    def offer_shard(self, frame: bytes, present: set[str]) -> None: ...


class Table:
    def __init__(self) -> None:
        self._replicas: dict[bytes, WeakSet] = defaultdict(WeakSet)

    def join(self, replica: Replica) -> None:
        held = self._replicas[replica.identity]
        for other in list(held):
            if other is replica:
                continue
            frame = other.last
            if frame is not None:
                replica.accept(frame, other.route())
        held.add(replica)

    def leave(self, replica: Replica) -> None:
        self._replicas[replica.identity].discard(replica)

    def put(self, replica: Replica, frame: bytes) -> None:
        replica.last = frame
        source = replica.route()
        present: set[str] = set()
        for other in list(self._replicas[replica.identity]):
            if other is replica:
                continue
            other.accept(frame, source)
            present.add(other.token)
        replica.offer_shard(frame, present)


TABLE = Table()
