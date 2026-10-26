from __future__ import annotations

import hashlib
import os
import socket
import time
from typing import Callable

from nodo.domain import ALPHA, DOORS, HASH, K, NOTICE_WAIT
from nodo.frame import complete

Admit = Callable[[tuple[str, int]], bool]


class Mesh:
    def __init__(self, port: int, admit: Admit | None = None) -> None:
        if port < 1 or port > 65535:
            raise ValueError("port")
        self.port = port
        self._admit = admit
        self._sock: socket.socket | None = None
        self._id = os.urandom(20)
        self._seq = 0
        self._nodes: dict[bytes, tuple[str, int]] = {}
        self._extra: list[tuple[str, int]] = []
        self._boot: set[tuple[str, int]] = set()
        self._peers: set[tuple[str, int]] = set()
        self._seen: set[tuple[str, int]] = set()
        self._queried: set[tuple[str, int]] = set()
        self._pending: dict[bytes, tuple[bytes, tuple[str, int], float]] = {}
        self._tokens: dict[tuple[str, int], bytes] = {}
        self._heard: list[tuple[bytes, tuple[str, int]]] = []
        self._public: tuple[str, int] | None = None
        self._told = False
        self._hosts: dict[tuple[str, int], list[tuple[str, int]]] = {}
        self._bind()

    def files(self) -> list:
        return [self._sock] if self._sock is not None else []

    def seed(self, peers: list[tuple[str, int]]) -> None:
        for peer in peers:
            for dest in self._resolve(peer):
                if dest in self._extra:
                    continue
                self._extra.append(dest)
                self._keep(dest)

    def tick(self) -> None:
        self._read()
        now = time.monotonic()
        for tid, (_name, peer, started) in list(self._pending.items()):
            if now - started < NOTICE_WAIT:
                continue
            self._pending.pop(tid, None)
            self._queried.add(peer)
        if not self._pending:
            self._step()

    def take(self) -> list[tuple[str, int]]:
        fresh = [peer for peer in self._peers if peer not in self._seen]
        self._seen.update(fresh)
        return fresh

    def contacts(self) -> list[tuple[str, int]]:
        return list(self._peers)

    def heard(self) -> list[tuple[bytes, tuple[str, int]]]:
        held, self._heard = self._heard, []
        return held

    def put(self, peer: tuple[str, int], data: bytes) -> None:
        for dest in self._resolve(peer):
            self._send(dest, data)

    def close(self) -> None:
        if self._sock is None:
            return
        try:
            self._sock.close()
        except OSError:
            pass
        self._sock = None

    def _keep(self, peer: tuple[str, int]) -> None:
        if peer == self._public:
            return
        if self._admit is not None and not self._admit(peer):
            return
        self._peers.add(peer)

    def _targets(self) -> list[tuple[str, int]]:
        found: list[tuple[str, int]] = []
        seen: set[tuple[str, int]] = set()
        ranked = [(ip, port) for _ident, (ip, port) in sorted(self._nodes.items(), key=lambda item: _xor(item[0], HASH))]
        if _fill(found, seen, ranked):
            return found
        _fill(found, seen, (*self._boot, *self._extra))
        return found

    def _step(self) -> None:
        self._ensure_boot()
        sent = 0
        pending = {item[1] for item in self._pending.values()}
        for peer in self._targets():
            if peer in self._queried or peer in pending:
                continue
            self._ask(peer, b"get_peers", {b"id": self._id, b"info_hash": HASH})
            sent += 1
            if sent >= ALPHA:
                return
        if self._pending:
            return
        if not self._told:
            self._announce()
            self._told = True
        if not self._peers:
            self._queried.clear()
            self._told = False

    def _announce(self) -> None:
        for peer, token in list(self._tokens.items()):
            self._ask(
                peer,
                b"announce_peer",
                {
                    b"id": self._id,
                    b"info_hash": HASH,
                    b"port": self.port,
                    b"token": token,
                    b"implied_port": 1,
                },
            )

    def _ask(self, peer: tuple[str, int], name: bytes, args: dict[bytes, object]) -> None:
        tid = self._tid()
        self._pending[tid] = (name, peer, time.monotonic())
        try:
            body = _encode({b"t": tid, b"y": b"q", b"q": name, b"a": args})
        except TypeError:
            self._pending.pop(tid, None)
            return
        self._send(peer, body)

    def _tid(self) -> bytes:
        self._seq = (self._seq + 1) & 0xFFFF
        return self._seq.to_bytes(2, "big")

    def _bind(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("", self.port))
        except OSError:
            sock.close()
            return
        sock.setblocking(False)
        self._sock = sock

    def _read(self) -> None:
        if self._sock is None:
            return
        while True:
            try:
                data, addr = self._sock.recvfrom(65536)
            except BlockingIOError:
                return
            except OSError:
                return
            peer = (str(addr[0]), int(addr[1]))
            if complete(data):
                self._keep(peer)
                self._heard.append((data, peer))
                continue
            msg = _decode(data)
            if msg is None:
                continue
            kind = msg.get(b"y")
            if kind == b"r":
                self._on_reply(msg, peer)
            elif kind == b"q":
                self._on_query(msg, peer)

    def _on_reply(self, msg: dict[bytes, object], peer: tuple[str, int]) -> None:
        tid = msg.get(b"t")
        held = self._pending.pop(tid, None) if isinstance(tid, bytes) else None
        body = msg.get(b"r")
        if not isinstance(body, dict):
            return
        self._glance(body)
        ident = body.get(b"id")
        if isinstance(ident, bytes) and len(ident) == 20:
            self._touch(ident, peer)
        if held is not None:
            self._queried.add(held[1])
            self._queried.add(peer)
        token = body.get(b"token")
        if isinstance(token, bytes) and token:
            self._tokens[peer] = token
            if held is not None:
                self._tokens[held[1]] = token
        for ident, ip, port in _nodes(body.get(b"nodes")):
            self._touch(ident, (ip, port))
        for hop in _peers(body.get(b"values")):
            self._keep(hop)

    def _on_query(self, msg: dict[bytes, object], peer: tuple[str, int]) -> None:
        tid = msg.get(b"t")
        name = msg.get(b"q")
        args = msg.get(b"a")
        if not isinstance(tid, bytes) or not isinstance(name, bytes) or not isinstance(args, dict):
            return
        ident = args.get(b"id")
        if not isinstance(ident, bytes) or len(ident) != 20:
            return
        self._touch(ident, peer)
        reply: dict[bytes, object] = {b"id": self._id}
        if name == b"get_peers":
            reply[b"token"] = self._token(peer)
            target = args.get(b"info_hash")
            values = self._values()
            if values and target == HASH:
                reply[b"values"] = values
            else:
                reply[b"nodes"] = self._compact(target if isinstance(target, bytes) else ident)
        elif name == b"find_node":
            target = args.get(b"target")
            reply[b"nodes"] = self._compact(target if isinstance(target, bytes) else ident)
        elif name == b"announce_peer":
            if args.get(b"token") != self._token(peer) or args.get(b"info_hash") != HASH:
                return
            port = peer[1]
            if not args.get(b"implied_port"):
                held = args.get(b"port")
                if isinstance(held, int) and not isinstance(held, bool) and 1 <= held <= 65535:
                    port = held
            self._keep((peer[0], port))
        elif name != b"ping":
            return
        self._reply(peer, tid, reply)

    def _reply(self, peer: tuple[str, int], tid: bytes, reply: dict[bytes, object]) -> None:
        try:
            body = _encode({b"t": tid, b"y": b"r", b"r": reply})
        except TypeError:
            return
        self._send(peer, body)

    def _glance(self, body: dict[bytes, object]) -> None:
        raw = body.get(b"ip")
        if not isinstance(raw, bytes):
            return
        if len(raw) >= 6:
            peer = _addr6(raw[:6])
            if peer is None:
                return
            self._public = peer
            return
        if len(raw) == 4:
            self._public = (socket.inet_ntoa(raw), self.port)

    def _touch(self, ident: bytes, peer: tuple[str, int]) -> None:
        if len(ident) != 20 or ident == self._id:
            return
        self._nodes[ident] = (peer[0], peer[1])

    def _token(self, peer: tuple[str, int]) -> bytes:
        return hashlib.sha1(self._id + peer[0].encode("ascii") + peer[1].to_bytes(2, "big")).digest()[:8]

    def _values(self) -> list[bytes]:
        found: list[bytes] = []
        for ip, port in self._peers:
            if self._admit is not None and not self._admit((ip, port)):
                continue
            try:
                found.append(_host(ip, port))
            except OSError:
                continue
            if len(found) >= K:
                break
        return found

    def _compact(self, target: object) -> bytes:
        key = target if isinstance(target, bytes) and len(target) == 20 else self._id
        body = b""
        count = 0
        ranked = sorted(self._nodes.items(), key=lambda item: _xor(item[0], key))
        for ident, (ip, port) in ranked:
            try:
                body += ident + _host(ip, port)
            except OSError:
                continue
            count += 1
            if count >= K:
                break
        return body

    def _ensure_boot(self) -> None:
        if self._boot:
            return
        for host, port in DOORS:
            try:
                infos = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_DGRAM)
            except OSError:
                continue
            for info in infos:
                dest = (str(info[4][0]), int(info[4][1]))
                self._boot.add(dest)
                self._keep(dest)

    def _resolve(self, addr: tuple[str, int]) -> list[tuple[str, int]]:
        held = self._hosts.get(addr)
        if held is not None:
            return held
        try:
            socket.inet_aton(addr[0])
        except OSError:
            found: list[tuple[str, int]] = []
            try:
                for info in socket.getaddrinfo(addr[0], addr[1], socket.AF_INET, socket.SOCK_DGRAM):
                    peer = (str(info[4][0]), int(info[4][1]))
                    if peer not in found:
                        found.append(peer)
            except OSError:
                found = [addr]
            if not found:
                found = [addr]
            self._hosts[addr] = found
            return found
        self._hosts[addr] = [addr]
        return [addr]

    def _send(self, peer: tuple[str, int], data: bytes) -> None:
        if self._sock is None:
            return
        try:
            self._sock.sendto(data, peer)
        except OSError:
            return


def _fill(found: list[tuple[str, int]], seen: set[tuple[str, int]], peers) -> bool:
    for peer in peers:
        if peer in seen:
            continue
        seen.add(peer)
        found.append(peer)
        if len(found) >= K:
            return True
    return False


def _host(ip: str, port: int) -> bytes:
    return socket.inet_aton(ip) + port.to_bytes(2, "big")


def _xor(left: bytes, right: bytes) -> int:
    return int.from_bytes(bytes(a ^ b for a, b in zip(left, right)), "big")


def _encode(value: object) -> bytes:
    if isinstance(value, bool):
        raise TypeError
    if isinstance(value, int):
        return b"i" + str(value).encode("ascii") + b"e"
    if isinstance(value, bytes):
        return str(len(value)).encode("ascii") + b":" + value
    if isinstance(value, list):
        return b"l" + b"".join(_encode(item) for item in value) + b"e"
    if isinstance(value, dict):
        body = b"d"
        for key in sorted(value):
            if not isinstance(key, bytes):
                raise TypeError
            body += _encode(key) + _encode(value[key])
        return body + b"e"
    raise TypeError


def _decode(data: bytes) -> dict[bytes, object] | None:
    try:
        value, index = _read(data, 0)
    except (IndexError, OverflowError, ValueError):
        return None
    if index != len(data) or not isinstance(value, dict):
        return None
    return value


def _read(data: bytes, index: int) -> tuple[object, int]:
    mark = data[index]
    if mark == 105:
        end = data.index(101, index + 1)
        raw = data[index + 1 : end]
        if len(raw) > 20 or raw == b"" or raw == b"-":
            raise ValueError
        if raw != b"0" and (raw.startswith(b"0") or raw.startswith(b"-0")):
            raise ValueError
        return int(raw), end + 1
    if mark == 108:
        index += 1
        items = []
        while data[index] != 101:
            item, index = _read(data, index)
            items.append(item)
        return items, index + 1
    if mark == 100:
        index += 1
        items: dict[bytes, object] = {}
        while data[index] != 101:
            key, index = _read(data, index)
            if not isinstance(key, bytes):
                raise ValueError
            value, index = _read(data, index)
            items[key] = value
        return items, index + 1
    if 48 <= mark <= 57:
        colon = data.index(58, index)
        size = int(data[index:colon])
        start = colon + 1
        end = start + size
        if size < 0 or size > 65535 or end > len(data):
            raise ValueError
        return data[start:end], end
    raise ValueError


def _addr6(item: bytes) -> tuple[str, int] | None:
    if len(item) != 6:
        return None
    port = int.from_bytes(item[4:6], "big")
    if port < 1:
        return None
    return socket.inet_ntoa(item[:4]), port


def _nodes(raw: object) -> list[tuple[bytes, str, int]]:
    if not isinstance(raw, bytes):
        return []
    found = []
    width = len(raw) - len(raw) % 26
    for offset in range(0, width, 26):
        item = raw[offset : offset + 26]
        peer = _addr6(item[20:26])
        if peer is None:
            continue
        found.append((item[:20], peer[0], peer[1]))
    return found


def _peers(raw: object) -> list[tuple[str, int]]:
    chunks: list[bytes] = []
    if isinstance(raw, bytes):
        width = len(raw) - len(raw) % 6
        chunks = [raw[offset : offset + 6] for offset in range(0, width, 6)]
    elif isinstance(raw, list):
        chunks = [item for item in raw if isinstance(item, bytes)]
    found = []
    for item in chunks:
        peer = _addr6(item)
        if peer is not None:
            found.append(peer)
    return found
