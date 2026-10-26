from __future__ import annotations

import os
import select
import socket
import time
import uuid
from pathlib import Path

from nodo.domain import LISTEN, NOTICE_WAIT
from nodo.dht import Mesh
from nodo.domain import network
from nodo.frame import complete
from nodo.seeds import add as remember_peer
from nodo.seeds import load as load_peers
from nodo.table import TABLE


class PlacementError(Exception):
    pass


LOOP = frozenset({"127.0.0.1", "0.0.0.0", "", "localhost"})


def _gone(path: Path | None) -> None:
    if path is None:
        return
    try:
        path.unlink()
    except OSError:
        pass


def _ip_host(host: str) -> bool:
    try:
        socket.inet_aton(host)
        return True
    except OSError:
        return False


def _interface_ips() -> set[str]:
    found: set[str] = set()
    try:
        names = socket.if_nameindex()
    except (AttributeError, OSError):
        return found
    try:
        import fcntl
        import struct
    except ImportError:
        return found
    for _index, name in names:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            packed = fcntl.ioctl(sock, 0x8915, struct.pack("256s", name.encode()[:15]))
        except OSError:
            continue
        finally:
            sock.close()
        found.add(socket.inet_ntoa(packed[20:24]))
    return found


def _runtime_root() -> Path | None:
    for name in ("XDG_RUNTIME_DIR", "LOCALAPPDATA"):
        raw = os.environ.get(name)
        if not raw:
            continue
        root = Path(raw)
        if not root.is_absolute():
            raise PlacementError("store")
        return root
    return None


class Route:
    def __init__(
        self,
        placement: Placement | None = None,
        token: str = "",
        addr: tuple[str, int] | None = None,
    ) -> None:
        self.placement = placement
        self.token = token
        self.addr = addr

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Route):
            return False
        if self.placement is not None and other.placement is not None:
            return self.placement is other.placement
        if self.addr is not None and other.addr is not None:
            return self.addr == other.addr
        return bool(self.token) and self.token == other.token


class Placement:
    def __init__(
        self,
        listen: int | None = None,
        peers: tuple[tuple[str, int], ...] | list[tuple[str, int]] = (),
        peers_path: Path | None = None,
    ) -> None:
        if listen is not None and (
            not isinstance(listen, int)
            or isinstance(listen, bool)
            or listen < 1
            or listen > 65535
        ):
            raise PlacementError("listen")
        self.identity = network()
        self.token = uuid.uuid4().hex
        self.last: bytes | None = None
        self._inbox: list[tuple[bytes, Route]] = []
        self._dir: Path | None = None
        self._path: Path | None = None
        self._put: Path | None = None
        self._announced: Path | None = None
        self._listen: socket.socket | None = None
        self._dht: Mesh | None = None
        self._incoming: list[tuple[socket.socket, tuple[str, int], bytearray]] = []
        self._sent: set[tuple[str, int]] = set()
        self._peers_path = peers_path
        known = list(load_peers(peers_path)) if peers_path is not None else []
        self._peers = self._peer_paths(known + list(peers))
        self._resolved: dict[tuple[str, int], list[tuple[str, int]]] = {}
        self._locals: set[str] | None = None
        self._bind_world(listen)
        self._open_world()
        root = _runtime_root()
        if root is not None:
            self._join(root)
            self._take_shard()
        TABLE.join(self)

    def _peer_paths(
        self, peers: tuple[tuple[str, int], ...] | list[tuple[str, int]]
    ) -> list[tuple[str, int]]:
        found = []
        seen: set[tuple[str, int]] = set()
        for item in peers:
            if (
                not isinstance(item, tuple)
                or len(item) != 2
                or not isinstance(item[0], str)
                or not item[0]
                or not isinstance(item[1], int)
                or isinstance(item[1], bool)
                or item[1] < 1
                or item[1] > 65535
            ):
                raise PlacementError("peers")
            peer = (item[0], item[1])
            if peer in seen:
                continue
            seen.add(peer)
            found.append(peer)
        return found

    def _bind_world(self, listen: int | None) -> None:
        port = listen if listen is not None else LISTEN
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("", port))
            sock.listen()
            sock.setblocking(False)
            sock.getsockname()[1]
        except OSError as exc:
            sock.close()
            if listen is not None:
                raise PlacementError("listen") from exc
            return
        self._listen = sock

    def _open_world(self) -> None:
        if self._listen is None:
            return
        try:
            self._dht = Mesh(self._listen.getsockname()[1], self._worldwide)
        except ValueError as exc:
            raise PlacementError("listen") from exc
        self._dht.seed(self._peers)

    def _join(self, root: Path) -> None:
        directory = root / "nodo" / self.identity.hex()
        directory.mkdir(parents=True, exist_ok=True)
        marker = directory / "identity"
        if marker.exists():
            try:
                held = marker.read_bytes()
            except OSError as exc:
                raise PlacementError("store") from exc
            if held != self.identity:
                raise PlacementError("store")
        else:
            marker.write_bytes(self.identity)
        path = directory / self.token
        try:
            path.write_bytes(b"")
        except OSError as exc:
            raise PlacementError("store") from exc
        self._dir = directory
        self._path = path
        self._put = directory / (self.token + ".put")
        if self._listen is not None:
            port = self._listen.getsockname()[1]
            announced = directory / (self.token + ".listen")
            try:
                announced.write_text(str(port), encoding="ascii")
            except OSError as exc:
                raise PlacementError("store") from exc
            self._announced = announced

    def _take_shard(self) -> None:
        if self._dir is None:
            return
        for path in self._dir.iterdir():
            if not path.name.endswith(".put") or path.name == self.token + ".put":
                continue
            try:
                frame = path.read_bytes()
            except OSError:
                continue
            if not complete(frame):
                continue
            token = path.name[: -len(".put")]
            self.accept(frame, Route(token=token))

    def files(self) -> list:
        found = []
        if self._listen is not None:
            found.append(self._listen)
        if self._dht is not None:
            found.extend(self._dht.files())
        for conn, _addr, _buf in self._incoming:
            found.append(conn)
        return found

    def route(self) -> Route:
        return Route(self, self.token)

    def notice(self, frame: bytes) -> None:
        if not complete(frame):
            return
        self._sent = set()
        TABLE.put(self, frame)
        self.tick()

    def offer_shard(self, frame: bytes, present: set[str]) -> None:
        if self._put is not None:
            try:
                self._put.write_bytes(frame)
            except OSError:
                pass
        if self._dir is None:
            return
        for path in self._dir.iterdir():
            if not path.name.endswith(".listen") or path.name == self.token + ".listen":
                continue
            token = path.name[: -len(".listen")]
            if token in present:
                continue
            port = self._listen_port(token)
            if port is None:
                continue
            self._write_path(("127.0.0.1", port), frame)

    def place(self, route: Route, frame: bytes) -> None:
        if not complete(frame):
            raise PlacementError("place")
        if route.placement is self:
            self.accept(frame, self.route())
            return
        if route.placement is not None:
            if route.placement.identity != self.identity:
                raise PlacementError("place")
            route.placement.accept(frame, self.route())
            return
        if route.addr is not None:
            if not self._offer(route.addr, frame):
                raise PlacementError("place")
            return
        if not route.token or self._dir is None:
            raise PlacementError("route")
        port = self._listen_port(route.token)
        if port is None:
            raise PlacementError("route")
        if not self._write_path(("127.0.0.1", port), frame):
            raise PlacementError("place")

    def accept(self, frame: bytes, source: Route) -> None:
        if not complete(frame):
            return
        self._inbox.append((frame, source))

    def receive(self) -> tuple[bytes, Route] | None:
        self.tick()
        if not self._inbox:
            return None
        return self._inbox.pop(0)

    def tick(self) -> None:
        self._drive()
        self._discover()
        if self._dht is not None and self.last is not None:
            deadline = time.monotonic() + NOTICE_WAIT
            seen: set[tuple[str, int]] = set()
            if not self._fan(self._dht.contacts() + list(self._peers), seen, deadline):
                self._fan(self._dht.take(), seen, deadline)
        self._drive()

    def _discover(self) -> None:
        if self._dht is None:
            return
        self._dht.tick()
        for peer in self._dht.take():
            self._adopt(peer)
        for frame, addr in self._dht.heard():
            for reply in self._replies(frame, addr):
                self._dht.put(addr, reply)

    def _fan(self, peers, seen: set[tuple[str, int]], deadline: float) -> bool:
        frame = self.last
        if frame is None:
            return False
        for peer in peers:
            if time.monotonic() >= deadline:
                return True
            if peer in seen:
                continue
            seen.add(peer)
            self._offer(peer, frame, deadline)
        return False

    def _listen_port(self, token: str) -> int | None:
        if self._dir is None:
            return None
        try:
            port = int((self._dir / (token + ".listen")).read_text(encoding="ascii"))
        except (OSError, ValueError):
            return None
        if port < 1 or port > 65535:
            return None
        return port

    def _adopt(self, peer: tuple[str, int]) -> None:
        if self._own(peer) or peer[0] in LOOP:
            return
        if self._dht is not None:
            self._dht.seed([peer])
        self._remember(peer)

    def _drive(self) -> None:
        self._accept()
        self._read_incoming()

    def _local_ips(self) -> set[str]:
        if self._locals is not None:
            return self._locals
        found = set(LOOP)
        if self._listen is not None:
            host = self._listen.getsockname()[0]
            if host:
                found.add(host)
        try:
            for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
                found.add(str(info[4][0]))
        except (OSError, socket.gaierror):
            pass
        found.update(_interface_ips())
        self._locals = found
        return found

    def _destinations(self, addr: tuple[str, int]) -> set[tuple[str, int]]:
        found = {addr}
        found.update(self._resolve(addr))
        return found

    def _resolve(self, addr: tuple[str, int]) -> list[tuple[str, int]]:
        held = self._resolved.get(addr)
        if held is not None:
            return held
        if _ip_host(addr[0]):
            self._resolved[addr] = [addr]
            return [addr]
        found: list[tuple[str, int]] = []
        try:
            for info in socket.getaddrinfo(addr[0], addr[1], socket.AF_INET, socket.SOCK_STREAM):
                peer = (str(info[4][0]), int(info[4][1]))
                if peer not in found:
                    found.append(peer)
        except (OSError, socket.gaierror):
            found = [addr]
        if not found:
            found = [addr]
        self._resolved[addr] = found
        return found

    def _own(self, addr: tuple[str, int]) -> bool:
        if self._listen is None:
            return False
        port = self._listen.getsockname()[1]
        local = self._local_ips()
        for host, listen in self._destinations(addr):
            if listen != port:
                continue
            if host in local:
                return True
        return False

    def _worldwide(self, peer: tuple[str, int]) -> bool:
        if peer[0] in LOOP:
            return False
        return not self._own(peer)

    def _replies(self, frame: bytes, addr: tuple[str, int]) -> list[bytes]:
        if complete(frame):
            self.accept(frame, Route(addr=addr))
            if self.last is not None and self.last != frame:
                return [self.last]
        return []

    def _absorb(self, data: bytes, addr: tuple[str, int]) -> None:
        if complete(data):
            self._replies(data, addr)

    def _offer(self, addr: tuple[str, int], frame: bytes, deadline: float | None = None) -> bool:
        sent = False
        if self._dht is not None and not self._own(addr):
            self._dht.put(addr, frame)
            sent = True
        if self._write_path(addr, frame, True, deadline):
            return True
        return sent

    def _write_path(
        self,
        addr: tuple[str, int],
        frame: bytes,
        once: bool = True,
        deadline: float | None = None,
    ) -> bool:
        if deadline is None:
            deadline = time.monotonic() + NOTICE_WAIT
        if time.monotonic() >= deadline:
            return False
        if self._own(addr):
            return True
        if once and addr in self._sent:
            return True
        targets = self._resolve(addr)
        dest = targets[0] if targets else addr
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setblocking(False)
        try:
            try:
                sock.connect(dest)
            except BlockingIOError:
                pass
            except OSError:
                return False
            if not self._wait_sock(sock, True, deadline):
                return False
            err = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            if err:
                return False
            try:
                peer = sock.getpeername()
                resolved = (str(peer[0]), int(peer[1]))
            except OSError:
                return False
            if self._own(resolved):
                if once:
                    self._sent.add(addr)
                    self._sent.add(resolved)
                return True
            if not self._send_all(sock, frame, deadline):
                return False
            try:
                sock.shutdown(socket.SHUT_WR)
            except OSError:
                return False
            reply = bytearray()
            while time.monotonic() < deadline:
                chunk = self._recv_some(sock, deadline)
                if chunk is None:
                    return False
                if chunk == b"":
                    break
                reply.extend(chunk)
            else:
                return False
            if once:
                self._sent.add(addr)
                self._sent.add(resolved)
            if complete(frame) and self._dht is not None and self._worldwide(resolved):
                self._dht.seed([resolved])
                self._remember(resolved)
            if reply:
                self._absorb(bytes(reply), resolved)
            return True
        finally:
            sock.close()

    def _wait_sock(self, sock: socket.socket, write: bool, deadline: float) -> bool:
        while time.monotonic() < deadline:
            remaining = max(0.0, deadline - time.monotonic())
            reads = [*self.files()]
            writes = [sock] if write else []
            if not write:
                reads.append(sock)
            try:
                ready_r, ready_w, ready_x = select.select(reads, writes, [sock], remaining)
            except (ValueError, OSError):
                return False
            self._drive()
            if sock in ready_x:
                return False
            if write and sock in ready_w:
                return True
            if not write and sock in ready_r:
                return True
        return False

    def _send_all(self, sock: socket.socket, frame: bytes, deadline: float) -> bool:
        view = memoryview(frame)
        offset = 0
        while offset < len(frame):
            if time.monotonic() >= deadline:
                return False
            try:
                sent = sock.send(view[offset:])
            except BlockingIOError:
                if not self._wait_sock(sock, True, deadline):
                    return False
                continue
            except OSError:
                return False
            if sent == 0:
                return False
            offset += sent
        return True

    def _recv_some(self, sock: socket.socket, deadline: float) -> bytes | None:
        while True:
            if time.monotonic() >= deadline:
                return None
            try:
                return sock.recv(65536)
            except BlockingIOError:
                if not self._wait_sock(sock, False, deadline):
                    return None
            except OSError:
                return None

    def _accept(self) -> None:
        if self._listen is None:
            return
        while True:
            try:
                conn, addr = self._listen.accept()
            except BlockingIOError:
                return
            except OSError:
                return
            if not isinstance(addr, tuple) or len(addr) < 2:
                conn.close()
                continue
            conn.setblocking(False)
            self._incoming.append((conn, (str(addr[0]), int(addr[1])), bytearray()))

    def _read_incoming(self) -> None:
        held = []
        for conn, addr, buf in self._incoming:
            closed = False
            while True:
                try:
                    chunk = conn.recv(65536)
                except BlockingIOError:
                    break
                except OSError:
                    closed = True
                    break
                if not chunk:
                    closed = True
                    break
                buf.extend(chunk)
            if not closed:
                held.append((conn, addr, buf))
                continue
            replies = self._replies(bytes(buf), addr)
            if replies:
                conn.settimeout(NOTICE_WAIT)
                try:
                    conn.setblocking(True)
                    for reply in replies:
                        conn.sendall(reply)
                    conn.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
            conn.close()
        self._incoming = held

    def _remember(self, peer: tuple[str, int]) -> None:
        if self._peers_path is None:
            return
        if peer in self._peers:
            return
        self._peers.append(peer)
        try:
            remember_peer(self._peers_path, peer)
        except OSError:
            pass

    def close(self) -> None:
        if self._dht is not None:
            for peer in self._dht.contacts():
                if self._worldwide(peer):
                    self._remember(peer)
        TABLE.leave(self)
        for conn, _addr, _buf in self._incoming:
            conn.close()
        self._incoming = []
        if self._dht is not None:
            self._dht.close()
            self._dht = None
        if self._listen is not None:
            self._listen.close()
            self._listen = None
        _gone(self._path)
        self._path = None
        _gone(self._announced)
        self._announced = None
        _gone(self._put)
        self._put = None
