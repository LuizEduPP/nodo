from __future__ import annotations

from pathlib import Path


def load(path: Path) -> list[tuple[str, int]]:
    if not path.is_file():
        return []
    found: list[tuple[str, int]] = []
    seen: set[tuple[str, int]] = set()
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    for line in lines:
        peer = parse_peer(line.strip())
        if peer is None or peer in seen:
            continue
        seen.add(peer)
        found.append(peer)
    return found


def write(path: Path, peers: list[tuple[str, int]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [f"{host}:{port}" for host, port in peers]
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def add(path: Path, peer: tuple[str, int]) -> None:
    held = load(path)
    if peer in held:
        return
    held.append(peer)
    write(path, held)


def parse_peer(text: str) -> tuple[str, int] | None:
    if not text or text.startswith("#"):
        return None
    host, sep, port_text = text.rpartition(":")
    if not sep or not host or any(char.isspace() for char in host):
        return None
    try:
        port = int(port_text)
    except ValueError:
        return None
    if isinstance(port, bool) or port < 1 or port > 65535:
        return None
    return host, port
