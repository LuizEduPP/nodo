from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from nodo.box import write_box
from nodo.domain import CLASSES, capability
from nodo.identity import load_secret, public_octets, write_identity
from nodo.measure import gpu_devices, host_budget, host_class
from nodo.seeds import load as load_peers


class ConfigError(Exception):
    pass


def join(publish: bool = True) -> dict[str, Any]:
    root = _data_root()
    root.mkdir(parents=True, exist_ok=True)
    identity = root / "ed25519"
    box = root / "box"
    state = root / "state"
    peers_path = root / "peers"
    if not identity.is_file():
        write_identity(identity)
    if not box.is_file():
        write_box(box)
    state.mkdir(parents=True, exist_ok=True)
    declaration = None
    publication = None
    device = None
    if publish:
        declaration, publication = _adopt_publication(public_octets(load_secret(identity)))
        device = _announce_device()
    return {
        "identity": identity,
        "box": box,
        "state": state,
        "announce": True,
        "condition": "accepted",
        "ram_limit": None,
        "vram_limit": None,
        "vram_device": device,
        "declaration": declaration,
        "artifacts": [],
        "vocabularies": [],
        "publication": publication,
        "listen": None,
        "peers": load_peers(peers_path),
        "peers_path": peers_path,
    }


def publication_root() -> Path:
    return _data_root() / "publication"


def _announce_device() -> str | None:
    if host_class() != "gpu":
        return None
    devices = gpu_devices()
    if len(devices) <= 1:
        return None
    return min(item[0] for item in devices)


def _adopt_publication(participant: bytes) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    from nodo.model import create, load

    root = publication_root()
    budget = host_budget()
    held = load(root, participant, budget)
    if held is None:
        try:
            held = create(root, participant, budget)
        except (OSError, TypeError, ValueError) as exc:
            raise ConfigError("publication") from exc
    held = dict(held)
    held["id"] = capability().hex()
    vocab = Path(held["vocabulary"]) if held.get("vocabulary") else root / "vocabulary"
    return _publication_from(held, root, vocab)


def _publication_from(
    raw: dict[str, Any], root: Path, vocabulary: Path
) -> tuple[dict[str, Any], dict[str, Any]]:
    if not isinstance(raw, dict):
        raise ConfigError("publication")
    try:
        roles_raw = raw["roles"]
        payload = {
            "name": raw["name"],
            "width": raw["width"],
            "bound": raw["bound"],
            "span": raw["span"],
            "roles": [
                {"name": item["name"], "reservation": item["reservation"]}
                for item in roles_raw
            ],
        }
        if "id" in raw:
            payload["id"] = raw["id"]
        declaration = _declaration(payload)
    except (ConfigError, KeyError, TypeError) as exc:
        raise ConfigError("publication") from exc
    roles = []
    for item in roles_raw:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str) or not item["path"]:
            raise ConfigError("publication")
        roles.append({"name": item["name"], "path": str(_path(root, item["path"]))})
    return declaration, {
        "roles": roles,
        "vocabulary": str(vocabulary) if vocabulary.is_file() else None,
    }


def _data_root() -> Path:
    raw = os.environ.get("XDG_DATA_HOME") or os.environ.get("LOCALAPPDATA")
    if raw:
        root = Path(raw)
        if not root.is_absolute():
            raise ConfigError("store")
        return root / "nodo"
    home = os.environ.get("HOME")
    if not home:
        raise ConfigError("store")
    return Path(home) / ".local" / "share" / "nodo"


def _str(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ConfigError(name)
    return value


def _path(root: Path, value: Any) -> Path:
    path = Path(_str(value, "path"))
    if not path.is_absolute():
        path = root / path
    return path


def _uint(value: Any, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ConfigError(name)
    return value


def _positive(value: Any, name: str) -> int:
    held = _uint(value, name)
    if held < 1:
        raise ConfigError(name)
    return held


def _hex(value: Any, size: int, name: str) -> bytes:
    if not isinstance(value, str):
        raise ConfigError(name)
    try:
        data = bytes.fromhex(value)
    except ValueError as exc:
        raise ConfigError(name) from exc
    if len(data) != size:
        raise ConfigError(name)
    return data


def _declaration(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ConfigError("declaration")
    allowed = {"name", "roles", "id", "width", "bound", "span"}
    if set(value) < {"name", "roles", "width", "bound", "span"} or set(value) - allowed:
        raise ConfigError("declaration")
    name = _str(value["name"], "declaration")
    if not isinstance(value["roles"], list) or not value["roles"]:
        raise ConfigError("declaration")
    roles = []
    for item in value["roles"]:
        if not isinstance(item, dict):
            raise ConfigError("roles")
        keys = set(item)
        if keys - {"name", "reservation", "class"} or not {"name", "reservation"} <= keys:
            raise ConfigError("roles")
        reservation = _positive(item["reservation"], "reservation")
        role = {"name": _str(item["name"], "roles"), "reservation": reservation}
        if "class" in item:
            if item["class"] not in CLASSES:
                raise ConfigError("class")
            role["class"] = item["class"]
        roles.append(role)
    width = _positive(value["width"], "width")
    bound = _positive(value["bound"], "bound")
    span = _uint(value["span"], "span")
    if span < bound:
        raise ConfigError("span")
    result = {"name": name, "roles": roles, "width": width, "bound": bound, "span": span}
    if "id" in value:
        identifier = _hex(value["id"], 16, "id")
        if identifier[6] >> 4 != 7:
            raise ConfigError("id")
        result["id"] = identifier
    return result
