from __future__ import annotations

from pathlib import Path
from typing import Any

from nodo.measure import host_budget
from nodo.domain import (
    CODE_MODEL,
    DIM,
    FF,
    HEADS,
    HIDDEN,
    KIND_BANK,
    KIND_EMBED,
    KIND_HEAD,
    KV,
    NAME,
    RMS,
    ROPE,
    SCALE,
    VOCAB,
)
from nodo.slice import bank_octets, dump, fit_span, header, inspect_file, reservation_of, rng
from nodo.vocabulary import bytes_vocab
from nodo.vocabulary import write as write_vocab


def load(root: Path, participant: bytes, budget: int | None = None) -> dict[str, Any] | None:
    budget = _ready(root, budget)
    if not _bank_path(root, participant).is_file():
        return None
    return publication(root, participant, budget)


def create(root: Path, participant: bytes, budget: int | None = None) -> dict[str, Any]:
    budget = _ready(root, budget, True)
    (root / "vocabulary").write_bytes(write_vocab(bytes_vocab()))
    path = _bank_path(root, participant)
    if not path.is_file():
        _write_bank(path, 0)
    result = _commit(root, participant, budget)
    if result is None:
        raise ValueError("model")
    return result


def open_part(root: Path, name: str, participant: bytes, budget: int | None = None) -> dict[str, Any] | None:
    budget = _budget(budget)
    root.mkdir(parents=True, exist_ok=True)
    if name == "embed":
        if (root / "head").is_file():
            return None
        _write_weights(root / "embed", KIND_EMBED, 0, VOCAB * HIDDEN + 2 * HIDDEN * HIDDEN, _seed(participant, 1))
    elif name == "head":
        if (root / "embed").is_file():
            return None
        maps = 4 * HIDDEN * HIDDEN + 2 * HIDDEN + 3 * HIDDEN * FF + HIDDEN + VOCAB * HIDDEN
        _write_weights(root / "head", KIND_HEAD, 1, maps, _seed(participant, 2))
    else:
        return None
    return _commit(root, participant, budget)


def publication(root: Path, participant: bytes, budget: int) -> dict[str, Any] | None:
    span, head_res = _window(budget)
    if span is None or head_res is None:
        return None
    roles = []
    embed = root / "embed"
    if _local(embed, KIND_EMBED):
        roles.append(_role("embed", 4, embed))
    bank = _bank_path(root, participant)
    if _local(bank, KIND_BANK):
        roles.append(_role(bank.name, 4, bank))
    head = root / "head"
    if _local(head, KIND_HEAD):
        roles.append(_role("head", head_res, head))
    if not roles:
        return None
    vocab = root / "vocabulary"
    return {
        "name": NAME,
        "width": HIDDEN * 2,
        "bound": span,
        "span": span,
        "roles": roles,
        "vocabulary": str(vocab.resolve()) if vocab.is_file() else None,
    }


def write_declaration(dest: Path, result: dict[str, Any]) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    import json

    payload = {
        "name": result["name"],
        "width": result["width"],
        "bound": result["bound"],
        "span": result["span"],
        "roles": [
            {"name": item["name"], "reservation": item["reservation"], "path": item["path"]}
            for item in result["roles"]
        ],
    }
    (dest / "declaration").write_text(json.dumps(payload), encoding="utf-8")


def _split(root: Path) -> None:
    embed = root / "embed"
    head = root / "head"
    if embed.is_file() and head.is_file():
        embed.unlink()
        head.unlink()


def _bank_path(root: Path, participant: bytes) -> Path:
    return root / ("bank-" + participant.hex())


def _local(path: Path, kind: int) -> bool:
    if not path.is_file():
        return False
    meta = inspect_file(path)
    return meta is not None and meta.get("code") == CODE_MODEL and meta["kind"] == kind


def _window(budget: int) -> tuple[int | None, int | None]:
    meta = {
        "layers": 1,
        "kv": KV,
        "dim": DIM,
        "hidden": HIDDEN,
        "heads": HEADS,
        "ff": FF,
    }
    span = fit_span(meta, budget, budget)
    if span is None:
        return None, None
    return span, reservation_of(meta, span)


def _budget(budget: int | None) -> int:
    return host_budget() if budget is None else budget


def _ready(root: Path, budget: int | None, make: bool = False) -> int:
    budget = _budget(budget)
    if make:
        root.mkdir(parents=True, exist_ok=True)
    _split(root)
    return budget


def _role(name: str, reservation: int, path: Path) -> dict[str, Any]:
    return {"name": name, "reservation": reservation, "path": str(path.resolve())}


def _commit(root: Path, participant: bytes, budget: int) -> dict[str, Any] | None:
    result = publication(root, participant, budget)
    if result is None:
        return None
    write_declaration(root, result)
    return result


def _seed(participant: bytes, salt: int) -> int:
    return (int.from_bytes(participant[:4], "big") ^ salt) or 1


def _model_header(kind: int, layers: int, weights: int) -> bytes:
    return header(kind, HIDDEN, VOCAB, layers, HEADS, KV, DIM, FF, weights, RMS, ROPE, CODE_MODEL)


def _write_weights(path: Path, kind: int, layers: int, count: int, seed: int) -> None:
    values = rng(count, seed, SCALE)
    with path.open("wb") as out:
        out.write(_model_header(kind, layers, values.size * 2))
        out.write(dump(values))


def _write_bank(path: Path, count: int) -> None:
    with path.open("wb") as out:
        out.write(_model_header(KIND_BANK, 0, bank_octets(HIDDEN, count)))
        out.write(count.to_bytes(4, "big"))
