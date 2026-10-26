from __future__ import annotations

import math
import struct
from pathlib import Path
from typing import Any, BinaryIO

import numpy as np

from nodo.domain import (
    CODE_MODEL,
    HEAD_CHUNK,
    HEADER,
    KIND_BANK,
    KIND_EMBED,
    KIND_HEAD,
    KINDS,
    SLICE_MAGIC,
)


class Held:
    def __init__(self, meta: dict[str, Any], state: bytearray, source: Path | bytes) -> None:
        self.meta = meta
        self.state = state
        self._path = source if isinstance(source, Path) else None
        self._blob = source if isinstance(source, (bytes, bytearray)) else None
        self._file: BinaryIO | None = None

    def close(self) -> None:
        if self._file is not None:
            self._file.close()
            self._file = None

    def octets(self, offset: int, size: int) -> bytes:
        if size < 1:
            return b""
        if self._blob is not None:
            return bytes(self._blob[offset : offset + size])
        handle = self._open()
        handle.seek(offset)
        return handle.read(size)

    def floats(self, offset: int, count: int) -> np.ndarray:
        if count < 1:
            return np.zeros(0, dtype=np.float32)
        raw = self.octets(offset, count * 2)
        if len(raw) != count * 2:
            return np.zeros(0, dtype=np.float32)
        return np.frombuffer(raw, dtype=">f2").astype(np.float32)

    def _open(self) -> BinaryIO:
        if self._file is None:
            if self._path is None:
                raise ValueError("slice")
            self._file = self._path.open("rb")
        return self._file


def header(
    kind: int,
    hidden: int,
    vocab: int,
    layers: int,
    heads: int,
    kv: int,
    dim: int,
    ff: int,
    weights: int,
    rms: float,
    rope: float,
    code: int = CODE_MODEL,
) -> bytes:
    if rms <= 0 or rope <= 0:
        raise ValueError("slice")
    if code != CODE_MODEL or kind not in KINDS:
        raise ValueError("slice")
    return (
        SLICE_MAGIC
        + bytes([code, kind])
        + _put32(hidden, vocab, layers, heads, kv, dim, ff)
        + struct.pack(">f", rms)
        + struct.pack(">f", rope)
        + weights.to_bytes(8, "big")
    )


def header_from(meta: dict[str, Any], **over: Any) -> bytes:
    fields = {**meta, **over}
    return header(
        fields["kind"],
        fields["hidden"],
        fields["vocab"],
        fields["layers"],
        fields["heads"],
        fields["kv"],
        fields["dim"],
        fields["ff"],
        fields["weights"],
        fields["rms"],
        fields["rope"],
        fields.get("code", CODE_MODEL),
    )


def inspect(data: bytes) -> dict[str, Any] | None:
    if len(data) < HEADER or data[:6] != SLICE_MAGIC:
        return None
    code, kind = data[6], data[7]
    if code != CODE_MODEL or kind not in KINDS:
        return None
    hidden, vocab, layers, heads, kv, dim, ff = _get32(data, 8, 7)
    rms = struct.unpack(">f", data[36:40])[0]
    rope = struct.unpack(">f", data[40:44])[0]
    weights = int.from_bytes(data[44:52], "big")
    if hidden < 1 or vocab < 1 or heads < 1 or kv < 1 or dim < 1:
        return None
    if heads * dim != hidden or heads % kv != 0:
        return None
    if layers < 0:
        return None
    if layers > 0 and ff < 1:
        return None
    if rms <= 0 or rope <= 0:
        return None
    return {
        "code": code,
        "kind": kind,
        "hidden": hidden,
        "vocab": vocab,
        "layers": layers,
        "heads": heads,
        "kv": kv,
        "dim": dim,
        "ff": ff,
        "rms": rms,
        "rope": rope,
        "weights": weights,
    }


def _put32(*values: int) -> bytes:
    return b"".join(value.to_bytes(4, "big") for value in values)


def _get32(data: bytes, start: int, count: int) -> list[int]:
    return [int.from_bytes(data[start + 4 * i : start + 4 * (i + 1)], "big") for i in range(count)]


def inspect_file(path: Path) -> dict[str, Any] | None:
    try:
        with path.open("rb") as handle:
            return inspect(handle.read(HEADER))
    except OSError:
        return None


def parse(data: bytes) -> dict[str, Any] | None:
    meta = inspect(data)
    if meta is None or HEADER + meta["weights"] > len(data):
        return None
    return meta


def width_of(meta: dict[str, Any]) -> int:
    return meta["hidden"] * 2


def state_octets(layers: int, span: int, kv: int, dim: int) -> int:
    return 4 + layers * 2 * span * kv * dim * 2


def reservation_of(meta: dict[str, Any], span: int) -> int | None:
    if span < 1:
        return None
    return state_octets(meta["layers"], span, meta["kv"], meta["dim"])


def reservation_for(data: bytes, span: int) -> int | None:
    meta = inspect(data)
    if meta is None:
        return None
    return reservation_of(meta, span)


def fit_span(meta: dict[str, Any], budget: int, ceiling: int) -> int | None:
    if ceiling < 1 or budget < 1:
        return None
    per = meta["layers"] * 2 * meta["kv"] * meta["dim"] * 2
    if per < 1:
        return ceiling if budget >= 4 else None
    if budget < 4 + per:
        return None
    span = min(ceiling, (budget - 4) // per)
    return span if span >= 1 else None


def rng(count: int, seed: int, scale: float = 1.0) -> np.ndarray:
    state = seed & 0xFFFFFFFF
    values = np.empty(count, dtype=np.float32)
    for index in range(count):
        state = (1664525 * state + 1013904223) & 0xFFFFFFFF
        values[index] = (((state >> 8) & 0xFFFF) / 32768.0 - 1.0) * scale
    return values


def dump(values: np.ndarray) -> bytes:
    return np.asarray(values, dtype=np.float32).astype(">f2").tobytes()


def apply(
    held: Held,
    width: int,
    index: int,
    count: int,
    token: int | None,
    carry: bytes | None,
    position: int,
    span: int,
) -> tuple[str, int | bytes] | None:
    if held.meta.get("code") != CODE_MODEL:
        return None
    return apply_model(held, width, index, count, token, carry, position, span)


def _ends(
    meta: dict[str, Any], width: int, index: int, count: int, position: int, span: int
) -> tuple[bool, bool] | None:
    if width != width_of(meta) or position < 0 or position >= span:
        return None
    if count < 1 or index < 0 or index >= count:
        return None
    return index == 0, index == count - 1


def _input(
    held: Held,
    first: bool,
    last: bool,
    token: int | None,
    carry: bytes | None,
    width: int,
    kinds: set[int],
) -> np.ndarray | None:
    meta = held.meta
    if first:
        if token is None or token < 0 or token >= meta["vocab"] or meta["kind"] not in kinds:
            return None
        vector = _embed(held, token)
        return vector if vector.size == meta["hidden"] else None
    if carry is None or len(carry) != width:
        return None
    vector = _load(carry)
    return vector if len(vector) == meta["hidden"] else None


def _take(
    held: Held, cursor: int, count: int, shape: tuple[int, ...] | None = None
) -> tuple[np.ndarray, int]:
    data = held.floats(cursor, count)
    if shape is not None:
        data = data.reshape(shape)
    return data, cursor + count * 2


def _advance(state: bytearray, position: int) -> int:
    used = int.from_bytes(state[:4], "big")
    if position + 1 > used:
        state[:4] = (position + 1).to_bytes(4, "big")
        used = position + 1
    return used


def _block(
    held: Held,
    vector: np.ndarray,
    maps: tuple[np.ndarray, ...],
    layer: int,
    position: int,
    span: int,
) -> np.ndarray:
    meta = held.meta
    wq, wk, wv, wo, rms_attn, rms_ff, w1, w2, w3 = maps
    kv_dim = meta["kv"] * meta["dim"]
    normed = _rms(vector, rms_attn, meta["rms"])
    query = _rope_heads(wq @ normed, meta["heads"], meta["dim"], position, meta["rope"])
    key = _rope_heads(wk @ normed, meta["kv"], meta["dim"], position, meta["rope"])
    _store(held.state, layer, span, kv_dim, position, key, wv @ normed)
    used = _advance(held.state, position)
    attn = _attend(query, held.state, layer, span, kv_dim, meta["heads"], meta["kv"], meta["dim"], used)
    vector = vector + (wo @ attn)
    inner = _rms(vector, rms_ff, meta["rms"])
    return vector + (w2 @ (_silu(w1 @ inner) * (w3 @ inner)))


def _argmax(held: Held, vector: np.ndarray, offset: int) -> int | None:
    hidden = held.meta["hidden"]
    vocab = held.meta["vocab"]
    rms = held.floats(offset, hidden)
    if rms.size != hidden:
        return None
    normed = _rms(vector, rms, held.meta["rms"])
    start = offset + hidden * 2
    best_i = 0
    best_v = -np.inf
    for index in range(0, vocab, HEAD_CHUNK):
        take = min(HEAD_CHUNK, vocab - index)
        block = held.floats(start + index * hidden * 2, take * hidden)
        if block.size != take * hidden:
            return None
        logits = block.reshape(take, hidden) @ normed
        local = int(logits.argmax())
        value = float(logits[local])
        if value > best_v:
            best_v = value
            best_i = index + local
    return best_i


def _embed(held: Held, token: int) -> np.ndarray:
    hidden = held.meta["hidden"]
    return held.floats(HEADER + token * hidden * 2, hidden)


def _maps(held: Held, cursor: int, specs: list[tuple]) -> tuple[tuple[np.ndarray, ...], int]:
    items = []
    for spec in specs:
        data, cursor = _take(held, cursor, spec[0], spec[1] if len(spec) > 1 else None)
        items.append(data)
    return tuple(items), cursor


def _floats(data: bytearray | bytes, offset: int, count: int) -> np.ndarray:
    if count < 1:
        return np.zeros(0, dtype=np.float32)
    return np.frombuffer(data, dtype=">f2", count=count, offset=offset).astype(np.float32)


def _load(data: bytes) -> np.ndarray:
    return _floats(data, 0, len(data) // 2)


def _rms(vector: np.ndarray, weight: np.ndarray, eps: float) -> np.ndarray:
    mean = float(np.mean(vector * vector))
    return weight * vector * (1.0 / math.sqrt(mean + eps))


def _silu(value: np.ndarray) -> np.ndarray:
    held = np.exp(-np.abs(value))
    return np.where(value >= 0.0, value / (1.0 + held), value * held / (1.0 + held))


def _rope_heads(vector: np.ndarray, groups: int, dim: int, position: int, base: float) -> np.ndarray:
    heads = vector.reshape(groups, dim)
    out = np.empty_like(heads)
    index = np.arange(0, dim, 2)
    freq = 1.0 / (base ** (index / dim))
    angle = position * freq
    cosine = np.cos(angle)
    sine = np.sin(angle)
    first = heads[:, 0::2]
    second = heads[:, 1::2] if dim > 1 else np.zeros_like(first)
    out[:, 0::2] = first * cosine - second * sine
    if dim > 1:
        out[:, 1::2] = first * sine + second * cosine
    return out.reshape(-1)


def _store(
    state: bytearray,
    layer: int,
    span: int,
    kv_dim: int,
    position: int,
    key: np.ndarray,
    value: np.ndarray,
) -> None:
    base = 4 + layer * 2 * span * kv_dim * 2
    key_off = base + position * kv_dim * 2
    val_off = base + span * kv_dim * 2 + position * kv_dim * 2
    raw_key = dump(key)
    raw_val = dump(value)
    state[key_off : key_off + len(raw_key)] = raw_key
    state[val_off : val_off + len(raw_val)] = raw_val


def _attend(
    query: np.ndarray,
    state: bytearray,
    layer: int,
    span: int,
    kv_dim: int,
    heads: int,
    kv: int,
    dim: int,
    used: int,
) -> np.ndarray:
    scale = 1.0 / math.sqrt(dim)
    base = 4 + layer * 2 * span * kv_dim * 2
    keys = _floats(state, base, used * kv_dim).reshape(used, kv, dim)
    vals = _floats(state, base + span * kv_dim * 2, used * kv_dim).reshape(used, kv, dim)
    q = query.reshape(heads, dim)
    groups = np.arange(heads) // (heads // kv)
    gathered_k = keys[:, groups, :]
    scores = np.einsum("hd,thd->ht", q, gathered_k) * scale
    shift = scores.max(axis=1, keepdims=True)
    weights = np.exp(scores - shift)
    weights = weights / weights.sum(axis=1, keepdims=True)
    gathered_v = vals[:, groups, :]
    return np.einsum("ht,thd->hd", weights, gathered_v).reshape(-1)


def bank_octets(hidden: int, count: int) -> int:
    return 4 + count * 2 * hidden * 2


def append_bank(path: Path, rows: list[tuple[np.ndarray, np.ndarray]]) -> None:
    meta = inspect_file(path)
    if meta is None:
        raise ValueError("bank")
    hidden = meta["hidden"]
    with path.open("r+b") as handle:
        handle.seek(HEADER)
        raw = handle.read(4)
        count = int.from_bytes(raw, "big") if len(raw) == 4 else 0
        handle.seek(0, 2)
        for key, value in rows:
            handle.write(dump(key))
            handle.write(dump(value))
        count += len(rows)
        handle.seek(44)
        handle.write(bank_octets(hidden, count).to_bytes(8, "big"))
        handle.seek(HEADER)
        handle.write(count.to_bytes(4, "big"))


def _pass(last: bool, vector: np.ndarray) -> tuple[str, bytes] | None:
    return None if last else ("carry", dump(vector))


def apply_model(
    held: Held,
    width: int,
    index: int,
    count: int,
    token: int | None,
    carry: bytes | None,
    position: int,
    span: int,
) -> tuple[str, int | bytes] | None:
    meta = held.meta
    ends = _ends(meta, width, index, count, position, span)
    if ends is None:
        return None
    first, last = ends
    kind = meta["kind"]
    vector = _input(held, first, last, token, carry, width, {KIND_EMBED} if first else {kind})
    if vector is None:
        return None
    if first:
        return _pass(last, vector)
    if kind == KIND_BANK:
        extra = _bank_read(held, vector)
        if held._path is not None:
            append_bank(held._path, [(vector, vector)])
        return _pass(last, vector + extra)
    if kind != KIND_HEAD or not last:
        return None
    if len(held.state) < state_octets(1, span, meta["kv"], meta["dim"]):
        return None
    return _model_token(held, _model_stack(held, vector, position, span))


def _bank_count(held: Held) -> int:
    raw = held.octets(HEADER, 4)
    if len(raw) != 4:
        return 0
    return int.from_bytes(raw, "big")


def _bank_read(held: Held, query: np.ndarray) -> np.ndarray:
    hidden = held.meta["hidden"]
    count = _bank_count(held)
    if count < 1:
        return np.zeros(hidden, dtype=np.float32)
    raw = held.floats(HEADER + 4, count * 2 * hidden)
    if raw.size != count * 2 * hidden:
        return np.zeros(hidden, dtype=np.float32)
    pairs = raw.reshape(count, 2, hidden)
    keys = pairs[:, 0, :]
    vals = pairs[:, 1, :]
    scores = keys @ query * (1.0 / math.sqrt(hidden))
    shift = float(scores.max())
    weights = np.exp(scores - shift)
    total = float(weights.sum())
    if total <= 0.0:
        return np.zeros(hidden, dtype=np.float32)
    return (weights / total) @ vals


def _model_maps(held: Held) -> tuple[np.ndarray, ...] | None:
    hidden = held.meta["hidden"]
    ff = held.meta["ff"]
    hh = hidden * hidden
    maps, _ = _maps(
        held,
        HEADER,
        [
            (hh, (hidden, hidden)),
            (hh, (hidden, hidden)),
            (hh, (hidden, hidden)),
            (hh, (hidden, hidden)),
            (hidden,),
            (hidden,),
            (hidden * ff, (ff, hidden)),
            (ff * hidden, (hidden, ff)),
            (hidden * ff, (ff, hidden)),
        ],
    )
    if any(item.size == 0 for item in maps):
        return None
    return maps


def _model_stack(held: Held, vector: np.ndarray, position: int, span: int) -> np.ndarray:
    maps = _model_maps(held)
    if maps is None:
        return vector
    return _block(held, vector, maps, 0, position, span)


def _model_token(held: Held, vector: np.ndarray) -> tuple[str, int] | None:
    hidden = held.meta["hidden"]
    ff = held.meta["ff"]
    offset = HEADER + (4 * hidden * hidden + 2 * hidden + 3 * hidden * ff) * 2
    out = _argmax(held, vector, offset)
    return None if out is None else ("token", out)
