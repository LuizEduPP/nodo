from __future__ import annotations

import json
import os
import struct
import sys
from pathlib import Path
from typing import Any

import numpy as np

from nodo.measure import host_budget
from nodo.domain import CODE_BPE, KIND_COMPLETE, LAYER, VOCAB_MAGIC
from nodo.model import write_declaration as write_publication
from nodo.slice import (
    embed_octets,
    fit_span,
    header,
    head_octets,
    inspect_file,
    layer_octets,
    reservation_of,
    width_of,
)
from nodo.vocabulary import Vocabulary
from nodo.vocabulary import write as write_vocab


def span_of(config: dict[str, Any]) -> int:
    value = config.get("max_position_embeddings")
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ValueError("span")
    return value


def llama_roots() -> list[Path]:
    extra = os.environ.get("NODO_MODELS")
    if not extra:
        return []
    candidates = [Path(extra)]
    found: list[Path] = []
    seen: set[Path] = set()
    for path in candidates:
        try:
            path = path.resolve()
        except OSError:
            continue
        if path in seen:
            continue
        seen.add(path)
        if llama_source(path):
            found.append(path)
            continue
        if not path.is_dir():
            continue
        for child in sorted(item for item in path.iterdir() if item.is_dir()):
            if child in seen or not llama_source(child):
                continue
            seen.add(child)
            found.append(child)
    return found


def llama_source(path: Path) -> bool:
    if not path.is_dir():
        return False
    config_path = path / "config.json"
    if not config_path.is_file() or not (path / "tokenizer.json").is_file():
        return False
    data = _object(config_path)
    if data is None or data.get("model_type") != "llama":
        return False
    if (path / "model.safetensors.index.json").is_file():
        return True
    return any(path.glob("*.safetensors"))


def publication_of(
    name: str,
    complete: Path,
    vocab: Path,
    ceiling: int,
    budget: int | None = None,
) -> dict[str, Any] | None:
    if not complete.is_file() or not vocab.is_file():
        return None
    try:
        if vocab.read_bytes()[:6] != VOCAB_MAGIC:
            return None
    except OSError:
        return None
    meta = inspect_file(complete)
    if meta is None or meta["kind"] != KIND_COMPLETE:
        return None
    span = ceiling if budget is None else fit_span(meta, budget, ceiling)
    if span is None:
        return None
    reserved = reservation_of(meta, span)
    if reserved is None:
        return None
    return {
        "name": name,
        "width": width_of(meta),
        "bound": span,
        "span": span,
        "roles": [{"name": "complete", "reservation": reserved, "path": str(complete.resolve())}],
        "vocabulary": str(vocab.resolve()),
    }


def read_packed(path: Path, budget: int | None = None) -> dict[str, Any] | None:
    if not path.is_dir():
        return None
    complete = path / "complete"
    meta = inspect_file(complete) if complete.is_file() else None
    if meta is None:
        return None
    raw = path / "declaration"
    if not raw.is_file():
        return None
    data = _object(raw)
    if data is None:
        return None
    ceiling = data.get("span")
    if not isinstance(ceiling, int) or isinstance(ceiling, bool) or ceiling < 1:
        return None
    return publication_of(path.name, complete, path / "vocabulary", ceiling, budget)


def _object(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text())
    except (OSError, TypeError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _config(source: Path) -> dict[str, Any]:
    config = _object(source / "config.json")
    if config is None:
        raise ValueError("model")
    return config


def pack_store(source: Path, dest: Path) -> dict[str, Any]:
    ceiling = span_of(_config(source))
    pack_directory(source, dest, ceiling)
    result = publication_of(source.name, dest / "complete", dest / "vocabulary", ceiling, host_budget())
    if result is None:
        raise ValueError("budget")
    write_publication(dest, result)
    return result


def pack_directory(source: Path, dest: Path, span: int) -> dict[str, Any]:
    config = _config(source)
    if config.get("model_type") != "llama":
        raise ValueError("model")
    hidden = int(config["hidden_size"])
    layers = int(config["num_hidden_layers"])
    heads = int(config["num_attention_heads"])
    kv = int(config["num_key_value_heads"])
    dim = int(config["head_dim"]) if "head_dim" in config else hidden // heads
    ff = int(config["intermediate_size"])
    vocab = int(config["vocab_size"])
    rms = float(config["rms_norm_eps"])
    rope = float(config["rope_theta"])
    if heads * dim != hidden or hidden < 1 or layers < 1:
        raise ValueError("model")
    shapes = {
        "hidden": (hidden,),
        "hh": (hidden, hidden),
        "kh": (kv * dim, hidden),
        "fh": (ff, hidden),
        "hf": (hidden, ff),
    }
    weights = Weights(source)
    size = embed_octets(vocab, hidden) + layers * layer_octets(hidden, kv, dim, ff) + head_octets(vocab, hidden)
    dest.mkdir(parents=True, exist_ok=True)
    complete_path = dest / "complete"
    with complete_path.open("wb") as out:
        out.write(header(KIND_COMPLETE, hidden, vocab, layers, heads, kv, dim, ff, size, rms, rope))
        _write_tensor(out, weights, "model.embed_tokens.weight", (vocab, hidden))
        for index in range(layers):
            prefix = f"model.layers.{index}."
            for name, kind in LAYER:
                _write_tensor(out, weights, prefix + name, shapes[kind])
        _write_tensor(out, weights, "model.norm.weight", (hidden,))
        head_name = "lm_head.weight" if "lm_head.weight" in weights.names else "model.embed_tokens.weight"
        _write_tensor(out, weights, head_name, (vocab, hidden))
    (dest / "vocabulary").write_bytes(write_vocab(_tokenizer(source / "tokenizer.json", vocab)))
    result = publication_of(source.name, complete_path, dest / "vocabulary", span)
    if result is None:
        raise ValueError("model")
    return result


class Weights:
    def __init__(self, source: Path) -> None:
        self.info: dict[str, tuple[Path, int, dict[str, Any]]] = {}
        index = source / "model.safetensors.index.json"
        if index.is_file():
            mapping = json.loads(index.read_text())["weight_map"]
            paths = sorted({source / filename for filename in mapping.values()})
        else:
            paths = sorted(source.glob("*.safetensors"))
        if not paths:
            raise ValueError("model")
        for path in paths:
            with path.open("rb") as handle:
                size = int.from_bytes(handle.read(8), "little")
                header_json = json.loads(handle.read(size))
            base = 8 + size
            for name, meta in header_json.items():
                if name != "__metadata__":
                    self.info[name] = (path, base, meta)

    @property
    def names(self) -> set[str]:
        return set(self.info)

    def tensor(self, name: str) -> tuple[str, tuple[int, ...], bytes]:
        item = self.info.get(name)
        if item is None:
            raise ValueError(name)
        path, base, meta = item
        start, end = meta["data_offsets"]
        with path.open("rb") as handle:
            handle.seek(base + start)
            raw = handle.read(end - start)
        if len(raw) != end - start:
            raise ValueError(name)
        return meta["dtype"], tuple(meta["shape"]), raw


def _write_tensor(out, weights: Weights, name: str, shape: tuple[int, ...]) -> None:
    dtype, found, raw = weights.tensor(name)
    if found != shape:
        raise ValueError(name)
    out.write(_f16be(dtype, raw))


def _f16be(dtype: str, raw: bytes) -> bytes:
    if dtype == "F16":
        return np.frombuffer(raw, dtype="<u2").byteswap().tobytes()
    if dtype == "BF16":
        wide = np.frombuffer(raw, dtype="<u2").astype(np.uint32) << 16
        half = wide.view(np.float32).astype(np.float16)
        return half.view("<u2").byteswap().tobytes()
    if dtype == "F32":
        half = np.frombuffer(raw, dtype="<f4").astype(np.float16)
        return half.view("<u2").byteswap().tobytes()
    raise ValueError(dtype)


def _tokenizer(path: Path, count: int) -> Vocabulary:
    data = json.loads(path.read_text())
    model = data["model"]
    table = dict(model["vocab"])
    for item in data.get("added_tokens", []):
        table[item["content"]] = item["id"]
    pieces = [b""] * count
    for token, ident in table.items():
        if not isinstance(ident, int) or ident < 0 or ident >= count:
            raise ValueError("vocabulary")
        pieces[ident] = token.encode("utf-8")
    if any(not piece for piece in pieces):
        raise ValueError("vocabulary")
    merges = []
    for item in model.get("merges", []):
        if isinstance(item, str):
            left, right = item.split(" ", 1)
        else:
            left, right = item
        merges.append((left.encode("utf-8"), right.encode("utf-8")))
    return Vocabulary(CODE_BPE, pieces, merges)


def write_safetensors(path: Path, tensors: dict[str, tuple[tuple[int, ...], list[float]]]) -> None:
    entries = {}
    blob = bytearray()
    for name, (shape, values) in tensors.items():
        start = len(blob)
        for value in values:
            blob.extend(struct.pack("<f", value))
        entries[name] = {"dtype": "F32", "shape": list(shape), "data_offsets": [start, len(blob)]}
    header_json = json.dumps(entries, separators=(",", ":")).encode("utf-8")
    path.write_bytes(len(header_json).to_bytes(8, "little") + header_json + blob)


def _report(result: dict[str, Any]) -> None:
    sys.stdout.write("width " + str(result["width"]) + "\n")
    for item in result["roles"]:
        sys.stdout.write(item["name"] + " " + str(item["reservation"]) + "\n")


def main() -> int:
    if len(sys.argv) == 2:
        source = Path(sys.argv[1])
        try:
            from nodo.config import publication_root

            result = pack_store(source, publication_root())
        except (KeyError, OSError, TypeError, ValueError) as exc:
            sys.stderr.write(str(exc) + "\n")
            return 1
        _report(result)
        return 0
    if len(sys.argv) < 4:
        sys.stderr.write("usage: python -m nodo.pack SOURCE [DEST SPAN]\n")
        return 2
    source = Path(sys.argv[1])
    dest = Path(sys.argv[2])
    try:
        span = int(sys.argv[3])
        if span < 1:
            raise ValueError
    except ValueError:
        sys.stderr.write("span\n")
        return 2
    try:
        result = pack_directory(source, dest, span)
    except (KeyError, OSError, TypeError, ValueError) as exc:
        sys.stderr.write(str(exc) + "\n")
        return 1
    _report(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
