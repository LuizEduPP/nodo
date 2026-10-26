from __future__ import annotations

import hashlib

PREFIX = b"nodo/1"
VERSION = 1
NOTICE_WAIT = 1
LISTEN = 9400
NAME = "nodo"

DOORS = (
    ("dht.libtorrent.org", 25401),
    ("dht.transmissionbt.com", 6881),
)
ALPHA = 3
K = 8

SLICE_MAGIC = b"nodo/s"
VOCAB_MAGIC = b"nodo/v"
CODE = 1
CODE_MODEL = 2
CODE_GREEDY = 1
CODE_BPE = 2
KIND_COMPLETE = 0
KIND_EMBED = 1
KIND_STACK = 2
KIND_HEAD = 3
KIND_BANK = 4
KINDS = {KIND_COMPLETE, KIND_EMBED, KIND_STACK, KIND_HEAD, KIND_BANK}
HEADER = 52
HEAD_CHUNK = 4096
VOCABULARY = "vocabulary"
CARRY = 1 << 20

HIDDEN = 256
HEADS = 8
KV = 8
DIM = 32
FF = 1024
VOCAB = 256
RMS = 1e-6
ROPE = 10000.0
EOS = 0
SCALE = 0.02

LAYER = (
    ("input_layernorm.weight", "hidden"),
    ("self_attn.q_proj.weight", "hh"),
    ("self_attn.k_proj.weight", "kh"),
    ("self_attn.v_proj.weight", "kh"),
    ("self_attn.o_proj.weight", "hh"),
    ("post_attention_layernorm.weight", "hidden"),
    ("mlp.gate_proj.weight", "fh"),
    ("mlp.down_proj.weight", "hf"),
    ("mlp.up_proj.weight", "fh"),
)

TYPES = (
    "association-open",
    "association-accept",
    "association-close",
    "presence",
    "introduction",
    "convey",
    "offer",
    "offer-withdrawal",
    "capability",
    "composition",
    "session-open",
    "session-progress",
    "session-suspend",
    "session-close",
    "rejection",
    "step-in",
    "step-carry",
    "step-out",
    "role-need",
    "role-carry",
)
TYPE_CODE = {name: index + 1 for index, name in enumerate(TYPES)}
CODE_TYPE = {code: name for name, code in TYPE_CODE.items()}
CONDITIONS = ("accepted", "pause", "leave")
CLASSES = ("cpu", "gpu")
SUSPENSION = ("recomposition-incomplete", "result-incompatible")
REJECTION = (
    "item",
    "signature",
    "version",
    "composition-mismatch",
    "authorization",
    "payload",
    "identifier-missing",
    "budget",
    "association",
    "frame",
)
SIGNED = frozenset(
    {
        "association-open",
        "association-accept",
        "association-close",
        "offer",
        "offer-withdrawal",
        "capability",
        "presence",
        "introduction",
        "convey",
        "session-open",
        "session-progress",
        "session-suspend",
        "session-close",
        "step-in",
        "step-carry",
        "step-out",
        "role-need",
        "role-carry",
    }
)
RECORD_TYPES = (SIGNED - {"association-open", "association-accept"}) | {"composition", "rejection"}
CLEAR_TYPES = frozenset({"presence", "rejection"})

EMPTY = 0
BOXED = 1
PENDING = 2
WAITING = 3
HEARD = 4
REC_NONE = 0
REC_PRESENCE = 1
REC_GAP = 3
REC_REPLAY = 4
REC_UNKNOWN = 5
REC_LEFTOVER = 6
SESSION_STATES = ("none", "open", "suspended", "closed")
SESSION_EVENTS = (
    "session-open",
    "session-open-repeat",
    "step-in",
    "step-in-repeat",
    "step-carry",
    "step-out",
    "step-out-incompatible",
    "session-progress",
    "session-suspend",
    "session-close",
    "opener-loss",
    "peer-loss",
    "not-opener-request",
    "not-holder-result",
)
SESSION_TABLE = {
    ("none", "session-open"): ("open", "accept"),
    ("none", "session-open-repeat"): ("none", "reject"),
    ("none", "step-in"): ("none", "reject"),
    ("none", "step-in-repeat"): ("none", "reject"),
    ("none", "step-carry"): ("none", "reject"),
    ("none", "step-out"): ("none", "reject"),
    ("none", "step-out-incompatible"): ("none", "reject"),
    ("none", "session-progress"): ("none", "discard"),
    ("none", "session-suspend"): ("none", "reject"),
    ("none", "session-close"): ("none", "reject"),
    ("none", "opener-loss"): ("none", "end"),
    ("none", "peer-loss"): ("none", "discard"),
    ("none", "not-opener-request"): ("none", "reject"),
    ("none", "not-holder-result"): ("none", "reject"),
    ("open", "session-open"): ("open", "reject"),
    ("open", "session-open-repeat"): ("open", "reject"),
    ("open", "step-in"): ("open", "accept"),
    ("open", "step-in-repeat"): ("open", "reject"),
    ("open", "step-carry"): ("open", "accept"),
    ("open", "step-out"): ("open", "accept"),
    ("open", "step-out-incompatible"): ("open", "recompose"),
    ("open", "session-progress"): ("open", "accept"),
    ("open", "session-suspend"): ("suspended", "accept"),
    ("open", "session-close"): ("closed", "accept"),
    ("open", "opener-loss"): ("closed", "end"),
    ("open", "peer-loss"): ("open", "recompose"),
    ("open", "not-opener-request"): ("open", "reject"),
    ("open", "not-holder-result"): ("open", "reject"),
    ("suspended", "session-open"): ("open", "accept"),
    ("suspended", "session-open-repeat"): ("open", "accept"),
    ("suspended", "step-in"): ("suspended", "reject"),
    ("suspended", "step-in-repeat"): ("suspended", "reject"),
    ("suspended", "step-carry"): ("suspended", "reject"),
    ("suspended", "step-out"): ("suspended", "reject"),
    ("suspended", "step-out-incompatible"): ("suspended", "reject"),
    ("suspended", "session-progress"): ("suspended", "discard"),
    ("suspended", "session-suspend"): ("suspended", "discard"),
    ("suspended", "session-close"): ("closed", "accept"),
    ("suspended", "opener-loss"): ("closed", "end"),
    ("suspended", "peer-loss"): ("suspended", "discard"),
    ("suspended", "not-opener-request"): ("suspended", "reject"),
    ("suspended", "not-holder-result"): ("suspended", "reject"),
    ("closed", "session-open"): ("closed", "reject"),
    ("closed", "session-open-repeat"): ("closed", "reject"),
    ("closed", "step-in"): ("closed", "reject"),
    ("closed", "step-in-repeat"): ("closed", "reject"),
    ("closed", "step-carry"): ("closed", "reject"),
    ("closed", "step-out"): ("closed", "reject"),
    ("closed", "step-out-incompatible"): ("closed", "reject"),
    ("closed", "session-progress"): ("closed", "discard"),
    ("closed", "session-suspend"): ("closed", "discard"),
    ("closed", "session-close"): ("closed", "discard"),
    ("closed", "opener-loss"): ("closed", "end"),
    ("closed", "peer-loss"): ("closed", "discard"),
    ("closed", "not-opener-request"): ("closed", "reject"),
    ("closed", "not-holder-result"): ("closed", "reject"),
}


class Cause(Exception):
    def __init__(self, cause: str) -> None:
        self.cause = cause


def network() -> bytes:
    return hashlib.sha256(PREFIX).digest()


def infohash() -> bytes:
    return hashlib.sha1(PREFIX).digest()


def uuid_shape(digest: bytes, version: int) -> bytes:
    data = bytearray(digest)
    data[6] = (data[6] & 0x0F) | (version << 4)
    data[8] = (data[8] & 0x3F) | 0x80
    return bytes(data)


def capability() -> bytes:
    return uuid_shape(hashlib.sha256(PREFIX).digest()[:16], 7)


HASH = infohash()
