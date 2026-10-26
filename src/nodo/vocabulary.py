from __future__ import annotations

import unicodedata
from dataclasses import dataclass

from nodo.domain import CODE_BPE, CODE_GREEDY, VOCAB_MAGIC


@dataclass
class Vocabulary:
    code: int
    pieces: list[bytes]
    merges: list[tuple[bytes, bytes]]


def write(vocab: Vocabulary) -> bytes:
    if vocab.code not in {CODE_GREEDY, CODE_BPE} or not vocab.pieces:
        raise ValueError("vocabulary")
    if vocab.code == CODE_GREEDY and vocab.merges:
        raise ValueError("vocabulary")
    body = bytes([vocab.code]) + len(vocab.pieces).to_bytes(4, "big")
    for piece in vocab.pieces:
        body += _piece(piece)
    if vocab.code == CODE_BPE:
        body += len(vocab.merges).to_bytes(4, "big")
        for left, right in vocab.merges:
            body += _piece(left) + _piece(right)
    return VOCAB_MAGIC + body


def read(data: bytes) -> Vocabulary | None:
    if len(data) < 11 or data[:6] != VOCAB_MAGIC:
        return None
    code = data[6]
    if code not in {CODE_GREEDY, CODE_BPE}:
        return None
    count = int.from_bytes(data[7:11], "big")
    if count < 1:
        return None
    offset = 11
    pieces = []
    for _ in range(count):
        piece, offset = _take(data, offset)
        if piece is None:
            return None
        pieces.append(piece)
    merges: list[tuple[bytes, bytes]] = []
    if code == CODE_BPE:
        if offset + 4 > len(data):
            return None
        merge_count = int.from_bytes(data[offset : offset + 4], "big")
        offset += 4
        for _ in range(merge_count):
            left, offset = _take(data, offset)
            right, offset = _take(data, offset)
            if left is None or right is None:
                return None
            merges.append((left, right))
    if offset != len(data):
        return None
    return Vocabulary(code, pieces, merges)


def encode(vocab: Vocabulary, request: bytes) -> list[int] | None:
    if not request:
        return None
    if vocab.code == CODE_GREEDY:
        return _greedy(vocab.pieces, request)
    if vocab.code == CODE_BPE:
        return _bpe(vocab, request)
    return None


def decode(vocab: Vocabulary, tokens: list[int]) -> bytes | None:
    out = bytearray()
    for token in tokens:
        if token < 0 or token >= len(vocab.pieces):
            return None
        out.extend(vocab.pieces[token])
    if vocab.code == CODE_GREEDY:
        return bytes(out)
    try:
        return _from_byte_pieces(out.decode("utf-8"))
    except UnicodeDecodeError:
        return None


def bytes_pieces() -> list[bytes]:
    return [bytes([index]) for index in range(128)]


def bytes_vocab() -> Vocabulary:
    return Vocabulary(CODE_BPE, [_BYTE_TO_CHAR[index].encode("utf-8") for index in range(256)], [])


def greedy(pieces: list[bytes]) -> Vocabulary:
    return Vocabulary(CODE_GREEDY, pieces, [])


def _piece(piece: bytes) -> bytes:
    if not piece:
        raise ValueError("vocabulary")
    piece.decode("utf-8")
    if len(piece) > 0xFFFF:
        raise ValueError("vocabulary")
    return len(piece).to_bytes(2, "big") + piece


def _take(data: bytes, offset: int) -> tuple[bytes | None, int]:
    if offset + 2 > len(data):
        return None, offset
    size = int.from_bytes(data[offset : offset + 2], "big")
    offset += 2
    if size < 1 or offset + size > len(data):
        return None, offset
    piece = data[offset : offset + size]
    try:
        piece.decode("utf-8")
    except UnicodeDecodeError:
        return None, offset
    return piece, offset + size


def _greedy(pieces: list[bytes], request: bytes) -> list[int] | None:
    order = sorted(range(len(pieces)), key=lambda index: len(pieces[index]), reverse=True)
    tokens = []
    offset = 0
    while offset < len(request):
        match = None
        for index in order:
            piece = pieces[index]
            if request.startswith(piece, offset):
                match = index
                offset += len(piece)
                break
        if match is None:
            return None
        tokens.append(match)
    return tokens


def _bpe(vocab: Vocabulary, request: bytes) -> list[int] | None:
    try:
        text = request.decode("utf-8")
    except UnicodeDecodeError:
        return None
    table = {piece: index for index, piece in enumerate(vocab.pieces)}
    rank = {pair: index for index, pair in enumerate(vocab.merges)}
    tokens: list[int] = []
    for part in _pretokens(text):
        symbols = _to_byte_pieces(part.encode("utf-8"))
        while len(symbols) > 1:
            chosen = None
            best = None
            for pair in zip(symbols, symbols[1:]):
                if pair in rank and (best is None or rank[pair] < best):
                    best = rank[pair]
                    chosen = pair
            if chosen is None:
                break
            nxt = []
            index = 0
            joined = chosen[0] + chosen[1]
            while index < len(symbols):
                if index + 1 < len(symbols) and symbols[index] == chosen[0] and symbols[index + 1] == chosen[1]:
                    nxt.append(joined)
                    index += 2
                else:
                    nxt.append(symbols[index])
                    index += 1
            symbols = nxt
        for symbol in symbols:
            ident = table.get(symbol)
            if ident is None:
                return None
            tokens.append(ident)
    return tokens if tokens else None


def _bytes_to_unicode() -> dict[int, str]:
    raw = list(range(ord("!"), ord("~") + 1)) + list(range(ord("¡"), ord("¬") + 1)) + list(range(ord("®"), ord("ÿ") + 1))
    mapped = list(raw)
    extra = 0
    for value in range(256):
        if value not in raw:
            raw.append(value)
            mapped.append(256 + extra)
            extra += 1
    return {byte: chr(code) for byte, code in zip(raw, mapped)}


_BYTE_TO_CHAR = _bytes_to_unicode()
_CHAR_TO_BYTE = {char: byte for byte, char in _BYTE_TO_CHAR.items()}


def _to_byte_pieces(data: bytes) -> list[bytes]:
    return [_BYTE_TO_CHAR[value].encode("utf-8") for value in data]


def _from_byte_pieces(text: str) -> bytes:
    out = bytearray()
    for char in text:
        if char not in _CHAR_TO_BYTE:
            raise UnicodeDecodeError("byte", b"", 0, 1, "piece")
        out.append(_CHAR_TO_BYTE[char])
    return bytes(out)


def _letter(char: str) -> bool:
    return unicodedata.category(char).startswith("L")


def _number(char: str) -> bool:
    return unicodedata.category(char).startswith("N")


def _pretokens(text: str) -> list[str]:
    found: list[str] = []
    index = 0
    length = len(text)
    while index < length:
        take = None
        for matcher in (_contraction, _letters, _digits, _other, _space):
            take = matcher(text, index)
            if take is not None:
                break
        if take is None:
            return found
        found.append(text[index : index + take])
        index += take
    return found


def _contraction(text: str, index: int) -> int | None:
    if text[index] != "'":
        return None
    rest = text[index + 1 : index + 3].lower()
    if rest.startswith(("s", "t", "m", "d")) and (index + 2 >= len(text) or not _letter(text[index + 2])):
        return 2
    if rest in {"re", "ve", "ll"} and (index + 3 >= len(text) or not _letter(text[index + 3])):
        return 3
    return None


def _letters(text: str, index: int) -> int | None:
    start = index
    if text[index] not in "\r\n" and not _letter(text[index]) and not _number(text[index]):
        index += 1
        if index >= len(text) or not _letter(text[index]):
            return None
    elif not _letter(text[index]):
        return None
    while index < len(text) and _letter(text[index]):
        index += 1
    return index - start


def _digits(text: str, index: int) -> int | None:
    if not _number(text[index]):
        return None
    take = 1
    while take < 3 and index + take < len(text) and _number(text[index + take]):
        take += 1
    return take


def _other(text: str, index: int) -> int | None:
    start = index
    if text[index] == " ":
        index += 1
        if index >= len(text):
            return None
    if text[index] in "\r\n\t " or _letter(text[index]) or _number(text[index]):
        return None
    while index < len(text) and text[index] not in "\r\n\t " and not _letter(text[index]) and not _number(text[index]):
        index += 1
    while index < len(text) and text[index] in "\r\n":
        index += 1
    return index - start if index > start else None


def _space(text: str, index: int) -> int | None:
    if text[index] not in "\r\n\t ":
        return None
    start = index
    while index < len(text) and text[index] in "\r\n\t ":
        index += 1
    return index - start
