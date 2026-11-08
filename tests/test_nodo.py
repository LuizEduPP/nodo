from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from nodo.association import (
    AssociationError,
    derive_keys,
    generate_ephemeral,
    open_handshake,
    seal_handshake,
    shared_secret,
)
from nodo.item import ItemError, decode_item, encode_item
from nodo.messages import encode_message
from nodo.record import open_record, seal
from nodo.slice import Held, apply, bank_octets, dump, header, inspect, reservation_of, state_octets
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
    RMS,
    ROPE,
    SCALE,
    VOCAB,
    VERSION,
)
from nodo.vocabulary import bytes_vocab, decode, encode, read, train_bpe, write as write_vocab


class TestItemRoundTrip(unittest.TestCase):
    """Round-trip encode_item/decode_item for all 20 item types."""

    def _round_trip(self, kind: str, fields: dict) -> None:
        message = {"type": kind, "version": 1, **fields}
        encoded = encode_item(message)
        decoded, rest = decode_item(encoded)
        self.assertEqual(decoded["type"], kind)
        self.assertEqual(decoded["version"], 1)
        for key, value in fields.items():
            self.assertEqual(decoded.get(key), value, f"{kind}: {key} mismatch")
        self.assertEqual(len(rest), 0)

    def test_association_open(self):
        self._round_trip("association-open", {
            "participant": bytes(32),
            "eph": bytes(32),
            "box": bytes(32),
        })

    def test_association_accept(self):
        self._round_trip("association-accept", {
            "participant": bytes(32),
            "eph": bytes(32),
            "box": bytes(32),
        })

    def test_association_close(self):
        self._round_trip("association-close", {"participant": bytes(32)})

    def test_presence(self):
        self._round_trip("presence", {"participant": bytes(32), "box": bytes(32)})

    def test_introduction(self):
        self._round_trip("introduction", {"participant": bytes(32), "subject": bytes(32)})

    def test_convey(self):
        self._round_trip("convey", {
            "participant": bytes(32),
            "subject": bytes(32),
            "body": b"nodo/1" + bytes(10),
        })

    def test_offer_withdrawal(self):
        self._round_trip("offer-withdrawal", {"participant": bytes(32)})

    def test_capability(self):
        self._round_trip("capability", {
            "id": bytes(16),
            "participant": bytes(32),
            "name": "nodo",
            "width": 512,
            "bound": 10,
            "span": 10,
            "roles": [],
        })

    def test_composition(self):
        self._round_trip("composition", {
            "declarant": bytes(32),
            "capability": bytes(16),
            "complete": True,
            "commitments": [],
        })

    def test_session_open(self):
        self._round_trip("session-open", {
            "id": bytes(16),
            "participant": bytes(32),
            "declarant": bytes(32),
            "capability": bytes(16),
            "commitments": [],
        })

    def test_session_progress(self):
        self._round_trip("session-progress", {
            "participant": bytes(32),
            "session": bytes(16),
            "sequence": 1,
        })

    def test_session_suspend(self):
        self._round_trip("session-suspend", {
            "participant": bytes(32),
            "session": bytes(16),
            "cause": "recomposition-incomplete",
        })

    def test_session_close(self):
        self._round_trip("session-close", {
            "participant": bytes(32),
            "session": bytes(16),
        })

    def test_rejection(self):
        self._round_trip("rejection", {"cause": "authorization"})

    def test_step_in(self):
        self._round_trip("step-in", {
            "participant": bytes(32),
            "session": bytes(16),
            "commitment": bytes(16),
            "sequence": 1,
            "token": 0,
        })

    def test_step_carry(self):
        self._round_trip("step-carry", {
            "participant": bytes(32),
            "session": bytes(16),
            "commitment": bytes(16),
            "sequence": 1,
            "body": bytes(512),
        })

    def test_step_out(self):
        self._round_trip("step-out", {
            "participant": bytes(32),
            "session": bytes(16),
            "sequence": 1,
            "token": 0,
        })

    def test_role_need(self):
        self._round_trip("role-need", {
            "participant": bytes(32),
            "holder": bytes(32),
            "declarant": bytes(32),
            "capability": bytes(16),
            "role": "embed",
        })

    def test_role_carry(self):
        self._round_trip("role-carry", {
            "participant": bytes(32),
            "holder": bytes(32),
            "declarant": bytes(32),
            "capability": bytes(16),
            "role": "embed",
            "offset": 0,
            "remain": 0,
            "body": bytes(512),
        })

    def test_offer_cpu(self):
        self._round_trip("offer", {
            "participant": bytes(32),
            "condition": "accepted",
            "commitments": [],
            "classes": ["cpu"],
            "ram_host": 16,
            "ram_limit": 8,
        })

    def test_offer_gpu(self):
        self._round_trip("offer", {
            "participant": bytes(32),
            "condition": "accepted",
            "commitments": [],
            "classes": ["gpu"],
            "vram_host": 8,
            "vram_limit": 4,
            "vram_device": "cuda:0",
        })

    def test_invalid_type(self):
        with self.assertRaises(ItemError):
            encode_item({"type": "unknown", "version": 1})

    def test_invalid_version(self):
        with self.assertRaises(ItemError):
            encode_item({"type": "presence", "version": 2})


class TestAEAD(unittest.TestCase):
    """Authenticated Encryption with Associated Data tests."""

    def test_record_seal_open(self):
        key = os.urandom(32)
        seq = 42
        plaintext = b"hello record"
        sealed = seal(key, seq, plaintext)
        self.assertGreaterEqual(len(sealed), 8 + 16)
        opened_seq, opened_text = open_record(key, sealed)
        self.assertEqual(opened_seq, seq)
        self.assertEqual(opened_text, plaintext)

    def test_record_tamper(self):
        key = os.urandom(32)
        seq = 42
        plaintext = b"hello record"
        sealed = seal(key, seq, plaintext)
        tampered = bytearray(sealed)
        tampered[10] ^= 0xFF
        result = open_record(key, bytes(tampered))
        self.assertIsNone(result)

    def test_record_replay(self):
        key = os.urandom(32)
        seq1 = 1
        seq2 = 2
        plaintext1 = b"first"
        plaintext2 = b"second"
        sealed1 = seal(key, seq1, plaintext1)
        sealed2 = seal(key, seq2, plaintext2)
        # Opening seq1 should work
        opened_seq, opened_text = open_record(key, sealed1)
        self.assertEqual(opened_seq, seq1)
        self.assertEqual(opened_text, plaintext1)
        # Opening seq2 should work
        opened_seq, opened_text = open_record(key, sealed2)
        self.assertEqual(opened_seq, seq2)
        self.assertEqual(opened_text, plaintext2)

    def test_handshake_seal_open(self):
        secret, public = generate_ephemeral()
        peer_secret, peer_public = generate_ephemeral()
        signer = Ed25519PrivateKey.generate()
        participant = bytes(32)
        message = {
            "type": "association-open",
            "version": VERSION,
            "participant": participant,
            "eph": public,
            "box": peer_public,
        }
        inner = encode_message(message, signer)
        sealed = seal_handshake(secret, peer_public, participant, inner)
        self.assertGreaterEqual(len(sealed), 32 + 16)
        opened = open_handshake(peer_secret, participant, sealed)
        self.assertEqual(opened, inner)

    def test_handshake_wrong_recipient(self):
        secret, public = generate_ephemeral()
        peer_secret, peer_public = generate_ephemeral()
        other_secret, other_public = generate_ephemeral()
        signer = Ed25519PrivateKey.generate()
        participant = bytes(32)
        message = {
            "type": "association-open",
            "version": VERSION,
            "participant": participant,
            "eph": public,
            "box": peer_public,
        }
        inner = encode_message(message, signer)
        sealed = seal_handshake(secret, peer_public, participant, inner)
        # Opening with the wrong private key should fail
        with self.assertRaises(AssociationError):
            open_handshake(other_secret, participant, sealed)

    def test_derive_keys_deterministic(self):
        secret, public = generate_ephemeral()
        peer_secret, peer_public = generate_ephemeral()
        shared = shared_secret(secret, peer_public)
        k_i1, k_a1 = derive_keys(shared, b"initiator", b"acceptor", public, peer_public)
        k_i2, k_a2 = derive_keys(shared, b"initiator", b"acceptor", public, peer_public)
        self.assertEqual(k_i1, k_i2)
        self.assertEqual(k_a1, k_a2)
        self.assertNotEqual(k_i1, k_a1)


class TestVocabulary(unittest.TestCase):
    """Vocabulary encode/decode and BPE tests."""

    def test_bytes_vocab_round_trip(self):
        vocab = bytes_vocab()
        request = b"hello world"
        tokens = encode(vocab, request)
        self.assertIsNotNone(tokens)
        decoded = decode(vocab, tokens)
        self.assertEqual(decoded, request)

    def test_bpe_vocab_round_trip(self):
        vocab = train_bpe()
        request = b"hello world"
        tokens = encode(vocab, request)
        self.assertIsNotNone(tokens)
        decoded = decode(vocab, tokens)
        self.assertEqual(decoded, request)

    def test_bpe_has_merges(self):
        vocab = train_bpe()
        self.assertGreater(len(vocab.merges), 0)
        self.assertEqual(vocab.code, 2)  # CODE_BPE

    def test_vocab_write_read(self):
        vocab = train_bpe()
        data = write_vocab(vocab) if hasattr(__import__("nodo.vocabulary", fromlist=["write"]), "write") else None
        if data is not None:
            parsed = read(data)
            self.assertIsNotNone(parsed)
            self.assertEqual(parsed.code, vocab.code)
            self.assertEqual(len(parsed.pieces), len(vocab.pieces))
            self.assertEqual(len(parsed.merges), len(vocab.merges))

    def test_encode_empty_request(self):
        vocab = bytes_vocab()
        self.assertIsNone(encode(vocab, b""))

    def test_decode_invalid_token(self):
        vocab = bytes_vocab()
        self.assertIsNone(decode(vocab, [999]))


class TestSlice(unittest.TestCase):
    """Slice apply model tests."""

    def _make_held(self, kind: int, layers: int = 1) -> Held:
        hidden = HIDDEN
        vocab = VOCAB
        heads = HEADS
        kv = KV
        dim = DIM
        ff = FF
        weights_count = (
            4 * hidden * hidden
            + 2 * hidden
            + 3 * hidden * ff
            + hidden
            + vocab * hidden
        )
        import numpy as np
        rng = np.random.default_rng(1)
        values = rng.normal(0.0, 0.02, weights_count).astype(">f2")
        header_bytes = header(
            kind, hidden, vocab, layers, heads, kv, dim, ff, weights_count, RMS, ROPE, CODE_MODEL
        )
        data = header_bytes + values.tobytes()
        meta = inspect(data)
        self.assertIsNotNone(meta)
        state = bytearray(state_octets(layers, 1, kv, dim))
        return Held(meta, state, data)

    def test_embed_apply(self):
        held = self._make_held(KIND_EMBED)
        # index=0, count=3: embed is first, not last -> returns carry
        result = apply(held, HIDDEN * 2, 0, 3, 0, None, 0, 1)
        self.assertIsNotNone(result)
        kind, value = result
        self.assertEqual(kind, "carry")
        self.assertEqual(len(value), HIDDEN * 2)

    def test_head_apply(self):
        held = self._make_held(KIND_HEAD)
        # index=2, count=3: head is last -> returns token
        # Use a dummy carry of the correct width
        carry = bytes(HIDDEN * 2)
        result = apply(held, HIDDEN * 2, 2, 3, 0, carry, 0, 1)
        self.assertIsNotNone(result)
        kind, value = result
        self.assertEqual(kind, "token")

    def test_bank_apply(self):
        held = self._make_held(KIND_BANK)
        # index=1, count=3: bank is middle -> needs carry input
        carry = bytes(HIDDEN * 2)
        result = apply(held, HIDDEN * 2, 1, 3, 0, carry, 0, 1)
        self.assertIsNotNone(result)
        kind, value = result
        self.assertEqual(kind, "carry")

    def test_inspect_valid(self):
        hidden = HIDDEN
        vocab = VOCAB
        weights_count = 100
        header_bytes = header(
            KIND_EMBED, hidden, vocab, 1, HEADS, KV, DIM, FF, weights_count, RMS, ROPE, CODE_MODEL
        )
        import numpy as np
        values = np.zeros(weights_count, dtype=">f2")
        data = header_bytes + values.tobytes()
        meta = inspect(data)
        self.assertIsNotNone(meta)
        self.assertEqual(meta["kind"], KIND_EMBED)
        self.assertEqual(meta["hidden"], hidden)
        self.assertEqual(meta["vocab"], vocab)

    def test_inspect_invalid(self):
        self.assertIsNone(inspect(b""))

    def test_reservation_of(self):
        meta = {
            "layers": 1,
            "kv": KV,
            "dim": DIM,
            "hidden": HIDDEN,
            "heads": HEADS,
            "ff": FF,
        }
        span = 10
        reservation = reservation_of(meta, span)
        expected = 4 + 1 * 2 * span * KV * DIM * 2
        self.assertEqual(reservation, expected)

    def test_reservation_none(self):
        meta = {
            "layers": 1,
            "kv": KV,
            "dim": DIM,
            "hidden": HIDDEN,
            "heads": HEADS,
            "ff": FF,
        }
        self.assertIsNone(reservation_of(meta, 0))


class TestModel(unittest.TestCase):
    """Model create and weight initialization tests."""

    def test_create_uses_real_weights(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            from nodo.model import create, open_part
            result = create(root, bytes(32), budget=8192)
            self.assertIsNotNone(result)
            # open_part creates the embed file with real weights
            embed_result = open_part(root, "embed", bytes(32), budget=8192)
            self.assertIsNotNone(embed_result)
            embed_path = root / "embed"
            self.assertTrue(embed_path.is_file())
            # Weights should not be all zeros
            data = embed_path.read_bytes()
            meta = inspect(data)
            self.assertIsNotNone(meta)
            weights_start = 52
            weights_data = data[weights_start:]
            self.assertNotEqual(weights_data, bytes(len(weights_data)))

    def test_write_weights_deterministic(self):
        from nodo.model import _write_weights
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            path = root / "test.bin"
            _write_weights(path, KIND_EMBED, 1, 100, seed=42)
            data = path.read_bytes()
            meta = inspect(data)
            self.assertIsNotNone(meta)
            # Same seed should produce same weights
            _write_weights(path, KIND_EMBED, 1, 100, seed=42)
            data2 = path.read_bytes()
            self.assertEqual(data, data2)
            # Different seed should produce different weights
            _write_weights(path, KIND_EMBED, 1, 100, seed=43)
            data3 = path.read_bytes()
            self.assertNotEqual(data, data3)


if __name__ == "__main__":
    unittest.main()
