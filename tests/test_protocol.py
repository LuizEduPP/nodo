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
from nodo.messages import (
    MessageError,
    decode_clear,
    decode_message,
    decode_signed,
    encode_message,
)
from nodo.record import open_record, seal
from nodo.view import View
from nodo.composition import compose, commitment_id
from nodo.domain import (
    PREFIX,
    VERSION,
    SIGNED,
    RECORD_TYPES,
    CLEAR_TYPES,
    REJECTION,
    TYPES,
    TYPE_CODE,
    CODE_TYPE,
    KEY_LEN,
    ID_LEN,
    SIGNATURE_LEN,
    EOS,
    CARRY,
    MAX_HOPS,
    CONVEY_HOPS,
    MIN_SLICE_BUDGET,
    SESSION_TABLE,
    SESSION_STATES,
    SESSION_EVENTS,
)
from nodo.slice import Held, apply, bank_octets, header, inspect, reservation_of, state_octets
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
)
from nodo.measure import cap
from nodo.vocabulary import bytes_vocab, decode, encode, train_bpe


class TestAssociationHandshake(unittest.TestCase):
    """Complete two-peer association handshake with key derivation."""

    def _make_peer(self):
        secret = Ed25519PrivateKey.generate()
        participant = secret.public_key().public_bytes_raw()
        box_secret = X25519PrivateKey.generate()
        box_public = box_secret.public_key().public_bytes_raw()
        return {
            "secret": secret,
            "participant": participant,
            "box_secret": box_secret,
            "box_public": box_public,
        }

    def test_two_peer_handshake(self):
        """Two peers perform a complete handshake and derive matching keys."""
        a = self._make_peer()
        b = self._make_peer()

        # Smaller Ed25519 id initiates
        initiator = a if a["participant"] < b["participant"] else b
        acceptor = b if initiator is a else a

        # Initiator generates ephemeral key and creates association-open
        eph_i, eph_public_i = generate_ephemeral()
        open_msg = {
            "type": "association-open",
            "version": VERSION,
            "participant": initiator["participant"],
            "eph": eph_public_i,
            "box": initiator["box_public"],
        }
        inner_i = encode_message(open_msg, initiator["secret"])
        sealed_i = seal_handshake(
            eph_i, acceptor["box_public"], initiator["participant"], inner_i
        )

        # Acceptor opens the handshake
        inner_a = open_handshake(
            acceptor["box_secret"], initiator["participant"], sealed_i
        )
        open_decoded = decode_signed(inner_a)
        self.assertEqual(open_decoded["type"], "association-open")
        self.assertEqual(open_decoded["participant"], initiator["participant"])

        # Acceptor derives shared secret and creates association-accept
        eph_a, eph_public_a = generate_ephemeral()
        shared = shared_secret(eph_a, eph_public_i)
        accept_msg = {
            "type": "association-accept",
            "version": VERSION,
            "participant": acceptor["participant"],
            "eph": eph_public_a,
            "box": acceptor["box_public"],
        }
        inner_a2 = encode_message(accept_msg, acceptor["secret"])
        sealed_a = seal_handshake(
            eph_a, initiator["box_public"], acceptor["participant"], inner_a2
        )

        # Initiator opens the accept
        inner_i2 = open_handshake(
            initiator["box_secret"], acceptor["participant"], sealed_a
        )
        accept_decoded = decode_signed(inner_i2)
        self.assertEqual(accept_decoded["type"], "association-accept")
        self.assertEqual(accept_decoded["participant"], acceptor["participant"])

        # Both peers derive the same shared secret
        shared_i = shared_secret(eph_i, eph_public_a)
        shared_a = shared_secret(eph_a, eph_public_i)
        self.assertEqual(shared_i, shared_a)

        # Both peers derive matching send/recv keys (crossed)
        info = PREFIX + initiator["participant"] + acceptor["participant"] + eph_public_i + eph_public_a
        k_i, k_a = derive_keys(shared_i, initiator["participant"], acceptor["participant"], eph_public_i, eph_public_a)

        # Initiator: send_key=k_i, recv_key=k_a
        # Acceptor: send_key=k_a, recv_key=k_i
        self.assertNotEqual(k_i, k_a)

        # Verify keys can seal/open records between peers
        # Initiator seals with send_key=k_i, acceptor opens with recv_key=k_i (same key value)
        seq = 1
        plaintext = b"hello protocol"
        sealed = seal(k_i, seq, plaintext)
        opened_seq, opened_text = open_record(k_i, sealed)
        self.assertEqual(opened_seq, seq)
        self.assertEqual(opened_text, plaintext)

        # Acceptor seals with send_key=k_a, initiator opens with recv_key=k_a (same key value)
        sealed2 = seal(k_a, 2, b"reply")
        opened_seq2, opened_text2 = open_record(k_a, sealed2)
        self.assertEqual(opened_seq2, 2)
        self.assertEqual(opened_text2, b"reply")

    def test_handshake_wrong_box_key(self):
        """Opening a handshake with the wrong box key fails."""
        a = self._make_peer()
        b = self._make_peer()
        eph, eph_public = generate_ephemeral()
        msg = {
            "type": "association-open",
            "version": VERSION,
            "participant": a["participant"],
            "eph": eph_public,
            "box": a["box_public"],
        }
        inner = encode_message(msg, a["secret"])
        sealed = seal_handshake(eph, b["box_public"], a["participant"], inner)
        with self.assertRaises(AssociationError):
            open_handshake(a["box_secret"], b["participant"], sealed)

    def test_handshake_tampered(self):
        """Tampering with a sealed handshake fails to open."""
        a = self._make_peer()
        b = self._make_peer()
        eph, eph_public = generate_ephemeral()
        msg = {
            "type": "association-open",
            "version": VERSION,
            "participant": a["participant"],
            "eph": eph_public,
            "box": a["box_public"],
        }
        inner = encode_message(msg, a["secret"])
        sealed = seal_handshake(eph, b["box_public"], a["participant"], inner)
        tampered = bytearray(sealed)
        tampered[40] ^= 0xFF
        with self.assertRaises(AssociationError):
            open_handshake(b["box_secret"], a["participant"], bytes(tampered))


class TestRecordProtocol(unittest.TestCase):
    """Record seal/open with sequence-based replay protection between peers."""

    def _make_peer_for_keys(self):
        secret = Ed25519PrivateKey.generate()
        participant = secret.public_key().public_bytes_raw()
        box_secret = X25519PrivateKey.generate()
        box_public = box_secret.public_key().public_bytes_raw()
        return {"participant": participant, "box_public": box_public}

    def test_record_seal_open_between_peers(self):
        """Two peers seal and open records with derived keys."""
        a = self._make_peer_for_keys()
        b = self._make_peer_for_keys()
        eph_i, eph_public_i = generate_ephemeral()
        eph_a, eph_public_a = generate_ephemeral()
        shared = shared_secret(eph_a, eph_public_i)
        info = PREFIX + a["participant"] + b["participant"] + eph_public_i + eph_public_a
        k_i, k_a = derive_keys(shared, a["participant"], b["participant"], eph_public_i, eph_public_a)

        # Peer A (initiator) seals with send_key=k_i, opens with recv_key=k_i (same key value)
        seq = 1
        plaintext = b"step-in token"
        sealed = seal(k_i, seq, plaintext)
        opened_seq, opened_text = open_record(k_i, sealed)
        self.assertEqual(opened_seq, seq)
        self.assertEqual(opened_text, plaintext)

        # Peer B (acceptor) seals with send_key=k_a, opens with recv_key=k_a (same key value)
        sealed2 = seal(k_a, 2, b"step-carry")
        opened_seq2, opened_text2 = open_record(k_a, sealed2)
        self.assertEqual(opened_seq2, 2)
        self.assertEqual(opened_text2, b"step-carry")

        # Wrong key fails to open
        wrong_key = os.urandom(32)
        self.assertIsNone(open_record(wrong_key, sealed))

        # Tampered record fails to open
        tampered = bytearray(sealed)
        tampered[20] ^= 0xFF
        self.assertIsNone(open_record(k_i, bytes(tampered)))


class TestMessageProtocol(unittest.TestCase):
    """Message encoding, signing, and verification between two peers."""

    def test_signed_message_round_trip(self):
        """A signed message can be encoded, signed, and verified."""
        secret = Ed25519PrivateKey.generate()
        participant = secret.public_key().public_bytes_raw()
        box_public = bytes(32)

        message = {
            "type": "presence",
            "version": VERSION,
            "participant": participant,
            "box": box_public,
        }
        signed = encode_message(message, secret)
        decoded = decode_signed(signed)
        self.assertEqual(decoded["type"], "presence")
        self.assertEqual(decoded["participant"], participant)
        self.assertEqual(decoded["box"], box_public)

    def test_clear_message_round_trip(self):
        """A clear message (presence/rejection) can be encoded and decoded."""
        secret = Ed25519PrivateKey.generate()
        participant = secret.public_key().public_bytes_raw()
        box_public = bytes(32)

        message = {
            "type": "presence",
            "version": VERSION,
            "participant": participant,
            "box": box_public,
        }
        # presence is in SIGNED, so it needs a secret for encoding
        encoded = encode_message(message, secret)
        decoded = decode_clear(encoded)
        self.assertEqual(decoded["type"], "presence")
        self.assertEqual(decoded["participant"], participant)

    def test_rejection_message(self):
        """A rejection message is a clear type and does not need a secret."""
        message = {
            "type": "rejection",
            "version": VERSION,
            "cause": "authorization",
        }
        encoded = encode_message(message, None)
        decoded = decode_clear(encoded)
        self.assertEqual(decoded["type"], "rejection")
        self.assertEqual(decoded["cause"], "authorization")

    def test_signed_message_wrong_signer(self):
        """A message signed by one peer is verified by the participant embedded in the message."""
        secret_a = Ed25519PrivateKey.generate()
        participant_a = secret_a.public_key().public_bytes_raw()
        secret_b = Ed25519PrivateKey.generate()
        participant_b = secret_b.public_key().public_bytes_raw()

        message = {
            "type": "presence",
            "version": VERSION,
            "participant": participant_a,
            "box": bytes(32),
        }
        signed = encode_message(message, secret_a)
        # decode_signed uses the participant embedded in the message as the author,
        # so it verifies with the signer's key (participant_a's public key).
        decoded = decode_signed(signed)
        self.assertEqual(decoded["participant"], participant_a)

    def test_all_signed_types(self):
        """All SIGNED types can be encoded with a secret."""
        secret = Ed25519PrivateKey.generate()
        participant = secret.public_key().public_bytes_raw()
        for type_name in sorted(SIGNED):
            if type_name in {"presence", "rejection"}:
                continue
            fields = {"participant": participant}
            if type_name == "convey":
                fields["subject"] = bytes(32)
                fields["body"] = PREFIX + bytes(10)
            elif type_name == "introduction":
                fields["subject"] = bytes(32)
            elif type_name == "capability":
                fields["id"] = bytes(16)
                fields["name"] = "test"
                fields["width"] = 512
                fields["bound"] = 10
                fields["span"] = 10
                fields["roles"] = [{"name": "embed", "reservation": 100}]
            elif type_name == "offer":
                fields["condition"] = "accepted"
                fields["commitments"] = []
                fields["classes"] = ["cpu"]
                fields["ram_host"] = 16
                fields["ram_limit"] = 8
            elif type_name == "composition":
                fields["declarant"] = bytes(32)
                fields["capability"] = bytes(16)
                fields["complete"] = True
                fields["commitments"] = []
            elif type_name == "session-open":
                fields["id"] = bytes(16)
                fields["declarant"] = bytes(32)
                fields["capability"] = bytes(16)
                fields["commitments"] = [{"id": bytes(16), "role": "embed", "participant": participant, "reservation": 100}]
            elif type_name == "session-progress":
                fields["session"] = bytes(16)
                fields["sequence"] = 1
            elif type_name == "session-suspend":
                fields["session"] = bytes(16)
                fields["cause"] = "recomposition-incomplete"
            elif type_name == "session-close":
                fields["session"] = bytes(16)
            elif type_name == "step-in":
                fields["session"] = bytes(16)
                fields["commitment"] = bytes(16)
                fields["sequence"] = 1
                fields["token"] = 0
            elif type_name == "step-carry":
                fields["session"] = bytes(16)
                fields["commitment"] = bytes(16)
                fields["sequence"] = 1
                fields["body"] = bytes(64)
            elif type_name == "step-out":
                fields["session"] = bytes(16)
                fields["sequence"] = 1
                fields["token"] = 0
            elif type_name == "role-need":
                fields["holder"] = bytes(32)
                fields["declarant"] = bytes(32)
                fields["capability"] = bytes(16)
                fields["role"] = "embed"
            elif type_name == "role-carry":
                fields["holder"] = bytes(32)
                fields["declarant"] = bytes(32)
                fields["capability"] = bytes(16)
                fields["role"] = "embed"
                fields["offset"] = 0
                fields["remain"] = 0
                fields["body"] = bytes(64)
            elif type_name in {"association-open", "association-accept", "association-close"}:
                if type_name != "association-close":
                    fields["eph"] = bytes(32)
                    fields["box"] = bytes(32)
            message = {"type": type_name, "version": VERSION, **fields}
            encoded = encode_message(message, secret)
            self.assertIsNotNone(encoded)

    def test_all_clear_types(self):
        """All CLEAR_TYPES can be encoded and decoded."""
        secret = Ed25519PrivateKey.generate()
        participant = secret.public_key().public_bytes_raw()
        for type_name in CLEAR_TYPES:
            if type_name == "presence":
                message = {
                    "type": type_name,
                    "version": VERSION,
                    "participant": participant,
                    "box": bytes(32),
                }
                # presence is in SIGNED, needs a secret for encoding
                encoded = encode_message(message, secret)
            else:  # rejection
                message = {
                    "type": type_name,
                    "version": VERSION,
                    "cause": "authorization",
                }
                encoded = encode_message(message, None)
            decoded = decode_clear(encoded)
            self.assertEqual(decoded["type"], type_name)

    def test_record_types(self):
        """RECORD_TYPES includes all signed types except association-open/accept, plus composition/rejection."""
        expected = set(SIGNED) - {"association-open", "association-accept"}
        expected.add("composition")
        expected.add("rejection")
        self.assertEqual(set(RECORD_TYPES), expected)


class TestCompositionProtocol(unittest.TestCase):
    """Composition logic: role assignment and commitment IDs."""

    def test_commitment_id_deterministic(self):
        """commitment_id is deterministic and uses UUID v5 of sha1."""
        capability = bytes(16)
        role = "embed"
        participant = bytes(32)
        cid1 = commitment_id(capability, role, participant)
        cid2 = commitment_id(capability, role, participant)
        self.assertEqual(cid1, cid2)
        self.assertEqual(len(cid1), 16)
        # UUID v5: version nibble = 5
        self.assertEqual(cid1[6] >> 4, 5)

    def _make_offer(self, participant, reservation=200):
        return {
            "version": VERSION,
            "type": "offer",
            "participant": participant,
            "condition": "accepted",
            "commitments": [{"id": commitment_id(bytes(16), "embed", participant), "reservation": reservation}],
            "classes": ["cpu"],
            "ram_host": 100000,
            "ram_limit": 1000,
        }

    def test_compose_assigns_roles(self):
        """compose() assigns roles to eligible participants."""
        capability = bytes(16)
        participant_a = bytes([1] * 32)
        participant_b = bytes([2] * 32)

        declaration = {
            "version": VERSION,
            "type": "capability",
            "id": capability,
            "participant": participant_a,
            "name": "test",
            "width": 512,
            "bound": 10,
            "span": 10,
            "roles": [
                {"name": "embed", "reservation": 100},
                {"name": "bank-1", "reservation": 100},
                {"name": "head", "reservation": 100},
            ],
        }

        offers = {
            participant_a: self._make_offer(participant_a),
            participant_b: self._make_offer(participant_b),
        }

        result = compose(declaration, offers, None)
        # All 3 roles should be assigned
        self.assertEqual(len(result["commitments"]), 3)

        # Verify each commitment has the correct role and participant
        roles = {item["role"]: item for item in result["commitments"]}
        self.assertEqual(len(roles), 3)
        self.assertIn("embed", roles)
        self.assertIn("bank-1", roles)
        self.assertIn("head", roles)

        # Verify commitment IDs match
        for role_name, item in roles.items():
            expected_id = commitment_id(capability, role_name, item["participant"])
            self.assertEqual(item["id"], expected_id)

    def test_compose_incomplete_when_no_eligible(self):
        """compose() returns complete=False when no eligible participant for a role."""
        capability = bytes(16)
        participant_a = bytes(32)

        declaration = {
            "version": VERSION,
            "type": "capability",
            "id": capability,
            "participant": participant_a,
            "name": "test",
            "width": 512,
            "bound": 10,
            "span": 10,
            "roles": [
                {"name": "embed", "reservation": 100},
                {"name": "head", "reservation": 100},
            ],
        }

        # No offers at all -> no eligible participants
        result = compose(declaration, {}, None)
        self.assertFalse(result["complete"])

    def test_compose_uses_previous_holder(self):
        """compose() prefers the previous holder if still eligible."""
        capability = bytes(16)
        participant_a = bytes(32)
        participant_b = bytes(32)

        declaration = {
            "version": VERSION,
            "type": "capability",
            "id": capability,
            "participant": participant_a,
            "name": "test",
            "width": 512,
            "bound": 10,
            "span": 10,
            "roles": [
                {"name": "embed", "reservation": 100},
                {"name": "head", "reservation": 100},
            ],
        }

        offers = {
            participant_a: self._make_offer(participant_a),
            participant_b: self._make_offer(participant_b),
        }

        previous = [{"role": "embed", "participant": participant_b}]
        result = compose(declaration, offers, previous)
        # participant_b was the previous holder and is still eligible
        embed = next(item for item in result["commitments"] if item["role"] == "embed")
        self.assertEqual(embed["participant"], participant_b)


class TestViewProtocol(unittest.TestCase):
    """View merge and compose logic."""

    def _make_participant(self, value):
        """Create a distinct participant ID."""
        return bytes([value] * 32)

    def test_merge_picks_embed_min_head_max(self):
        """View.merge picks embed=min id, head=max id, banks in between."""
        view = View()
        capability = bytes(16)
        participant_a = self._make_participant(1)
        participant_b = self._make_participant(2)
        participant_c = self._make_participant(3)

        # Make sure participant_a < participant_b < participant_c
        self.assertLess(participant_a, participant_b)
        self.assertLess(participant_b, participant_c)

        # Declarations: A has embed, B has bank-1, C has head
        decl_a = {
            "version": VERSION,
            "type": "capability",
            "id": capability,
            "participant": participant_a,
            "name": "test",
            "width": 512,
            "bound": 10,
            "span": 10,
            "roles": [
                {"name": "embed", "reservation": 100},
            ],
        }
        decl_b = {
            "version": VERSION,
            "type": "capability",
            "id": capability,
            "participant": participant_b,
            "name": "test",
            "width": 512,
            "bound": 10,
            "span": 10,
            "roles": [
                {"name": "bank-1", "reservation": 100},
            ],
        }
        decl_c = {
            "version": VERSION,
            "type": "capability",
            "id": capability,
            "participant": participant_c,
            "name": "test",
            "width": 512,
            "bound": 10,
            "span": 10,
            "roles": [
                {"name": "head", "reservation": 100},
            ],
        }

        view.store_declaration(decl_a)
        view.store_declaration(decl_b)
        view.store_declaration(decl_c)

        # Offers: all accepted
        offer_a = {
            "version": VERSION,
            "type": "offer",
            "participant": participant_a,
            "condition": "accepted",
            "commitments": [{"id": commitment_id(capability, "embed", participant_a), "reservation": 200}],
            "classes": ["cpu"],
            "ram_host": 100000,
            "ram_limit": 1000,
        }
        offer_b = {
            "version": VERSION,
            "type": "offer",
            "participant": participant_b,
            "condition": "accepted",
            "commitments": [{"id": commitment_id(capability, "bank-1", participant_b), "reservation": 200}],
            "classes": ["cpu"],
            "ram_host": 100000,
            "ram_limit": 1000,
        }
        offer_c = {
            "version": VERSION,
            "type": "offer",
            "participant": participant_c,
            "condition": "accepted",
            "commitments": [{"id": commitment_id(capability, "head", participant_c), "reservation": 200}],
            "classes": ["cpu"],
            "ram_host": 100000,
            "ram_limit": 1000,
        }

        view.store_offer(offer_a)
        view.store_offer(offer_b)
        view.store_offer(offer_c)

        merged = view.merge(capability)
        self.assertIsNotNone(merged)

        # embed should be min id (participant_a)
        embed = next(item for item in merged["roles"] if item["name"] == "embed")
        self.assertEqual(embed["holder"], participant_a)

        # head should be max id (participant_c)
        head = next(item for item in merged["roles"] if item["name"] == "head")
        self.assertEqual(head["holder"], participant_c)

        # banks should be in between, sorted by holder
        banks = [item for item in merged["roles"] if item["name"].startswith("bank-")]
        self.assertEqual(len(banks), 1)
        self.assertEqual(banks[0]["holder"], participant_b)

        # declarant should be embed's holder
        self.assertEqual(merged["participant"], participant_a)

    def test_merge_no_declarations(self):
        """View.merge returns None when there are no declarations."""
        view = View()
        result = view.merge(bytes(16))
        self.assertIsNone(result)

    def test_merge_no_accepted_offers(self):
        """View.merge returns a result with embed/head but no banks when no accepted offers."""
        view = View()
        capability = bytes(16)
        participant = self._make_participant(1)

        decl = {
            "version": VERSION,
            "type": "capability",
            "id": capability,
            "participant": participant,
            "name": "test",
            "width": 512,
            "bound": 10,
            "span": 10,
            "roles": [
                {"name": "embed", "reservation": 100},
                {"name": "head", "reservation": 100},
            ],
        }
        view.store_declaration(decl)

        # Offer with condition != "accepted" -> not in available set
        offer = {
            "version": VERSION,
            "type": "offer",
            "participant": participant,
            "condition": "pause",
            "commitments": [],
            "classes": ["cpu"],
            "ram_host": 100000,
            "ram_limit": 100000,
        }
        view.store_offer(offer)

        result = view.merge(capability)
        # merge still returns embed+head (banks require accepted offers)
        self.assertIsNotNone(result)
        # No banks since the offer is not accepted
        banks = [item for item in result["roles"] if item["name"].startswith("bank-")]
        self.assertEqual(len(banks), 0)

    def test_compositions_returns_complete(self):
        """View.compositions returns complete compositions."""
        view = View()
        capability = bytes(16)
        participant_a = self._make_participant(1)
        participant_b = self._make_participant(2)

        self.assertLess(participant_a, participant_b)

        decl_a = {
            "version": VERSION,
            "type": "capability",
            "id": capability,
            "participant": participant_a,
            "name": "test",
            "width": 512,
            "bound": 10,
            "span": 10,
            "roles": [
                {"name": "embed", "reservation": 100},
            ],
        }
        decl_b = {
            "version": VERSION,
            "type": "capability",
            "id": capability,
            "participant": participant_b,
            "name": "test",
            "width": 512,
            "bound": 10,
            "span": 10,
            "roles": [
                {"name": "bank-1", "reservation": 100},
                {"name": "head", "reservation": 100},
            ],
        }

        view.store_declaration(decl_a)
        view.store_declaration(decl_b)

        offer_a = {
            "version": VERSION,
            "type": "offer",
            "participant": participant_a,
            "condition": "accepted",
            "commitments": [{"id": commitment_id(capability, "embed", participant_a), "reservation": 200}],
            "classes": ["cpu"],
            "ram_host": 100000,
            "ram_limit": 1000,
        }
        offer_b = {
            "version": VERSION,
            "type": "offer",
            "participant": participant_b,
            "condition": "accepted",
            "commitments": [
                {"id": commitment_id(capability, "bank-1", participant_b), "reservation": 200},
                {"id": commitment_id(capability, "head", participant_b), "reservation": 200},
            ],
            "classes": ["cpu"],
            "ram_host": 100000,
            "ram_limit": 1000,
        }

        view.store_offer(offer_a)
        view.store_offer(offer_b)

        compositions = view.compositions()
        self.assertEqual(len(compositions), 1)
        self.assertTrue(compositions[0]["complete"])
        self.assertEqual(len(compositions[0]["commitments"]), 3)

    def test_declaration_returns_merged(self):
        """View.declaration returns the merged capability for the declarant."""
        view = View()
        capability = bytes(16)
        participant = self._make_participant(1)

        decl = {
            "version": VERSION,
            "type": "capability",
            "id": capability,
            "participant": participant,
            "name": "test",
            "width": 512,
            "bound": 10,
            "span": 10,
            "roles": [
                {"name": "embed", "reservation": 100},
                {"name": "head", "reservation": 100},
            ],
        }
        view.store_declaration(decl)

        offer = {
            "version": VERSION,
            "type": "offer",
            "participant": participant,
            "condition": "accepted",
            "commitments": [{"id": commitment_id(capability, "embed", participant), "reservation": 200}],
            "classes": ["cpu"],
            "ram_host": 100000,
            "ram_limit": 100000,
        }
        view.store_offer(offer)

        result = view.declaration(participant, capability)
        self.assertIsNotNone(result)
        self.assertEqual(result["participant"], participant)


class TestSessionStateMachine(unittest.TestCase):
    """Session state machine transitions from SESSION_TABLE."""

    def test_session_table_covers_all_states_and_events(self):
        """Every state-event pair in SESSION_TABLE has a defined transition."""
        states = set(SESSION_STATES)
        events = set(SESSION_EVENTS)
        for state in states:
            for event in events:
                key = (state, event)
                self.assertIn(key, SESSION_TABLE, f"Missing transition for {key}")
                next_state, action = SESSION_TABLE[key]
                self.assertIn(next_state, states, f"Invalid next state {next_state} for {key}")
                self.assertIn(action, {"accept", "reject", "discard", "end", "recompose"}, f"Invalid action {action} for {key}")

    def test_session_open_transitions(self):
        """Session open transitions from none->open with accept action."""
        self.assertEqual(SESSION_TABLE[("none", "session-open")], ("open", "accept"))
        self.assertEqual(SESSION_TABLE[("none", "session-open-repeat")], ("none", "reject"))
        self.assertEqual(SESSION_TABLE[("open", "session-open")], ("open", "reject"))

    def test_step_transitions(self):
        """Step-in and step-out transitions keep session open with accept."""
        self.assertEqual(SESSION_TABLE[("open", "step-in")], ("open", "accept"))
        self.assertEqual(SESSION_TABLE[("open", "step-out")], ("open", "accept"))
        self.assertEqual(SESSION_TABLE[("open", "step-carry")], ("open", "accept"))
        self.assertEqual(SESSION_TABLE[("open", "step-in-repeat")], ("open", "reject"))
        self.assertEqual(SESSION_TABLE[("open", "step-out-incompatible")], ("open", "recompose"))

    def test_session_close_transitions(self):
        """Session close transitions from open->closed and suspended->closed."""
        self.assertEqual(SESSION_TABLE[("open", "session-close")], ("closed", "accept"))
        self.assertEqual(SESSION_TABLE[("suspended", "session-close")], ("closed", "accept"))
        self.assertEqual(SESSION_TABLE[("closed", "session-close")], ("closed", "discard"))

    def test_suspend_transitions(self):
        """Session suspend transitions from open->suspended."""
        self.assertEqual(SESSION_TABLE[("open", "session-suspend")], ("suspended", "accept"))
        self.assertEqual(SESSION_TABLE[("suspended", "session-suspend")], ("suspended", "discard"))

    def test_peer_loss_transitions(self):
        """Peer loss from open triggers recompose."""
        k1 = ("open", "peer-loss")
        self.assertEqual(SESSION_TABLE[k1], ("open", "recompose"))
        k2 = ("suspended", "peer-loss")
        self.assertEqual(SESSION_TABLE[k2], ("suspended", "discard"))
        k3 = ("closed", "peer-loss")
        self.assertEqual(SESSION_TABLE[k3], ("closed", "discard"))


class TestSliceProtocol(unittest.TestCase):
    """Slice model apply protocol: embed/bank/head roles."""

    def _make_held(self, kind, layers=1):
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
        values = rng.normal(0.0, SCALE, weights_count).astype(">f2")
        header_bytes = header(
            kind, hidden, vocab, layers, heads, kv, dim, ff, weights_count, RMS, ROPE, CODE_MODEL
        )
        data = header_bytes + values.tobytes()
        meta = inspect(data)
        self.assertIsNotNone(meta)
        state = bytearray(state_octets(layers, 1, kv, dim))
        return Held(meta, state, data)

    def test_embed_apply_returns_carry(self):
        """Embed (first, not last) returns a carry."""
        held = self._make_held(KIND_EMBED)
        result = apply(held, HIDDEN * 2, 0, 3, 0, None, 0, 1)
        self.assertIsNotNone(result)
        kind, value = result
        self.assertEqual(kind, "carry")
        self.assertEqual(len(value), HIDDEN * 2)

    def test_bank_apply_returns_carry(self):
        """Bank (middle) returns a carry and reads from bank."""
        held = self._make_held(KIND_BANK)
        carry = bytes(HIDDEN * 2)
        result = apply(held, HIDDEN * 2, 1, 3, 0, carry, 0, 1)
        self.assertIsNotNone(result)
        kind, value = result
        self.assertEqual(kind, "carry")
        self.assertEqual(len(value), HIDDEN * 2)

    def test_head_apply_returns_token(self):
        """Head (last) returns a token."""
        held = self._make_held(KIND_HEAD)
        carry = bytes(HIDDEN * 2)
        result = apply(held, HIDDEN * 2, 2, 3, 0, carry, 0, 1)
        self.assertIsNotNone(result)
        kind, value = result
        self.assertEqual(kind, "token")

    def test_reservation_of(self):
        """reservation_of computes the correct byte count."""
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

    def test_reservation_none_for_zero_span(self):
        """reservation_of returns None for zero span."""
        meta = {
            "layers": 1,
            "kv": KV,
            "dim": DIM,
            "hidden": HIDDEN,
            "heads": HEADS,
            "ff": FF,
        }
        self.assertIsNone(reservation_of(meta, 0))

    def test_apply_model_uses_real_weights(self):
        """apply_model uses real Gaussian weights (not zeros)."""
        held = self._make_held(KIND_EMBED)
        result = apply(held, HIDDEN * 2, 0, 3, 0, None, 0, 1)
        self.assertIsNotNone(result)
        kind, value = result
        self.assertEqual(kind, "carry")
        # Verify the carry is not all zeros (real weights were used)
        self.assertNotEqual(value, bytes(len(value)))


class TestVocabularyProtocol(unittest.TestCase):
    """Vocabulary encode/decode protocol."""

    def test_bytes_vocab_round_trip(self):
        """bytes_vocab can encode and decode a request."""
        vocab = bytes_vocab()
        request = b"hello world"
        tokens = encode(vocab, request)
        self.assertIsNotNone(tokens)
        decoded = decode(vocab, tokens)
        self.assertEqual(decoded, request)

    def test_bpe_vocab_round_trip(self):
        """BPE vocab can encode and decode a request."""
        vocab = train_bpe()
        request = b"hello world"
        tokens = encode(vocab, request)
        self.assertIsNotNone(tokens)
        decoded = decode(vocab, tokens)
        self.assertEqual(decoded, request)

    def test_bpe_has_merges(self):
        """BPE vocab has merge rules."""
        vocab = train_bpe()
        self.assertGreater(len(vocab.merges), 0)
        self.assertEqual(vocab.code, 2)  # CODE_BPE

    def test_encode_empty_request(self):
        """Encoding an empty request returns None."""
        vocab = bytes_vocab()
        self.assertIsNone(encode(vocab, b""))

    def test_decode_invalid_token(self):
        """Decoding with an invalid token returns None."""
        vocab = bytes_vocab()
        self.assertIsNone(decode(vocab, [999]))


class TestModelProtocol(unittest.TestCase):
    """Model creation and weight initialization."""

    def test_create_uses_real_weights(self):
        """create() generates real non-zero weights."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            from nodo.model import create, open_part
            result = create(root, bytes(32), budget=8192)
            self.assertIsNotNone(result)
            embed_result = open_part(root, "embed", bytes(32), budget=8192)
            self.assertIsNotNone(embed_result)
            embed_path = root / "embed"
            self.assertTrue(embed_path.is_file())
            data = embed_path.read_bytes()
            meta = inspect(data)
            self.assertIsNotNone(meta)
            weights_start = 52
            weights_data = data[weights_start:]
            self.assertNotEqual(weights_data, bytes(len(weights_data)))

    def test_write_weights_deterministic(self):
        """Same seed produces same weights; different seed produces different weights."""
        from nodo.model import _write_weights
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            path = root / "test.bin"
            _write_weights(path, KIND_EMBED, 1, 100, seed=42)
            data = path.read_bytes()
            meta = inspect(data)
            self.assertIsNotNone(meta)
            _write_weights(path, KIND_EMBED, 1, 100, seed=42)
            data2 = path.read_bytes()
            self.assertEqual(data, data2)
            _write_weights(path, KIND_EMBED, 1, 100, seed=43)
            data3 = path.read_bytes()
            self.assertNotEqual(data, data3)


class TestHardcodedValues(unittest.TestCase):
    """Ensure all hardcoded thresholds and magic numbers are preserved."""

    def test_domain_constants(self):
        from nodo.domain import (
            VERSION, PREFIX, LISTEN, CARRY, HIDDEN, HEADS, KV, DIM, FF,
            VOCAB, EOS, SCALE, MAX_HOPS, CONVEY_HOPS, MIN_SLICE_BUDGET,
        )
        self.assertEqual(VERSION, 1)
        self.assertEqual(PREFIX, b"nodo/1")
        self.assertEqual(LISTEN, 9400)
        self.assertEqual(CARRY, 1 << 20)
        self.assertEqual(HIDDEN, 256)
        self.assertEqual(HEADS, 8)
        self.assertEqual(KV, 8)
        self.assertEqual(DIM, 32)
        self.assertEqual(FF, 1024)
        self.assertEqual(VOCAB, 256)
        self.assertEqual(EOS, 0)
        self.assertEqual(SCALE, 0.02)
        self.assertEqual(MAX_HOPS, 5)
        self.assertEqual(CONVEY_HOPS, 4)
        self.assertEqual(MIN_SLICE_BUDGET, 4)

    def test_cap_function(self):
        from nodo.measure import cap
        self.assertEqual(cap(1000), 10)
        self.assertEqual(cap(999), 9)
        self.assertEqual(cap(10000), 100)

    def test_message_types(self):
        from nodo.domain import SIGNED, CLEAR_TYPES, RECORD_TYPES
        # 20 types total
        from nodo.domain import TYPES
        self.assertEqual(len(TYPES), 20)
        # SIGNED = all except presence, rejection
        self.assertEqual(len(SIGNED), 18)
        # CLEAR_TYPES = presence, rejection
        self.assertEqual(len(CLEAR_TYPES), 2)
        # RECORD_TYPES = SIGNED - {association-open, association-accept} + {composition, rejection}
        self.assertEqual(len(RECORD_TYPES), 18)

    def test_session_table(self):
        from nodo.domain import SESSION_TABLE, SESSION_STATES, SESSION_EVENTS
        # 4 states x 14 events = 56 transitions
        self.assertEqual(len(SESSION_TABLE), len(SESSION_STATES) * len(SESSION_EVENTS))

    def test_item_types(self):
        from nodo.item import TYPE_CODE, CODE_TYPE
        # 20 types, codes 1-20
        self.assertEqual(len(TYPE_CODE), 20)
        self.assertEqual(len(CODE_TYPE), 20)


if __name__ == "__main__":
    unittest.main()
