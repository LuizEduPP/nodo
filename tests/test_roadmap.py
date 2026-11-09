from __future__ import annotations

import hashlib
import os
import socket
import tempfile
import uuid
from pathlib import Path
from unittest import TestCase

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from nodo.association import (
    generate_ephemeral,
    open_handshake,
    seal_handshake,
    shared_secret,
    derive_keys,
)
from nodo.box import box_public, load_box
from nodo.config import join
from nodo.domain import (
    KEY_LEN,
    ID_LEN,
    SIGNATURE_LEN,
    LISTEN,
    MAX_HOPS,
    MIN_SLICE_BUDGET,
    CONVEY_HOPS,
    PREFIX,
    VERSION,
    RECORD_TYPES,
    SIGNED,
    CONDITIONS,
    EOS,
    HIDDEN,
    HEADS,
    KV,
    DIM,
    FF,
    VOCAB,
    RMS,
    ROPE,
    SCALE,
    CODE_MODEL,
    SESSION_TABLE,
    SESSION_STATES,
    SESSION_EVENTS,
    CLEAR_TYPES,
)
from nodo.frame import FrameError, complete, unwrap, wrap
from nodo.identity import load_secret, public_octets
from nodo.item import ItemError, decode_item, encode_item
from nodo.messages import (
    MessageError,
    decode_clear,
    decode_message,
    decode_signed,
    encode_message,
)
from nodo.record import open_record, seal
from nodo.slice import Held, apply, header, inspect, reservation_of, state_octets
from nodo.view import View
from nodo.composition import compose, commitment_id
from nodo.access import lock, submit, take, unlock, reply
from nodo.vocabulary import bytes_vocab, decode, encode, train_bpe
from nodo.measure import cap, host_budget, host_class


def _find_port() -> int:
    """Find an available TCP port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TestRoadmapJoin(TestCase):
    """Roadmap Done item 1: nodo / join(): store, keys, lock, prompt."""

    def test_join_creates_store_and_keys(self):
        """join() creates the store directory, identity key, and box key."""
        with tempfile.TemporaryDirectory() as tmpdir:
            os.environ["XDG_DATA_HOME"] = str(tmpdir)
            try:
                config = join(publish=False)
            finally:
                del os.environ["XDG_DATA_HOME"]
            self.assertIsNotNone(config)
            self.assertTrue(config["identity"].is_file())
            self.assertTrue(config["box"].is_file())
            self.assertTrue(config["state"].is_dir())
            # identity is a valid ed25519 private key (32 bytes)
            identity_data = config["identity"].read_bytes()
            self.assertEqual(len(identity_data), KEY_LEN)
            secret = load_secret(config["identity"])
            participant = public_octets(secret)
            self.assertEqual(len(participant), KEY_LEN)
            # box is a valid x25519 private key
            box_secret = load_box(config["box"])
            box_public_value = box_public(box_secret)
            self.assertEqual(len(box_public_value), KEY_LEN)

    def test_join_creates_store_without_publish(self):
        """join(publish=False) creates keys and store but no publication."""
        with tempfile.TemporaryDirectory() as tmpdir:
            os.environ["XDG_DATA_HOME"] = str(tmpdir)
            try:
                config = join(publish=False)
            finally:
                del os.environ["XDG_DATA_HOME"]
            self.assertIsNotNone(config)
            self.assertIsNone(config["declaration"])
            self.assertIsNone(config["publication"])
            self.assertEqual(config["condition"], "accepted")
            self.assertIsNone(config["ram_limit"])
            self.assertIsNone(config["vram_limit"])

    def test_lock_prevents_second_member(self):
        """The member lock excludes a second node on the same store."""
        with tempfile.TemporaryDirectory() as tmpdir:
            state = Path(tmpdir) / "state"
            state.mkdir(parents=True, exist_ok=True)
            handle1 = lock(state)
            self.assertIsNotNone(handle1)
            handle2 = lock(state)
            self.assertIsNone(handle2)  # lock is exclusive
            unlock(handle1)

    def test_access_mailbox_take(self):
        """The access mailbox accepts a command and the member can take it."""
        with tempfile.TemporaryDirectory() as tmpdir:
            state = Path(tmpdir) / "state"
            state.mkdir(parents=True, exist_ok=True)
            # Write a cmd file directly (simulating a client submitting)
            token = uuid.uuid4().hex
            cmd = state / "access" / f"{token}.cmd"
            cmd.parent.mkdir(parents=True, exist_ok=True)
            cmd.write_text("hello", encoding="utf-8")
            taken = take(state)
            self.assertEqual(len(taken), 1)
            self.assertEqual(taken[0][0], token)
            self.assertEqual(taken[0][1], "hello")
            # cmd should have been removed
            self.assertFalse(cmd.is_file())

    def test_access_mailbox_reply(self):
        """The member can reply to an access mailbox command."""
        with tempfile.TemporaryDirectory() as tmpdir:
            state = Path(tmpdir) / "state"
            state.mkdir(parents=True, exist_ok=True)
            token = uuid.uuid4().hex
            # Reply before the cmd is taken (simulating the server responding)
            reply(state, token, ["ok"], ["err"])
            done = state / "access" / f"{token}.done"
            self.assertTrue(done.is_file())
            out = (state / "access" / f"{token}.out").read_text()
            err = (state / "access" / f"{token}.err").read_text()
            # _joined adds a trailing newline
            self.assertEqual(out, "ok\n")
            self.assertEqual(err, "err\n")

    def test_join_uses_named_constants(self):
        """All magic numbers from join/keys/lock/prompt come from named constants."""
        self.assertEqual(KEY_LEN, 32)
        self.assertEqual(ID_LEN, 16)
        self.assertEqual(SIGNATURE_LEN, 64)
        self.assertEqual(LISTEN, 9400)
        self.assertEqual(MAX_HOPS, 5)
        self.assertEqual(CONVEY_HOPS, 4)
        self.assertEqual(MIN_SLICE_BUDGET, 4)
        self.assertEqual(cap(1000), 10)
        self.assertEqual(cap(999), 9)
        self.assertEqual(cap(10000), 100)


class TestRoadmapCompose(TestCase):
    """Roadmap Done item 2: Compose - embed on smallest id, head on largest, banks in between."""

    def _offer(self, participant, capability, role, reservation=200):
        return {
            "version": VERSION,
            "type": "offer",
            "participant": participant,
            "condition": "accepted",
            "commitments": [{"id": commitment_id(capability, role, participant), "reservation": reservation}],
            "classes": ["cpu"],
            "ram_host": 100000,
            "ram_limit": 1000,
        }

    def test_merge_picks_embed_min_head_max_banks_between(self):
        """View.merge picks embed=min id, head=max id, banks in between by id order."""
        view = View()
        capability = bytes(ID_LEN)
        participant_a = bytes([1] * KEY_LEN)
        participant_b = bytes([2] * KEY_LEN)
        participant_c = bytes([3] * KEY_LEN)
        participant_d = bytes([4] * KEY_LEN)

        self.assertLess(participant_a, participant_b)
        self.assertLess(participant_b, participant_c)
        self.assertLess(participant_c, participant_d)

        decl_a = {
            "version": VERSION,
            "type": "capability",
            "id": capability,
            "participant": participant_a,
            "name": "test",
            "width": 512,
            "bound": 10,
            "span": 10,
            "roles": [{"name": "embed", "reservation": 100}],
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
            "roles": [{"name": "bank-1", "reservation": 100}],
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
            "roles": [{"name": "bank-2", "reservation": 100}],
        }
        decl_d = {
            "version": VERSION,
            "type": "capability",
            "id": capability,
            "participant": participant_d,
            "name": "test",
            "width": 512,
            "bound": 10,
            "span": 10,
            "roles": [{"name": "head", "reservation": 100}],
        }

        view.store_declaration(decl_a)
        view.store_declaration(decl_b)
        view.store_declaration(decl_c)
        view.store_declaration(decl_d)

        view.store_offer(self._offer(participant_a, capability, "embed"))
        view.store_offer(self._offer(participant_b, capability, "bank-1"))
        view.store_offer(self._offer(participant_c, capability, "bank-2"))
        view.store_offer(self._offer(participant_d, capability, "head"))

        merged = view.merge(capability)
        self.assertIsNotNone(merged)
        roles = merged["roles"]
        names = [item["name"] for item in roles]
        self.assertEqual(names[0], "embed")
        self.assertEqual(names[-1], "head")
        self.assertTrue(all(n.startswith("bank-") for n in names[1:-1]))
        # embed is min id, head is max id
        embed = next(item for item in roles if item["name"] == "embed")
        head = next(item for item in roles if item["name"] == "head")
        self.assertEqual(embed["holder"], participant_a)
        self.assertEqual(head["holder"], participant_d)
        # banks sorted by holder id
        banks = [item for item in roles if item["name"].startswith("bank-")]
        self.assertEqual([item["holder"] for item in banks], [participant_b, participant_c])

    def test_compose_assigns_embed_and_head_to_different_holders(self):
        """compose() never assigns embed and head to the same id."""
        capability = bytes(ID_LEN)
        participant_a = bytes([1] * KEY_LEN)
        participant_b = bytes([2] * KEY_LEN)

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
        # Each participant offers only one role with a budget that covers
        # their own role but not the other (debit for the other role's
        # commitment makes free < reservation).
        offer_a = {
            "version": VERSION,
            "type": "offer",
            "participant": participant_a,
            "condition": "accepted",
            "commitments": [{"id": commitment_id(capability, "embed", participant_a), "reservation": 100}],
            "classes": ["cpu"],
            "ram_host": 10000,
            "ram_limit": 100,
        }
        offer_b = {
            "version": VERSION,
            "type": "offer",
            "participant": participant_b,
            "condition": "accepted",
            "commitments": [{"id": commitment_id(capability, "head", participant_b), "reservation": 100}],
            "classes": ["cpu"],
            "ram_host": 10000,
            "ram_limit": 100,
        }
        offers = {participant_a: offer_a, participant_b: offer_b}
        result = compose(declaration, offers, None)
        self.assertTrue(result["complete"])
        roles = {item["role"]: item for item in result["commitments"]}
        # embed and head must be on different holders
        self.assertNotEqual(roles["embed"]["participant"], roles["head"]["participant"])

    def test_compose_incomplete_when_emb_and_head_same(self):
        """compose() returns complete=False when only one holder can be embed+head."""
        capability = bytes(ID_LEN)
        participant_a = bytes([1] * KEY_LEN)
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
            participant_a: self._offer(participant_a, capability, "embed") | {
                "commitments": [
                    {"id": commitment_id(capability, "embed", participant_a), "reservation": 200},
                    {"id": commitment_id(capability, "head", participant_a), "reservation": 200},
                ]
            },
        }
        result = compose(declaration, offers, None)
        self.assertFalse(result["complete"])

    def test_commitment_id_deterministic(self):
        """commitment_id is deterministic and uses UUID v5 of sha1."""
        capability = bytes(ID_LEN)
        role = "embed"
        participant = bytes(KEY_LEN)
        cid1 = commitment_id(capability, role, participant)
        cid2 = commitment_id(capability, role, participant)
        self.assertEqual(cid1, cid2)
        self.assertEqual(len(cid1), ID_LEN)
        self.assertEqual(cid1[6] >> 4, 5)  # UUID v5


class TestRoadmapFramePresenceAssociationRecords(TestCase):
    """Roadmap Done item 3: Frame, presence, association, records."""

    def test_frame_complete_and_unwrap(self):
        """frame.complete and unwrap/wrap work with the nodo/1 prefix."""
        body = b"hello"
        wrapped = wrap(body)
        self.assertTrue(complete(wrapped))
        self.assertEqual(unwrap(wrapped), body)
        self.assertFalse(complete(b"short"))
        self.assertFalse(complete(b"nodo/1"))  # only prefix, no body

    def test_frame_error_on_bad_wrap(self):
        """wrap raises FrameError when the resulting frame is not complete."""
        with self.assertRaises(FrameError):
            wrap(b"")

    def test_item_round_trip_all_types(self):
        """Round-trip encode_item/decode_item for all 20 item types."""
        participant = bytes(KEY_LEN)
        for kind in (
            "association-open", "association-accept", "association-close",
            "presence", "introduction", "convey",
            "offer-withdrawal", "capability", "composition",
            "session-open", "session-progress", "session-suspend", "session-close",
            "rejection", "step-in", "step-carry", "step-out",
            "role-need", "role-carry", "offer",
        ):
            message = {"type": kind, "version": VERSION, "participant": participant}
            if kind == "presence":
                message["box"] = bytes(KEY_LEN)
            elif kind == "convey":
                message["subject"] = bytes(KEY_LEN)
                message["body"] = PREFIX + bytes(10)
            elif kind == "introduction":
                message["subject"] = bytes(KEY_LEN)
            elif kind == "capability":
                message.update({"id": bytes(ID_LEN), "name": "nodo", "width": 512, "bound": 10, "span": 10, "roles": []})
            elif kind == "composition":
                message.update({"declarant": bytes(KEY_LEN), "capability": bytes(ID_LEN), "complete": True, "commitments": []})
            elif kind == "session-open":
                message.update({"id": bytes(ID_LEN), "declarant": bytes(KEY_LEN), "capability": bytes(ID_LEN), "commitments": []})
            elif kind == "session-progress":
                message.update({"session": bytes(ID_LEN), "sequence": 1})
            elif kind == "session-suspend":
                message.update({"session": bytes(ID_LEN), "cause": "recomposition-incomplete"})
            elif kind == "session-close":
                message.update({"session": bytes(ID_LEN)})
            elif kind == "step-in":
                message.update({"session": bytes(ID_LEN), "commitment": bytes(ID_LEN), "sequence": 1, "token": 0})
            elif kind == "step-carry":
                message.update({"session": bytes(ID_LEN), "commitment": bytes(ID_LEN), "sequence": 1, "body": bytes(512)})
            elif kind == "step-out":
                message.update({"session": bytes(ID_LEN), "sequence": 1, "token": 0})
            elif kind == "role-need":
                message.update({"holder": bytes(KEY_LEN), "declarant": bytes(KEY_LEN), "capability": bytes(ID_LEN), "role": "embed"})
            elif kind == "role-carry":
                message.update({"holder": bytes(KEY_LEN), "declarant": bytes(KEY_LEN), "capability": bytes(ID_LEN), "role": "embed", "offset": 0, "remain": 0, "body": bytes(512)})
            elif kind == "rejection":
                message["cause"] = "authorization"
            elif kind == "offer":
                message.update({"condition": "accepted", "commitments": [], "classes": ["cpu"], "ram_host": 16, "ram_limit": 8})
            elif kind in {"association-open", "association-accept"}:
                message.update({"eph": bytes(KEY_LEN), "box": bytes(KEY_LEN)})
            encoded = encode_item(message)
            decoded, rest = decode_item(encoded)
            self.assertEqual(decoded["type"], kind)
            self.assertEqual(decoded["version"], VERSION)
            self.assertEqual(len(rest), 0)

    def test_record_seal_open_and_tamper(self):
        """Records seal/open with sequence-based replay protection."""
        key = os.urandom(32)
        seq = 42
        plaintext = b"hello record"
        sealed = seal(key, seq, plaintext)
        self.assertGreaterEqual(len(sealed), 8 + 16)
        opened_seq, opened_text = open_record(key, sealed)
        self.assertEqual(opened_seq, seq)
        self.assertEqual(opened_text, plaintext)
        # tampered record fails
        tampered = bytearray(sealed)
        tampered[10] ^= 0xFF
        self.assertIsNone(open_record(key, bytes(tampered)))

    def test_handshake_seal_open(self):
        """Handshake seal/open with ephemeral X25519 and long-term box."""
        secret, public = generate_ephemeral()
        peer_secret, peer_public = generate_ephemeral()
        signer = Ed25519PrivateKey.generate()
        participant = signer.public_key().public_bytes_raw()
        message = {
            "type": "association-open",
            "version": VERSION,
            "participant": participant,
            "eph": public,
            "box": peer_public,
        }
        inner = encode_message(message, signer)
        sealed = seal_handshake(secret, peer_public, participant, inner)
        self.assertGreaterEqual(len(sealed), KEY_LEN + 16)
        opened = open_handshake(peer_secret, participant, sealed)
        self.assertEqual(opened, inner)

    def test_presence_is_signed_and_clear(self):
        """presence is a SIGNED item and a CLEAR_TYPES item."""
        self.assertIn("presence", SIGNED)
        self.assertIn("presence", CLEAR_TYPES)
        secret = Ed25519PrivateKey.generate()
        participant = secret.public_key().public_bytes_raw()
        message = {"type": "presence", "version": VERSION, "participant": participant, "box": bytes(KEY_LEN)}
        signed = encode_message(message, secret)
        decoded = decode_signed(signed)
        self.assertEqual(decoded["type"], "presence")
        self.assertEqual(decoded["participant"], participant)

    def test_rejection_is_clear_and_not_signed(self):
        """rejection is a CLEAR_TYPES item and not signed."""
        self.assertIn("rejection", CLEAR_TYPES)
        self.assertNotIn("rejection", SIGNED)
        message = {"type": "rejection", "version": VERSION, "cause": "authorization"}
        encoded = encode_message(message, None)
        decoded = decode_clear(encoded)
        self.assertEqual(decoded["type"], "rejection")
        self.assertEqual(decoded["cause"], "authorization")

    def test_all_signed_types_encode_with_secret(self):
        """All SIGNED types can be encoded with a secret and decoded."""
        secret = Ed25519PrivateKey.generate()
        participant = secret.public_key().public_bytes_raw()
        for type_name in sorted(SIGNED):
            if type_name in {"presence", "rejection"}:
                continue
            fields = {"participant": participant}
            if type_name == "convey":
                fields["subject"] = bytes(KEY_LEN)
                fields["body"] = PREFIX + bytes(10)
            elif type_name == "introduction":
                fields["subject"] = bytes(KEY_LEN)
            elif type_name == "capability":
                fields.update({"id": bytes(ID_LEN), "name": "test", "width": 512, "bound": 10, "span": 10, "roles": [{"name": "embed", "reservation": 100}]})
            elif type_name == "composition":
                fields.update({"declarant": bytes(KEY_LEN), "capability": bytes(ID_LEN), "complete": True, "commitments": []})
            elif type_name == "session-open":
                fields.update({
                    "id": bytes(ID_LEN),
                    "declarant": bytes(KEY_LEN),
                    "capability": bytes(ID_LEN),
                    "commitments": [{"id": bytes(ID_LEN), "role": "embed", "participant": participant, "reservation": 100}],
                })
            elif type_name == "session-progress":
                fields.update({"session": bytes(ID_LEN), "sequence": 1})
            elif type_name == "session-suspend":
                fields.update({"session": bytes(ID_LEN), "cause": "recomposition-incomplete"})
            elif type_name == "session-close":
                fields.update({"session": bytes(ID_LEN)})
            elif type_name == "step-in":
                fields.update({"session": bytes(ID_LEN), "commitment": bytes(ID_LEN), "sequence": 1, "token": 0})
            elif type_name == "step-carry":
                fields.update({"session": bytes(ID_LEN), "commitment": bytes(ID_LEN), "sequence": 1, "body": bytes(64)})
            elif type_name == "step-out":
                fields.update({"session": bytes(ID_LEN), "sequence": 1, "token": 0})
            elif type_name == "role-need":
                fields.update({"holder": bytes(KEY_LEN), "declarant": bytes(KEY_LEN), "capability": bytes(ID_LEN), "role": "embed"})
            elif type_name == "role-carry":
                fields.update({"holder": bytes(KEY_LEN), "declarant": bytes(KEY_LEN), "capability": bytes(ID_LEN), "role": "embed", "offset": 0, "remain": 0, "body": bytes(64)})
            elif type_name in {"association-open", "association-accept"}:
                fields.update({"eph": bytes(KEY_LEN), "box": bytes(KEY_LEN)})
            elif type_name == "association-close":
                pass
            elif type_name == "offer":
                fields.update({"condition": "accepted", "commitments": [], "classes": ["cpu"], "ram_host": 16, "ram_limit": 8})
            message = {"type": type_name, "version": VERSION, **fields}
            encoded = encode_message(message, secret)
            self.assertIsNotNone(encoded)
            decoded = decode_signed(encoded)
            self.assertEqual(decoded["type"], type_name)
            self.assertEqual(decoded["participant"], participant)

    def test_record_types_constant(self):
        """RECORD_TYPES = SIGNED - {association-open, association-accept} + {composition, rejection}."""
        expected = set(SIGNED) - {"association-open", "association-accept"}
        expected.add("composition")
        expected.add("rejection")
        self.assertEqual(set(RECORD_TYPES), expected)

    def test_derive_keys_deterministic_and_crossed(self):
        """derive_keys is deterministic and the two keys are different."""
        secret, public = generate_ephemeral()
        peer_secret, peer_public = generate_ephemeral()
        shared = shared_secret(secret, peer_public)
        k_i1, k_a1 = derive_keys(shared, b"initiator", b"acceptor", public, peer_public)
        k_i2, k_a2 = derive_keys(shared, b"initiator", b"acceptor", public, peer_public)
        self.assertEqual(k_i1, k_i2)
        self.assertEqual(k_a1, k_a2)
        self.assertNotEqual(k_i1, k_a1)


class TestRoadmapDHTPlacementConvey(TestCase):
    """Roadmap Done item 4: Mainline DHT, same-host replica, convey."""

    def test_mesh_bind_and_close(self):
        """Mesh binds to a UDP port and can be closed."""
        from nodo.dht import Mesh
        port = _find_port()
        mesh = Mesh(port)
        self.assertIsNotNone(mesh._sock)
        self.assertEqual(mesh._sock.getsockname()[1], port)
        mesh.close()
        self.assertIsNone(mesh._sock)

    def test_mesh_seed_and_tick(self):
        """Mesh seeds peers and ticks without error."""
        from nodo.dht import Mesh
        port = _find_port()
        mesh = Mesh(port)
        mesh.seed([("127.0.0.1", 9400)])
        mesh.tick()  # should not raise
        mesh.close()

    def test_placement_identity_and_route(self):
        """Placement creates an identity and a route."""
        from nodo.placement import Placement
        port = _find_port()
        placement = Placement(listen=port)
        self.assertIsNotNone(placement.identity)
        self.assertEqual(len(placement.identity), 32)
        route = placement.route()
        self.assertIsNotNone(route.token)
        placement.close()

    def test_placement_accept_and_receive(self):
        """Placement accepts a frame and receive returns it."""
        from nodo.placement import Placement
        port = _find_port()
        placement = Placement(listen=port)
        frame = wrap(b"nodo/1 test body")
        placement.accept(frame, placement.route())
        got = placement.receive()
        self.assertIsNotNone(got)
        self.assertEqual(got[0], frame)
        placement.close()

    def test_table_join_and_leave(self):
        """TABLE.join registers replicas and TABLE.leave removes them."""
        from nodo.table import TABLE

        class FakeReplica:
            def __init__(self, identity, token):
                self.identity = identity
                self.token = token
                self.last = None
            def accept(self, frame, source): pass
            def route(self): return self
            def offer_shard(self, frame, present): pass

        rep1 = FakeReplica(bytes(32), "token1")
        rep2 = FakeReplica(bytes(32), "token2")
        TABLE.join(rep1)
        TABLE.join(rep2)
        # two replicas of same identity
        self.assertEqual(len(TABLE._replicas[bytes(32)]), 2)
        TABLE.leave(rep1)
        self.assertEqual(len(TABLE._replicas[bytes(32)]), 1)
        TABLE.leave(rep2)
        self.assertEqual(len(TABLE._replicas[bytes(32)]), 0)

    def test_dht_node_id_and_hash(self):
        """DHT uses sha1(nodo/1) as infohash and 20-byte node ids."""
        from nodo.domain import HASH, infohash
        self.assertEqual(HASH, infohash())
        self.assertEqual(len(HASH), 20)
        self.assertEqual(HASH, hashlib.sha1(PREFIX).digest())

    def test_convey_message_round_trip(self):
        """convey item encodes and decodes with a body that starts with nodo/1."""
        participant = bytes(KEY_LEN)
        subject = bytes(KEY_LEN)
        body = PREFIX + bytes(20)
        message = {"type": "convey", "version": VERSION, "participant": participant, "subject": subject, "body": body}
        encoded = encode_item(message)
        decoded, rest = decode_item(encoded)
        self.assertEqual(decoded["type"], "convey")
        self.assertEqual(decoded["subject"], subject)
        self.assertEqual(decoded["body"], body)
        self.assertEqual(len(rest), 0)


class TestRoadmapSessionWalk(TestCase):
    """Roadmap Done item 5: Session walk (step-in → carry → step-out)."""

    def test_step_items_round_trip(self):
        """step-in, step-carry, step-out items round-trip."""
        participant = bytes(KEY_LEN)
        session = bytes(ID_LEN)
        commitment = bytes(ID_LEN)
        for kind, fields in (
            ("step-in", {"session": session, "commitment": commitment, "sequence": 1, "token": 0}),
            ("step-carry", {"session": session, "commitment": commitment, "sequence": 1, "body": bytes(512)}),
            ("step-out", {"session": session, "sequence": 1, "token": 0}),
        ):
            message = {"type": kind, "version": VERSION, "participant": participant, **fields}
            encoded = encode_item(message)
            decoded, rest = decode_item(encoded)
            self.assertEqual(decoded["type"], kind)
            self.assertEqual(len(rest), 0)

    def test_session_state_machine_all_transitions(self):
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

    def test_session_walk_sequence(self):
        """The session walk sequence: open → step-in → step-carry → step-out."""
        # none -> open via session-open
        self.assertEqual(SESSION_TABLE[("none", "session-open")], ("open", "accept"))
        # open -> open via step-in
        self.assertEqual(SESSION_TABLE[("open", "step-in")], ("open", "accept"))
        # open -> open via step-carry
        self.assertEqual(SESSION_TABLE[("open", "step-carry")], ("open", "accept"))
        # open -> closed via session-close
        self.assertEqual(SESSION_TABLE[("open", "session-close")], ("closed", "accept"))

    def test_apply_embed_returns_carry(self):
        """apply on an embed holder (first, not last) returns a carry."""
        held = self._make_held(1)  # KIND_EMBED = 1
        result = apply(held, HIDDEN * 2, 0, 3, 0, None, 0, 1)
        self.assertIsNotNone(result)
        kind, value = result
        self.assertEqual(kind, "carry")
        self.assertEqual(len(value), HIDDEN * 2)

    def test_apply_bank_returns_carry(self):
        """apply on a bank holder (middle) returns a carry."""
        held = self._make_held(4)  # KIND_BANK = 4
        carry = bytes(HIDDEN * 2)
        result = apply(held, HIDDEN * 2, 1, 3, 0, carry, 0, 1)
        self.assertIsNotNone(result)
        kind, value = result
        self.assertEqual(kind, "carry")
        self.assertEqual(len(value), HIDDEN * 2)

    def test_apply_head_returns_token(self):
        """apply on a head holder (last) returns a token."""
        held = self._make_held(3)  # KIND_HEAD = 3
        carry = bytes(HIDDEN * 2)
        result = apply(held, HIDDEN * 2, 2, 3, 0, carry, 0, 1)
        self.assertIsNotNone(result)
        kind, value = result
        self.assertEqual(kind, "token")
        self.assertIsInstance(value, int)

    def test_session_open_and_close_transitions(self):
        """Session close transitions from open->closed and suspended->closed."""
        self.assertEqual(SESSION_TABLE[("open", "session-close")], ("closed", "accept"))
        self.assertEqual(SESSION_TABLE[("suspended", "session-close")], ("closed", "accept"))
        self.assertEqual(SESSION_TABLE[("closed", "session-close")], ("closed", "discard"))

    def test_suspend_and_resume_transitions(self):
        """Session suspend transitions and resume."""
        self.assertEqual(SESSION_TABLE[("open", "session-suspend")], ("suspended", "accept"))
        self.assertEqual(SESSION_TABLE[("suspended", "session-suspend")], ("suspended", "discard"))
        self.assertEqual(SESSION_TABLE[("suspended", "session-open")], ("open", "accept"))

    def test_peer_loss_triggers_recompose(self):
        """Peer loss from open triggers recompose."""
        self.assertEqual(SESSION_TABLE[("open", "peer-loss")], ("open", "recompose"))
        self.assertEqual(SESSION_TABLE[("suspended", "peer-loss")], ("suspended", "discard"))

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

    def test_view_merge_no_declarations(self):
        """View.merge returns None when there are no declarations."""
        view = View()
        result = view.merge(bytes(ID_LEN))
        self.assertIsNone(result)

    def test_view_compositions_complete(self):
        """View.compositions returns complete compositions."""
        view = View()
        capability = bytes(ID_LEN)
        participant_a = bytes([1] * KEY_LEN)
        participant_b = bytes([2] * KEY_LEN)
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
            "roles": [{"name": "embed", "reservation": 100}],
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
            "roles": [{"name": "bank-1", "reservation": 100}, {"name": "head", "reservation": 100}],
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


class TestRoadmapIntegration(TestCase):
    """Integration tests that walk the full roadmap flow end-to-end."""

    def test_full_handshake_and_record_flow(self):
        """Two peers complete a handshake, then seal and open records."""
        def make_peer():
            secret = Ed25519PrivateKey.generate()
            participant = secret.public_key().public_bytes_raw()
            box_secret = X25519PrivateKey.generate()
            box_public = box_secret.public_key().public_bytes_raw()
            return {"secret": secret, "participant": participant, "box_secret": box_secret, "box_public": box_public}

        a = make_peer()
        b = make_peer()
        initiator = a if a["participant"] < b["participant"] else b
        acceptor = b if initiator is a else a

        eph_i, eph_public_i = generate_ephemeral()
        open_msg = {
            "type": "association-open",
            "version": VERSION,
            "participant": initiator["participant"],
            "eph": eph_public_i,
            "box": initiator["box_public"],
        }
        inner_i = encode_message(open_msg, initiator["secret"])
        sealed_i = seal_handshake(eph_i, acceptor["box_public"], initiator["participant"], inner_i)
        inner_a = open_handshake(acceptor["box_secret"], initiator["participant"], sealed_i)
        open_decoded = decode_signed(inner_a)
        self.assertEqual(open_decoded["type"], "association-open")

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
        sealed_a = seal_handshake(eph_a, initiator["box_public"], acceptor["participant"], inner_a2)
        inner_i2 = open_handshake(initiator["box_secret"], acceptor["participant"], sealed_a)
        accept_decoded = decode_signed(inner_i2)
        self.assertEqual(accept_decoded["type"], "association-accept")

        shared_i = shared_secret(eph_i, eph_public_a)
        shared_a = shared_secret(eph_a, eph_public_i)
        self.assertEqual(shared_i, shared_a)

        info = PREFIX + initiator["participant"] + acceptor["participant"] + eph_public_i + eph_public_a
        k_i, k_a = derive_keys(shared_i, initiator["participant"], acceptor["participant"], eph_public_i, eph_public_a)
        self.assertNotEqual(k_i, k_a)

        # Record seal/open between peers
        seq = 1
        plaintext = b"step-in token"
        sealed = seal(k_i, seq, plaintext)
        opened_seq, opened_text = open_record(k_i, sealed)
        self.assertEqual(opened_seq, seq)
        self.assertEqual(opened_text, plaintext)

    def test_composition_complete_and_session_open(self):
        """A complete composition yields a session-open that can be held."""
        view = View()
        capability = bytes(ID_LEN)
        participant_a = bytes([1] * KEY_LEN)
        participant_b = bytes([2] * KEY_LEN)
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
            "roles": [{"name": "embed", "reservation": 100}],
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
            "roles": [{"name": "head", "reservation": 100}],
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
            "commitments": [{"id": commitment_id(capability, "head", participant_b), "reservation": 200}],
            "classes": ["cpu"],
            "ram_host": 100000,
            "ram_limit": 1000,
        }
        view.store_offer(offer_a)
        view.store_offer(offer_b)

        compositions = view.compositions()
        self.assertEqual(len(compositions), 1)
        self.assertTrue(compositions[0]["complete"])
        # session-open matches the composition: generate a key pair and use the
        # public key as the participant id, then sign with the private key.
        comp = compositions[0]
        signer = Ed25519PrivateKey.generate()
        signer_participant = signer.public_key().public_bytes_raw()
        session_open = {
            "type": "session-open",
            "version": VERSION,
            "participant": signer_participant,
            "id": bytes(ID_LEN),
            "declarant": comp["declarant"],
            "capability": comp["capability"],
            "commitments": comp["commitments"],
        }
        encoded = encode_message(session_open, signer)
        decoded = decode_signed(encoded)
        self.assertEqual(decoded["type"], "session-open")
        self.assertEqual(decoded["participant"], signer_participant)
        self.assertEqual(decoded["commitments"], comp["commitments"])


if __name__ == "__main__":
    import unittest
    unittest.main()
