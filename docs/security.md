[nodo](index.md) · [Flow](flow.md) · [Network](network.md) · [Model](model.md) · [Session](session.md) · [Protocol](protocol.md) · [Roadmap](roadmap.md) · [Design](design.md) · **Security**

# Security

Do not open a public issue for a vulnerability. See [SECURITY.md](SECURITY.md).

This page is about the design as it stands, not a bug report.

## What is authenticated

| item | signed over | verified against |
| --- | --- | --- |
| `presence` | `nodo/1 || payload` | Ed25519 of `participant` |
| `introduction` | same | same |
| `offer`, `capability`, `association-close`, `step-in`, `step-carry`, `step-out`, `role-need`, `role-carry`, `session-*` | same | same |
| `convey` | same | same |
| `composition`, `rejection` | not signed | inside an already-authenticated record |

`decode_message` verifies the signature, then checks `message["participant"] == author.public_bytes_raw()`. Both checks happen; either failure is `MessageError("signature")`.

`SIGNED` is the set above. `composition` and `rejection` are the exceptions: they travel inside a record and are authenticated by the record's envelope. `rejection` may also go in the clear (`CLEAR_TYPES`), and `presence` may too.

## Handshake

```text
outer = eph_public || ChaCha20-Poly1305(key, nonce=12×0, aad=nodo/1, signed item)
key   = SHA-256( 0x03 || X25519(eph, peer_box) || nodo/1 || recipient_id )
```

`open_handshake` decrypts with the peer's box and the initiator's ephemeral:

```text
key = SHA-256( 0x03 || X25519(box, public) || nodo/1 || recipient_id )
```

The first 32 bytes of `outer` must equal the `eph` field inside the item. Zero ECDH output is rejected (`AssociationError("zero")`).

Record keys:

```text
info = nodo/1 || initiator || acceptor || eph_initiator || eph_acceptor
k_i  = SHA-256( 0x01 || shared || info )
k_a  = SHA-256( 0x02 || shared || info )
```

`shared` is X25519 between the two ephemerals. The initiator sends `k_i`, receives `k_a`; the acceptor sends `k_a`, receives `k_i`.

Record envelope:

```text
seq u64be
ciphertext = ChaCha20-Poly1305(send_key, nonce=4×0||seq, aad=nodo/1||seq, item)
```

`recv_seq` must match exactly. Lower is replay (drop). Higher is a gap (end association).

## What is not authenticated

- **Weight files.** A bank holder reads its own file. No weight file is ever sent, so there is nothing to authenticate on the product path.
- **The opener's prompt.** The opener does not sign the prompt; it is the only one that sees it.
- **`convey` hops.** A hop forwards a `convey` record without being able to authenticate the subject's key. See [Design](design.md#nat-traversal).

## Replays and gaps

`recv_seq` is a strict integer sequence. A replayed record has `seq < recv_seq` and is dropped. A record with `seq > recv_seq` ends the association. A gap is not tolerated.

`seen` is keyed on `(session, commitment, sequence)`. A replayed `step-*` with the same sequence is dropped.

`_on_open` ignores an initiator that is greater than self, which prevents a replayed open from starting a second association.

## Known weaknesses

- **A compromised hop compromises the mesh.** `convey` requires a hop that already has a route to the subject. If that hop is hostile, the subject's frames are forwarded without authentication.
- **The store is a single directory.** `$XDG_DATA_HOME/nodo` (or the other two roots) is one directory. A site that joins writes to it. There is no replication between sites.
- **`peers` survives; `introducers` and `via` do not.** A restart rebuilds associations from nothing.
- **A bank grows without bound.** `append_bank` appends to a file on that disk. There is no eviction, no size cap, and no way to remove an old pair.
- **The view is in memory.** `Participant.__init__` rebuilds `assocs` and `View` from nothing. A restart is a new mesh.
- **`no model` is a catch-all.** It is printed for several different failures, including a dead bind. See [Roadmap](roadmap.md#errors-that-say-what-failed).
- **`rng` is deterministic.** `rng(count, seed, scale)` is a linear congruential generator. Two sites with the same `seed` produce the same weights.

## Configuration

`join()` writes Ed25519 and X25519 keys if they are missing, and creates the local bank. `identity` is `root / "ed25519"` and `box` is `root / "box"`.

`capability` is derived from `sha256(nodo/1)` and is the same for every site:

```text
capability() = uuid_shape(sha256(nodo/1)[:16], 7)
```

`uuid_shape` sets `data[6] = (data[6] & 0x0F) | (version << 4)` and `data[8] = (data[8] & 0x3F) | 0x80`.

`network()` is `sha256(nodo/1)` and names the replica directory on one host. `infohash()` is `sha1(nodo/1)` and is the DHT infohash. They are different digests and must not be confused.

## Failure handling

`main()` catches `LocalFailure` and prints `str(getattr(exc, "cause", exc))`. Several paths raise `LocalFailure` with a cause; some raise it with no cause (`raise LocalFailure("announce")` where the real reason is in the branch). `Placement._bind_world` swallows `OSError` when `listen` is not explicit and continues without a world socket.

`Participant.serve` treats an empty read as a prompt available. The serve loop is not a loop of steps; it is a loop of waits, and `step()` is called when there is work.

## Open questions

- Does a `convey` hop sign with its own key (endorsement) or forward as-is?
- Is the floor Python 3.14, or a version people already have?
- Is `no model` the right output, or should each cause be reported?
- Does a site that leaves drop out, or does its bank survive under the next holder?
