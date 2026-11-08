[nodo](index.md) · [Flow](flow.md) · [Network](network.md) · [Model](model.md) · [Session](session.md) · [Protocol](protocol.md) · [Roadmap](roadmap.md) · **Design**

# Design

Why the mesh is shaped the way it is, and the decisions that follow from them. This page is about intent; [Network](network.md) is about delivery, [Model](model.md) is about the forward pass.

## The three constraints

Everything below follows from these three.

1. **No site file.** There is no coordinator, no bootstrap list, no machine cap. A site that joins is a mesh member from the first byte it sends.
2. **Weights never travel.** A machine publishes the part it created and keeps it on its own disk. The only bytes that cross the wire are carries: 512 f16be floats, one per step, one per holder.
3. **One model, many sites.** Several computers form one inference model. A prompt walks the machines that are up: `embed → banks → head`.

Constraint 2 is what makes constraint 1 possible. Constraint 3 is what makes constraint 2 worth it.

## What a site is

A site is a process that joins the store, creates a bank, and announces a resource offer. It is not a node in a graph and not a shard of a model. A site may hold any number of roles in the current composition, and it does not know which until it is asked.

```text
site = { store, keys, bank, offer, view, associations, session? }
```

The session is optional. A site that never receives a `session-open` is still a member of the mesh.

## What a prompt is

A prompt is a byte string that the opener encodes into tokens with `bytes_vocab()`, then walks as a sequence of `step-in` items, one per commitment. The opener does not hold the model; it holds the walk.

```text
prompt → bytes_vocab() → tokens → step-in(token) → step-carry → … → step-out(token)
```

The opener reads the decoded tokens and prints one line. It never sees a weight file.

## Roles and budget

A composition has `embed` (smallest accepted id), `head` (largest accepted id), and `bank-*` (every other accepted holder, in id order). A single site may hold more than one role, but never both `embed` and `head`.

The budget is `measure.cap(quantity) = quantity // 100`. It is the announced limit and the local publication budget. `span` and `bound` are `fit_span` of one layer of KV state against that budget:

```text
span = (budget - 4) // 1024
```

The constant `1024` is the KV reservation per position for this architecture (`state_octets(1, span, 8, 32)`), not an architectural constant. It is `2 * span * KV * DIM * 2` for the native slice.

A prompt is rejected unless `n + bound <= span`. `bound` equals `span` on the publication `join()` writes, so the ceiling and the capacity are the same number.

## Why the id ordering rules

`View.merge` picks `embed` as the smallest holder and `head` as the largest holder. `compose` picks each role by `min(eligible, key=sha256(participant || capability_id))`. Both are deterministic orderings over a set of ids, which is what makes `complete` a well-defined predicate rather than a race.

The ordering is over ids, not over addresses. Two sites on the same LAN are still ordered by id. That is deliberate: the mesh is not a cluster and does not want one.

## Why the handshake is pairwise

`_on_open` ignores an initiator that is greater than self:

```text
if initiator == self.participant or initiator > self.participant:
    return
```

Pairwise initiation is the smaller Ed25519 id. The rule prevents a replayed `association-open` from starting a second association, and it makes the handshake symmetric: the smaller id sends first, the larger id answers.

The rule is also a security rule. A site that receives an `association-open` from a larger id is treated as a broken or replayed open, not as a new association.

## Why `convey` exists

`convey` is the fallback when there is no direct route. It wraps a frame in a `convey` record and sends it to an associate that already has a route to the subject.

```text
hop → subject: convey {participant, subject, body}
```

`body` must itself be a frame (start with `nodo/1`). A `convey` to a subject with no route is rejected with `association`.

This is how the mesh spans networks that cannot open TCP to each other: a common associate forwards sealed handshake frames and later records. It is not a transport; it is a relay.

## Why the bank grows

`_apply_step` on a bank holder:

1. `apply_role` returns `("carry", body)`.
2. `append_bank` writes `(body, body)` as a new `(key, value)` pair on **that** holder's file.
3. The carry is forwarded to the opener.

The append is the whole information transfer. Two machines therefore accumulate different memory, and later prompts attend against whatever each site already stored. Nothing ships those pairs to the opener.

This is the design that makes the mesh worth building: each site cedes information gradually, and the cession is the model.

## Why `no model`

`no model` is the honest output of an incomplete composition. It is printed when:

- fewer than two accepted holders exist, or
- `embed` and `head` are still on the same id, or
- the prompt does not fit `span`.

A single machine alone has only a bank. Composition is incomplete, so a prompt prints `no model`. The third, tenth, or hundredth machine does not add another embed; it adds another bank.

## Why the store is a mailbox

A second process on the same store does not open a mesh. It talks to the first through the access mailbox: `state/access/<uuid>.cmd` and `.out` / `.err` / `.done`.

The serve loop (`_apply_access`) runs `command` on each `.cmd`. If a session is still open, the token is queued (`_mailbox`) and answered when generation finishes.

This is how the design keeps one member per store: the lock is exclusive, and the mailbox is the only way in.

## What is not implemented

These are documented here rather than silently absent.

- **NAT traversal.** `convey` needs a hop that already has a route. Two NATs with no reachable hop cannot associate.
- **IPv6.** `placement` and `Mesh` are IPv4-only.
- **Two nodes on one host.** A second `nodo` on the same store is only a mailbox.
- **A real model.** Every weight file is `rng(count, seed, scale)`. The model is not trained, and the output is not language.
- **A real vocabulary.** `bytes_vocab()` maps each byte to one token. The output is a byte string, not language.
- **A real stop condition.** `EOS = 0` is a byte token, and generation stops at `bound`.
- **Error messages.** `no model` is used for several different failures.
- **Tests.** There are none.

## Security model

| layer | what |
| --- | --- |
| identity | Ed25519 public key is the `participant` id, and the signing key |
| association | X25519 ephemeral, ChaCha20-Poly1305, nonce `4×0 || seq` |
| records | signed over `nodo/1 || payload`; signature verified against the peer's public key |
| handshake | sealed with the peer's long-term box; `eph_public || AEAD` |
| frame | `nodo/1 || body`; anything else is rejected as `frame` |

`SIGNED` items are verified by `decode_message`: signature, then `message["participant"] == author.public_bytes_raw()`. A signature over the wrong payload, or from the wrong key, is `MessageError("signature")`.

`presence` is a `CLEAR_TYPES` item, so it may travel outside a record. It is the only item that does.

## Failure handling

`main()` catches `LocalFailure` and prints `str(getattr(exc, "cause", exc))`. Several paths raise `LocalFailure` with a cause; some raise it with no cause (`raise LocalFailure("announce")` where the real reason is in the branch). `Placement._bind_world` swallows `OSError` when `listen` is not explicit and continues without a world socket.

`Participant.serve` treats an empty read as a prompt available. The serve loop is not a loop of steps; it is a loop of waits, and `step()` is called when there is work.

## Open questions

- Does a `convey` hop sign with its own key (endorsement) or forward as-is?
- Is the floor Python 3.14, or a version people already have?
- Is `no model` the right output, or should each cause be reported?
- Does a site that leaves drop out, or does its bank survive under the next holder?
