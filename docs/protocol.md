[nodo](index.md) · [Flow](flow.md) · [Network](network.md) · [Model](model.md) · [Session](session.md) · **Protocol**

# Protocol

Wire version `VERSION = 1`. Encoding is binary (`item.py`). There is no JSON on the mesh. JSON exists only as `publication/declaration` on disk.

## Frame

```text
nodo/1 || body
```

`body` is one of:

- a clear item (`presence` or `rejection`)
- a sealed handshake (`eph_public || AEAD`)
- a record (`seq || AEAD`)

## Item header

```text
type   u8     # TYPE_CODE, 1-based index in TYPES
version u8    # must be 1
fields …      # LAYOUT or offer special-case
[signature 64]  # if type ∈ SIGNED
```

Integers are unsigned big-endian. Text is `u16` length + UTF-8 (length ≥ 1). Binary is `u32` length + bytes. Bool is `0` or `1`. Enum is a `u8` index into the table named below. Lists are `u16` count + elements.

`SIGNED` items append Ed25519 over `nodo/1 || payload` (payload includes type and version, excludes the signature). The verifying public key must equal the item's `participant` field.

`composition` and `rejection` are not signed. They travel inside an already-authenticated record, except `rejection`, which may also go in the clear (`CLEAR_TYPES`).

`RECORD_TYPES` = (`SIGNED` minus the two handshake types) ∪ `{composition, rejection}`. Any other type inside a record ends the association.

## Types

`TYPES` order is the type byte. Field lists match `LAYOUT` / offer codec.

### Handshake and mesh

| type | byte | signed | fields |
| --- | --- | --- | --- |
| `association-open` | 1 | yes | `participant` 32, `eph` 32, `box` 32 |
| `association-accept` | 2 | yes | same |
| `association-close` | 3 | yes | `participant` 32 |
| `presence` | 4 | yes | `participant` 32, `box` 32 |
| `introduction` | 5 | yes | `participant` 32, `subject` 32 |
| `convey` | 6 | yes | `participant` 32, `subject` 32, `body` bin (must start with `nodo/1`) |

### Offer and capability

| type | byte | signed | fields |
| --- | --- | --- | --- |
| `offer` | 7 | yes | see below |
| `offer-withdrawal` | 8 | yes | `participant` 32 |
| `capability` | 9 | yes | `id` 16, `participant` 32, `name` text, `width` u32, `bound` u32, `span` u32, `roles` |
| `composition` | 10 | no | `declarant` 32, `capability` 16, `complete` bool, `commitments` |

**Offer body** after the common head (`participant`, `condition` ∈ `accepted|pause|leave`, `commitments` of `{id 16, reservation u64}`):

- CPU: class `cpu`, `ram_host` u64, `ram_limit` u64
- GPU: class `gpu`, `vram_host` u64, `vram_limit` u64, optional `vram_device` (flag + text)

**Role** in a capability: `name` text, `reservation` u64 ≥ 1, optional `class` ∈ `cpu|gpu` (flag + enum).

**Commitment** (composition / session-open): `id` 16, `role` text, `participant` 32, `reservation` u64 ≥ 1.

Capability `id` is 16 bytes, UUID version 7 (`id[6] >> 4 == 7`). `span >= bound >= 1`, `width >= 1`.

Commitment id is UUID version 5 of `sha1(capability_id || utf8(role) || participant)` (`composition.commitment_id`).

### Session and steps

| type | byte | signed | fields |
| --- | --- | --- | --- |
| `session-open` | 11 | yes | `id` 16, `participant` 32, `declarant` 32, `capability` 16, `commitments` (non-empty) |
| `session-progress` | 12 | yes | `participant` 32, `session` 16, `sequence` u64 |
| `session-suspend` | 13 | yes | `participant` 32, `session` 16, `cause` ∈ `recomposition-incomplete\|result-incompatible` |
| `session-close` | 14 | yes | `participant` 32, `session` 16 |
| `rejection` | 15 | no | `cause` ∈ `REJECTION` |
| `step-in` | 16 | yes | `participant` 32, `session` 16, `commitment` 16, `sequence` u64, `token` u32 |
| `step-carry` | 17 | yes | `participant` 32, `session` 16, `commitment` 16, `sequence` u64, `body` bin |
| `step-out` | 18 | yes | `participant` 32, `session` 16, `sequence` u64, `token` u32 |
| `role-need` | 19 | yes | `participant` 32, `holder` 32, `declarant` 32, `capability` 16, `role` text |
| `role-carry` | 20 | yes | those fields plus `offset` u64, `remain` u64, `body` bin |

`role-carry.body` is at most `CARRY` (1 048 576) bytes. `remain` is octets still unread after this chunk. The receiver appends only if `offset` equals the current file size.

## Record envelope

```text
seq u64be
ciphertext = ChaCha20-Poly1305(send_key, nonce=4×0||seq, aad=nodo/1||seq, item)
```

Handshake seal (not a record):

```text
eph_public 32
ciphertext = ChaCha20-Poly1305(handshake_key, nonce=12×0, aad=nodo/1, signed item)
```

`handshake_key` and `derive_keys` are in [Network](network.md#association-handshake).

## Identifiers

| name | size | source |
| --- | --- | --- |
| participant | 32 | Ed25519 public |
| box / eph | 32 | X25519 public |
| capability / session / commitment | 16 | UUID (v7 capability and session; v5 commitment) |
| network directory | 32 | `sha256(nodo/1)` |
| DHT infohash | 20 | `sha1(nodo/1)` |
| DHT node id | 20 | random per process |

## Session table

`domain.SESSION_TABLE` maps `(state, event) → (next, action)`. Actions: `accept`, `reject`, `discard`, `recompose`, `end`.

Events include the item names plus `session-open-repeat`, `step-in-repeat`, `step-out-incompatible`, `opener-loss`, `peer-loss`, `not-opener-request`, `not-holder-result`.

### `none`

| event | next | action |
| --- | --- | --- |
| `session-open` | `open` | accept |
| `session-open-repeat` | `none` | reject |
| `step-in`, `step-in-repeat`, `step-carry`, `step-out`, `step-out-incompatible` | `none` | reject |
| `session-progress` | `none` | discard |
| `session-suspend`, `session-close` | `none` | reject |
| `opener-loss` | `none` | end |
| `peer-loss` | `none` | discard |
| `not-opener-request`, `not-holder-result` | `none` | reject |

### `open`

| event | next | action |
| --- | --- | --- |
| `session-open`, `session-open-repeat` | `open` | reject |
| `step-in`, `step-carry`, `step-out`, `session-progress` | `open` | accept |
| `step-in-repeat` | `open` | reject |
| `step-out-incompatible` | `open` | recompose |
| `session-suspend` | `suspended` | accept |
| `session-close` | `closed` | accept |
| `opener-loss` | `closed` | end |
| `peer-loss` | `open` | recompose |
| `not-opener-request`, `not-holder-result` | `open` | reject |

### `suspended`

| event | next | action |
| --- | --- | --- |
| `session-open`, `session-open-repeat` | `open` | accept |
| any `step-*` | `suspended` | reject |
| `session-progress`, `session-suspend` | `suspended` | discard |
| `session-close` | `closed` | accept |
| `opener-loss` | `closed` | end |
| `peer-loss` | `suspended` | discard |
| `not-opener-request`, `not-holder-result` | `suspended` | reject |

### `closed`

| event | next | action |
| --- | --- | --- |
| `session-open`, `session-open-repeat`, any `step-*` | `closed` | reject |
| `session-progress`, `session-suspend`, `session-close`, `peer-loss` | `closed` | discard |
| `opener-loss` | `closed` | end |
| `not-opener-request`, `not-holder-result` | `closed` | reject |

## Rejection

`rejection.cause` is one of:

| cause | typical trigger |
| --- | --- |
| `item` | codec or field set |
| `signature` | missing, wrong length, or verify fail |
| `version` | version ≠ 1 |
| `composition-mismatch` | session-open does not match a complete composition |
| `authorization` | wrong hop, not a holder, or replayed open |
| `payload` | reserved |
| `identifier-missing` | required 16/32-byte id absent or wrong size |
| `budget` | offer limit above `cap` or reservations above limit |
| `association` | handshake/record misuse, convey with no route |
| `frame` | body without `nodo/1`, leftover after an unsigned item |

A clear `rejection` is decoded and ignored by the serve loop (`_apply_frame`). A record `rejection` is dispatched; `association` also ends the pair.

[nodo](index.md) · [Flow](flow.md) · [Network](network.md) · [Model](model.md) · [Session](session.md) · **Protocol**
