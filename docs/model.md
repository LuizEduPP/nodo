[nodo](index.md) · [Flow](flow.md) · [Network](network.md) · **Model** · [Session](session.md) · [Protocol](protocol.md)

# Model

The native model is `CODE_MODEL = 2` under magic `nodo/s`. It is not Llama. `join()` creates and applies only this code.

Weights stay on the machine that wrote them. That machine may be on another network in another country. Inference is a walk of commitments across the current accepted set. The opener sends tokens and carries; each holder reads its local file. Adding a site adds a bank, not a copy of embed or head.

## Architecture

Fixed in `domain.py` and written into every native slice header:

| name | value | role |
| --- | --- | --- |
| `HIDDEN` | 256 | residual width |
| `HEADS` / `KV` | 8 / 8 | attention heads (GQA groups = heads) |
| `DIM` | 32 | head dimension (`HEADS * DIM == HIDDEN`) |
| `FF` | 1024 | MLP inner width |
| `VOCAB` | 256 | token table size |
| `RMS` | `1e-6` | RMSNorm epsilon |
| `ROPE` | `10000` | RoPE base |
| `EOS` | 0 | stop token |
| `SCALE` | `0.02` | init scale for `rng` |
| `width` | `HIDDEN * 2` = 512 | carry on the wire (f16be) |

`span` and `bound` are not architectural constants. They are computed from the host budget (`fit_span`). For this architecture the KV reservation per position is 1024 bytes, so `span = (budget - 4) // 1024`. `bound` equals `span` on the publication `join()` writes. `span >= bound` is required by the capability codec.

## Vocabulary

Magic `nodo/v`. `join()` writes `bytes_vocab()`:

- code `CODE_BPE = 2`
- 256 pieces: GPT-2-style byte-to-char maps, each stored as UTF-8
- no merges

`encode` therefore maps each input byte to one token. `decode` concatenates pieces and reverses the byte map. The opener always calls `bytes_vocab()` in memory; it does not read a peer's `vocabulary` file for generation.

Token `0` is EOS.

## Parts

| file | `kind` | who writes it | reservation | what apply does |
| --- | --- | --- | --- | --- |
| `embed` | `KIND_EMBED = 1` | smallest accepted id, once two or more offers exist | 4 bytes | first step: vocab row → carry |
| `bank-<hex>` | `KIND_BANK = 4` | every participant, in `create` | 4 bytes | attend stored pairs; append the query |
| `head` | `KIND_HEAD = 3` | largest accepted id, if it is not also the smallest | `state_octets(1, span, 8, 32)` | last step: one block + argmax |

`<hex>` is the 32-byte participant id. There is one bank file per participant, not one shared bank. Concurrent sites do not share an append offset; each file grows on its own disk. `View.merge` keeps every `bank-*` whose holder is still `accepted`, sorted by holder id. A site that leaves drops out of the next compose.

### Create versus open

`model.create` (used by `join()` when the bank is missing):

1. `_split`: if `embed` and `head` both exist, **unlink both**.
2. Write `vocabulary`.
3. Write an empty bank (`count = 0`).
4. Commit a declaration that lists only the roles whose files are present and have `code == CODE_MODEL`.

`model.open_part` (called from `_ensure_parts` after the view shows two or more accepted offers):

- `embed`: refuse if `head` exists on this disk; else write `VOCAB*HIDDEN + 2*HIDDEN*HIDDEN` f16 weights, seed `(id[:4] as u32) XOR 1`.
- `head`: refuse if `embed` exists; else write `4*H*H + 2*H + 3*H*FF + H + VOCAB*H` weights, seed `XOR 2`.
- Any other name: no-op.

`open_part` does **not** call `_split`. That is why a leftover pair from an older seed is deleted in `create`/`load`, not at open.

`_ensure_parts` only creates a missing name, and only on the participant that owns that extreme id among `accepted ∪ {self}`:

```text
if "embed" not in names and self == min(accepted): open_part("embed")
if "head"  not in names and self == max(accepted) and self != min: open_part("head")
```

After a successful open, the declaration is refreshed and blasted to associations.

## Capability merge

`View.merge(capability)` folds every stored declaration with that id.

1. `width` / `bound` / `span` from the first fragment; overwritten by a fragment that lists `head`.
2. **embed** — among fragments that list it, keep the one whose `holder` is smallest.
3. **banks** — every `bank-*` whose holder currently has an accepted offer, sorted by holder id.
4. **head** — among fragments that list it, keep the one whose `holder` is largest.
5. Declarant of the merged capability is the embed holder, or the smallest declarant if embed is still missing.

`compose` then assigns each role:

- Candidate set is `role["holder"]` if present, else every offer.
- Offer must be `accepted`, match an optional `class` (`cpu`/`gpu`), have reservation fields, and have enough free budget (`effective_budget` minus foreign commitments minus roles already assigned on that participant).
- Prefer the previous holder for that role if still eligible; otherwise `min(eligible, key=sha256(participant || capability_id))`.

`complete` is true only when every role was assigned **and** embed and head sit on different participants (`_parts_apart`). That is the rule that makes a single node print `no model`.

## Apply (`CODE_MODEL`)

`slice.apply` dispatches to `apply_model` when `meta["code"] == 2`.

Shared checks (`_ends`): `width` must be 512, `0 <= position < span`, `0 <= index < count`.

| step | input | computation | output |
| --- | --- | --- | --- |
| first (`embed`) | `token` | row `token` of the vocab table (offset `HEADER`, `HIDDEN` f16be) | carry, unless this is also the last step (then refuse) |
| middle (`bank`) | carry | softmax attention of the query against stored keys; values weighted-sum; **append** `(query, query)` to the file | carry + extra |
| last (`head`) | carry | one `_block` (QKV, RoPE, attend+KV cache, O, SiLU MLP) then argmax against the vocab projection | `token` |

Bank attention (`_bank_read`):

```text
pairs[i] = (key_i, value_i)          # each HIDDEN f32
scores   = keys @ query / sqrt(HIDDEN)
weights  = softmax(scores)
extra    = weights @ values
```

`append_bank` updates the `u32` count at `HEADER` and the `weights` field at byte 44. The new pair is the carry both as key and as value. That is how each machine cedes information: every apply that hits its bank grows the file.

Head session state is `Held.state`: 4 bytes of used length plus `2 * span * KV * DIM` f16 slots (K and V). `reservation_of` sizes that buffer. Embed and bank reservations are 4 bytes (counter only); they do not hold KV cache.

A holder that does not have the file locally (`_artifact` / `_file_path`) does not apply. `role-need` / `role-carry` can copy a file in `CARRY = 1 MiB` chunks into `state/publication/<declarant hex>-<uuid>/`, but `_apply_step` never requests that copy. Product inference uses only files created on that disk.

## Slice on disk

52-byte header (`HEADER`):

| offset | size | field |
| --- | --- | --- |
| 0 | 6 | `nodo/s` |
| 6 | 1 | `code` (`1` Llama, `2` native) |
| 7 | 1 | `kind` |
| 8 | 4×7 | `hidden, vocab, layers, heads, kv, dim, ff` (u32be) |
| 36 | 4 | `rms` f32be |
| 40 | 4 | `rope` f32be |
| 44 | 8 | `weights` octet count (u64be) |

`inspect` rejects `heads * dim != hidden`, `heads % kv != 0`, non-positive rms/rope, and `CODE=1` with `KIND_BANK`.

Weights after the header are f16 big-endian.

### Bank payload

```text
HEADER
u32be count
count × (key[HIDDEN] f16be || value[HIDDEN] f16be)
```

`bank_octets(hidden, count) = 4 + count * 2 * hidden * 2`.

### Embed payload

`layers = 0`. Floats: vocab table (`VOCAB * HIDDEN`) then two `HIDDEN × HIDDEN` maps. Apply uses only the table.

### Head payload

`layers = 1`. Maps in apply order (`_model_maps`): four `HIDDEN × HIDDEN` (Q, K, V, O), two `HIDDEN` (norms), three FF maps (`FF × HIDDEN`, `HIDDEN × FF`, `FF × HIDDEN`). After those, a `HIDDEN` skip and the `VOCAB × HIDDEN` projection used by `_argmax`.

## Llama (`CODE = 1`)

`slice.apply` still runs complete / embed / stack / head for `CODE=1` (Llama layout, `LAYER` names in `domain.py`). `nodo.pack` writes that format from a local checkpoint when `NODO_MODELS` points at one.

`join()` does not call `pack`, does not set `CODE=1` on publication, and `_local` only accepts `CODE_MODEL`. A leftover Llama tree under `publication/` is ignored for the native declaration.

[nodo](index.md) · [Flow](flow.md) · [Network](network.md) · **Model** · [Session](session.md) · [Protocol](protocol.md)
