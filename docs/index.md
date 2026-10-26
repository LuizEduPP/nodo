**nodo** · [Flow](flow.md) · [Network](network.md) · [Model](model.md) · [Session](session.md) · [Protocol](protocol.md)

# nodo

nodo is a mesh participant. The same program runs on any number of machines, on different networks, in different places. Together they are one inference model. There is no site file and no machine cap. The protocol name is `nodo/1`. The product is the `nodo` command (`python -m nodo`), which calls `join()` and runs a `Participant`.

There is no product JSON configuration. Constants live in `src/nodo/domain.py`. Python `>= 3.14`. Dependencies: `cryptography`, `numpy`.

## What it does

Each machine that joins:

1. Creates or reuses a local store (identity, box, publication).
2. Publishes a **bank** — a growing table of key/value vectors written on that disk only.
3. Announces an **offer** (CPU or GPU, and a budget of `quantity // 100`).
4. Listens on TCP and UDP port **9400**, announces `sha1(nodo/1)` on the public BitTorrent Mainline DHT, and associates with every id it hears — including hosts it can only reach through `convey`.
5. When two or more accepted offers exist (anywhere on the mesh), the smallest Ed25519 id creates **embed**, and the largest (if different) creates **head**. Those two files must not live on the same disk. Every other accepted machine keeps only its bank.

A prompt is encoded on the opener, then walked across the commitments in order: embed → all accepted banks (holder-id order) → head. Each holder applies only the file on its own disk. Weight files are not assembled onto one machine and do not cross the wire on the product path.

One machine alone has only a bank. Composition is incomplete, so a prompt prints `no model`. The third, tenth, or hundredth machine does not add another embed; it adds another bank.

## Running

```text
nodo
```

`join()` creates the store if needed, writes Ed25519 and X25519 keys if they are missing, creates the local bank, and returns the config that `Participant` uses. The process then takes `state/member.lock` and enters the serve loop.

| how you start it | what happens |
| --- | --- |
| `nodo` on a TTY, lock free | mesh member; prompt `>`; each line is a generation request |
| `nodo <text>` , lock free | same member; that text is the first request; then serve |
| `nodo` on a TTY, lock taken | client of the member that holds the lock; same `>` prompt; each line is written to `state/access` |
| `nodo <text>` , lock taken | one-shot client; waits for `state/access/<token>.done` |

A second process on the same store does not open another mesh. It talks to the first through the access mailbox.

`compose.yaml` runs the same command, publishes TCP and UDP 9400, and sets `XDG_DATA_HOME=/var/lib` so the store is `/var/lib/nodo`.

## Store

Root, first match:

1. `$XDG_DATA_HOME/nodo`
2. `%LOCALAPPDATA%/nodo`
3. `$HOME/.local/share/nodo`

| path | contents |
| --- | --- |
| `ed25519` | 32-byte Ed25519 seed (signing identity) |
| `box` | 32-byte X25519 seed (association box) |
| `state/member.lock` | exclusive lock of the mesh member |
| `state/capability.id` | 16-byte capability id (UUID version 7) |
| `state/access/` | mailbox: `<token>.cmd`, `.out`, `.err`, `.done` |
| `state/publication/` | files received over `role-carry` (not used by `join()` apply) |
| `peers` | remembered `host:port` lines |
| `publication/vocabulary` | `nodo/v` byte vocabulary |
| `publication/bank-<hex>` | this participant's bank (`<hex>` is its 32-byte id) |
| `publication/embed` | token embedding, only on the lowest accepted id |
| `publication/head` | attention + FF + vocab projection, only on the highest accepted id |
| `publication/declaration` | JSON snapshot of the local roles (written by `create` / `open_part`) |

Replica files for same-host processes sit under `$XDG_RUNTIME_DIR/nodo/<network hex>/` (or `%LOCALAPPDATA%`), not in the data store. See [Network](network.md).

## Budget

`measure.cap(quantity)` is `quantity // 100`. That value is both the announced offer limit and the local publication budget.

- CPU host: `ram_host()` from `SC_PHYS_PAGES` / page size (or Windows `GlobalMemoryStatusEx`).
- GPU host: first working source among `nvidia-smi`, DRM `mem_info_vram_total`, DXGI, or Darwin `system_profiler`. If several GPUs exist, `join()` picks the smallest device id and announces that VRAM.

`span` (and `bound`) are `fit_span` of one layer of KV state against that budget: `span = (budget - 4) // 1024` for the native architecture. A prompt of `n` tokens is rejected unless `n + bound <= span`.

## Capability

Every `join()` publication uses the same capability id: UUID version 7 derived from the first 16 bytes of `sha256(nodo/1)`, with the RFC 4122 version/variant bits set (`domain.capability()`). Fragments from different machines merge because they share that id.

## What happens on a prompt

1. The opener takes the first complete composition (`View.complete`).
2. It encodes the request with `bytes_vocab()` (256 byte tokens, BPE code, no merges).
3. It opens a session (`session-open` with those commitments) and sends `step-in` to the embed holder.
4. Embed looks up the token row and returns a 512-byte carry (`HIDDEN` floats, f16 big-endian).
5. Each bank attends the carry against its stored pairs, **appends** the carry as a new pair, and forwards a carry.
6. Head runs one attention+FF block and returns `step-out` with an argmax token.
7. After the prompt is consumed, generated tokens are fed back as the next `step-in`. Stop at `EOS=0` or when `generated` reaches `bound`.
8. The opener decodes the generated tokens as UTF-8 (dropping a trailing EOS) and prints one line.

Details: [Session](session.md).

`nodo.pack` can write a Llama slice (`CODE=1`). `join()` never publishes or loads that slice.

## Reading order

1. This page — product, store, one-page generation.
2. [Flow](flow.md) — lifetime, mesh, generation diagrams.
3. [Network](network.md) — frames, DHT, presence, association, records.
4. [Model](model.md) — parts, composition, apply, on-disk layout.
5. [Session](session.md) — opener/holder walk, bank growth, suspend.
6. [Protocol](protocol.md) — binary items, signatures, session table, rejection.

## Source map

| module | responsibility |
| --- | --- |
| `domain` | constants, `network()`, `infohash()`, `capability()` |
| `config` | `join()`, store root, adopt publication |
| `model` | create bank, open embed/head, declaration |
| `slice` | `nodo/s` header, `apply` / `apply_model` |
| `vocabulary` | `nodo/v`, `bytes_vocab`, encode/decode |
| `view` | offers + declarations → merged capability |
| `composition` | assign holders, `complete` |
| `participant` | serve loop, ask, session, association |
| `placement` | replica, TCP 9400, DHT fan-out |
| `dht` | Mainline KRPC/bencode |
| `item` / `messages` | binary codec, Ed25519 |
| `association` / `record` | handshake and sequenced AEAD |
| `access` | lock and mailbox |
| `measure` | RAM/VRAM and `cap` |
| `pack` | optional Llama writer, unused by `join()` |

**nodo** · [Flow](flow.md) · [Network](network.md) · [Model](model.md) · [Session](session.md) · [Protocol](protocol.md)
