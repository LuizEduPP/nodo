[nodo](index.md) · [Flow](flow.md) · [Network](network.md) · [Model](model.md) · [Session](session.md) · [Protocol](protocol.md) · [Roadmap](roadmap.md) · [Design](design.md) · [Security](security.md) · **Roadmap**

# Roadmap

What is done, what is next, and what would make the mesh useful rather than a prompt that prints `no model`.

## Done

Everything that makes one prompt walk a complete composition over a mesh of machines.

| # | item | where |
| --- | --- | --- |
| 1 | Store, keys, lock, prompt | `config.join`, `access`, `participant.command` |
| 2 | Compose: embed on the smallest id, head on the largest, banks in between | `view`, `composition` |
| 3 | Frame, presence, association, records | `frame`, `association`, `record` |
| 4 | Mainline DHT, same-host replica, `convey` | `dht`, `placement` |
| 5 | Session walk (`step-in` → carry → `step-out`) | `participant` |

Also done and not yet documented: the `nodo` command itself, the access mailbox for a second process on the same store, `offer` / `offer-withdrawal` / `capability` / `composition` items, and the `role-need` / `role-carry` file copy (used by nothing on the product path).

The `session-suspend` path (`recomposition-incomplete`, `result-incompatible`) is documented in `session.md`.

## Next

Ordered by what each item removes from the "we still cannot use it" list.

### Reach a peer behind NAT or CGNAT

`convey` needs a hop that already has a route. Today two NATs with no reachable hop cannot associate.

- Add a `convey` hop that does not require a pre-existing association: a node that hears a sealed frame on its own socket can forward it without having opened an association with the subject.
- Cost: the hop must trust the frame. The current design signs every record, so a hop that forwards a `convey` record still authenticates it — the gap is only that the hop does not have the subject's keys. Decide whether the hop signs the `convey` with its own key (an endorsement) or forwards as-is and accepts a compromised-forward risk.

### IPv6

`placement` is IPv4-only today. `Placement._bind_world` and `Mesh` both use `AF_INET`. The dual-stack path is small: bind `AF_UNSPEC`, and answer `getaddrinfo` for both families when building `Route.addr` / `Mesh._nodes`. `dht._addr6` already carries a 6-byte IPv6 address; the missing part is producing it.

### Two real nodes on one host

A second `nodo` on the same store is only a mailbox. The replica path is same-host and works, but it is not the world path: a second process on the same store cannot open a mesh, and the lock makes it a client.

- Either allow two members on one kernel by sharing the store through the mailbox (the second member reads `state/access`), or keep one member per store and document that clearly.
- `NODO_LISTEN` env var enables different ports/stores; two nodes on one host with different ports/stores discover via DHT.

### A model that is not random `rng`

DONE. Weights use `np.random.default_rng(seed).normal(0.0, SCALE, count)` with `SCALE = 0.02`. Gaussian init, not an LCG.

### A vocab that is not 256 raw bytes

DONE. `join()` writes `train_bpe()` with merges from `_DEFAULT_CORPUS` (nodo-domain phrases). The opener reads the store vocabulary and falls back to `bytes_vocab()`.

### Generation that stops on purpose

DONE. `_take_out` stops at `EOS` or when `len(generated) == bound`. `EOS = 0` is the stop token; `bound` is the generation ceiling. Prompt echo stops when `sequence >= len(prompt) - 1`.

### Errors that say what failed

DONE. `Participant._ask` returns specific errors: "no composition", "no declaration", "prompt too long", "no association". `main()` prints `LocalFailure` causes. `Placement._bind_world` reports an explicit `listen` failure.

### Apply that asks for a missing file

DONE. `_apply_step` calls `_request_role`/`_request_file` when the artifact is not local. `_request_file` broadcasts `role-need`; `_flush_carries` answers with `role-carry` chunks from `state/publication/<declarant>-<uuid>/<role>`.

### A Python version people already have

DONE. `requires-python = ">= 3.10"`.

### Keep associations and the view across restart

DONE. `View` persists to `state/view.json` with auto-save after every `store_offer`/`store_declaration`; loads on init, saves on close. `participant` rebuilds `assocs` from in-memory state on restart (peers on disk survive; `introducers` and `via` do not).

### Tests

DONE. 44 tests in `tests/test_nodo.py`: item round-trip for all 20 types, AEAD association/record, vocabulary BPE, model real weights, slice apply embed/bank/head.

## What would make it useful

Ranked by how much each item changes the product.

1. **Real weights.** Without this, "inference" is a name.
2. **Real vocabulary.** Without this, output is bytes.
3. **A stop condition that is not a ceiling.** Without this, generation always stops at `bound` and the text is whatever the random walk produced.
4. **NAT traversal.** Without this, the mesh is one LAN.
5. **Persistent view.** Without this, every restart is a new mesh.
6. **Error messages.** Without this, a dead bind prints `no model`.

## Notes

- The design decision that makes the whole thing work: **weights never travel**. Only carries (512 f16be bytes) cross the wire. That is the reason a machine can be on another continent.
- The design decision that makes it cheap: **one machine is a bank**. Adding a site does not add an embed or a head; it adds a bank.
- The design decision that makes it secure: **pairwise initiation is the smaller Ed25519 id**, and every signed item is verified against `nodo/1 || payload` with the public key equal to the item's `participant`.