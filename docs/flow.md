[nodo](index.md) · **Flow** · [Network](network.md) · [Model](model.md) · [Session](session.md) · [Protocol](protocol.md)

# Flow

nodo is one worldwide mesh. There is no site list and no machine cap. Each `nodo` on a different network announces `sha1(nodo/1)` on public Mainline DHT, associates with ids it hears, and keeps its own `bank-<hex>` on that disk. A prompt uses every accepted bank that is reachable in the current composition.

The diagrams below use five sites only as a drawing. The same path holds for tens or hundreds: more accepted offers means more banks in the walk, still one embed (smallest id) and one head (largest id), never both on the same disk.

## Topology

```mermaid
flowchart LR
    DHT[("Mainline DHT<br/>infohash sha1(nodo/1)")]
    A["site A<br/>bank-A"]
    B["site B<br/>embed + bank-B"]
    C["site C<br/>bank-C"]
    D["site D<br/>bank-D"]
    E["site E<br/>bank-E + head"]
    A --- DHT
    B --- DHT
    C --- DHT
    D --- DHT
    E --- DHT
    B -->|"TCP :9400"| C
    C -->|"TCP :9400"| E
    A -.->|"convey via C"| E
    D -.->|"convey via B"| C
```

Solid lines are a stored TCP route. Dashed lines are `convey`: the body is a full `nodo/1` frame, forwarded by an associate that already has a route to the subject. Replica files (`$XDG_RUNTIME_DIR`) are same-host only; they are not the world path.

`introduction` floods known subjects after every new association. A machine that never had a direct path still learns boxes and can handshake through a hop.

TCP `:9400` must be reachable from somewhere for a route to form. Two NATs with no reachable hop cannot associate. A site that is reachable (or that already associated with a reachable hop) is enough for the others to convey.

## Lifetime of one site

Every machine runs this. Discovery is not “find the other one”; it is “hear any number of ids, associate with each”.

```mermaid
flowchart TD
    start["nodo"] --> join["join(): store, keys, bank, offer"]
    join --> lock{"member.lock free?"}
    lock -->|no| client["access mailbox on this store"]
    lock -->|yes| world["listen TCP+UDP :9400"]
    world --> dht["get_peers / announce_peer on Mainline"]
    dht --> fan["fan presence to contacts and seeds"]
    fan --> hear{"new participant id?"}
    hear -->|no| serve["serve"]
    hear -->|yes| who{"own id smaller?"}
    who -->|yes| open["sealed association-open"]
    who -->|no| waitOpen["wait association-open"]
    open --> keys["record keys"]
    waitOpen --> keys
    keys --> first["offer, capability, presence, introductions"]
    first --> view["View.merge all fragments of capability()"]
    view --> n{"accepted offers >= 2?"}
    n -->|no| serve
    n -->|yes| parts["min id: embed<br/>max id: head"]
    parts --> ready{"embed and head on different holders?"}
    ready -->|no| serve
    ready -->|yes| complete["complete: embed + every accepted bank + head"]
    complete --> line{"prompt?"}
    line -->|no composition| serve
    line -->|yes| ask["_ask walks all commitments"]
    ask --> serve
```

`no model` is only the case with fewer than two accepted holders, or embed and head still on the same id. One more reachable machine anywhere is enough to open embed and head. Each further machine adds a bank, not a second embed.

## How sites meet

```mermaid
sequenceDiagram
    participant A as site A
    participant B as site B
    participant D as Mainline DHT
    participant C as site C
    participant E as site E
    A->>D: announce_peer :9400
    B->>D: announce_peer :9400
    C->>D: announce_peer :9400
    E->>D: announce_peer :9400
    D-->>A: values host:port
    D-->>B: values host:port
    A->>B: presence
    B->>A: presence
    A->>B: association if A id is smaller
    B->>C: presence + association
    C->>E: presence + association
    B->>C: introduction of A
    C->>E: introduction of A and B
    Note over A,E: each pair: smaller id opens<br/>then offer + capability
    Note over A,E: no TCP to E: convey through C
```

Pairwise initiation is always the smaller Ed25519 id. Mesh growth is introductions plus convey, not a star and not a configured peer list. `peers` on disk is only what DHT already returned.

## Generation across the mesh

The opener is whichever complete site read the prompt. It does not collect weights. It sends `session-open` to every holder, then one token at a time: embed → banks in holder-id order → head.

```mermaid
sequenceDiagram
    participant U as stdin / access
    participant O as opener
    participant Emb as embed site
    participant B1 as bank site 1
    participant B2 as bank site 2
    participant B3 as bank site N
    participant Hd as head site
    U->>O: line
    O->>O: bytes_vocab encode
    O->>Emb: session-open
    O->>B1: session-open
    O->>B2: session-open
    O->>B3: session-open
    O->>Hd: session-open
    loop each sequence until EOS or bound
        O->>Emb: step-in token
        Emb->>Emb: vocab row
        Emb->>O: step-carry
        O->>B1: step-carry
        B1->>B1: attend + append local bank
        B1->>O: step-carry
        O->>B2: step-carry
        B2->>B2: attend + append local bank
        B2->>O: step-carry
        O->>B3: step-carry
        B3->>B3: attend + append local bank
        B3->>O: step-carry
        O->>Hd: step-carry
        Hd->>Hd: block + argmax
        Hd->>O: step-out token
    end
    O->>U: decoded line
```

Each bank apply appends the carry on **that** disk only. Machines in different countries therefore accumulate different memory. The next prompt attends against whatever each site already stored. If a site is down, `View.merge` drops its bank (holder not accepted) and compose may reassign; the opener suspends with `recomposition-incomplete` until the composition is complete again.

A hop with no TCP uses the same `step-*` items inside `convey`. The opener still needs an association to every holder (`_ask` returns `no model` if a remote holder has no assoc).

[nodo](index.md) · **Flow** · [Network](network.md) · [Model](model.md) · [Session](session.md) · [Protocol](protocol.md)
