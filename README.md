# nodo

![nodo](docs/nodo.jpg)

**We are still developing this.** Test only. Not production. A prompt is not a usable model yet.

nodo exists because paying an API for every token is expensive, and running a full model on one machine is too heavy. Several computers form one inference model. Each disk keeps the part it created. A prompt walks the machines that are up: `embed → banks → head`. Weights do not travel.

Protocol `nodo/1`. Command `nodo`.

## Run

Python `>= 3.14`. `cryptography`, `numpy`.

```text
pip install .
nodo
```

Listens on TCP and UDP **9400**. Store: `$XDG_DATA_HOME/nodo`, `%LOCALAPPDATA%/nodo`, or `~/.local/share/nodo`.

## Status

### Done

- [x] `nodo` / `join()`: store, keys, lock, prompt
- [x] Compose: embed on the smallest id, head on the largest, banks in between
- [x] Frame, presence, association, records
- [x] Mainline DHT, same-host replica, `convey`
- [x] Session walk (`step-in` → carry → `step-out`)

### Next

- [ ] Reach a peer behind NAT or CGNAT (IPv4 only today; `convey` needs a hop that already has a route; `compose.yaml` still needs host 9400 open)
- [ ] IPv6
- [ ] Two real nodes on one host (second `nodo` on the same store is only a mailbox)
- [ ] A model that is not random `rng`
- [ ] A vocab that is not 256 raw bytes
- [ ] Generation that stops on purpose (not EOS=0 by chance, not a full `bound`)
- [ ] Errors that say what failed (`no model` is used for almost everything, including a prompt that does not fit `span` and a dead bind)
- [ ] Apply that asks for a missing file (`role-need` exists and is not sent)
- [ ] A Python version people already have
- [ ] Keep associations and the view across restart
- [ ] Tests

## Docs

[Overview](docs/index.md) · [Flow](docs/flow.md) · [Network](docs/network.md) · [Model](docs/model.md) · [Session](docs/session.md) · [Protocol](docs/protocol.md)

## Contribute

Everyone can contribute. Code, docs, issues, reviews, machines on other networks. Your name stays on the commits. [Contributors](https://github.com/LuizEduPP/nodo/graphs/contributors).

[Issues](https://github.com/LuizEduPP/nodo/issues) · [Discussions](https://github.com/LuizEduPP/nodo/discussions) · [Pull requests](https://github.com/LuizEduPP/nodo/pulls)

## Security

Do not open a public issue for a vulnerability. See [SECURITY.md](SECURITY.md).

## License

MIT. See [LICENSE](LICENSE).

Copyright © 2026 [Luiz Eduardo](https://github.com/LuizEduPP) · [LuizEduPP/nodo](https://github.com/LuizEduPP/nodo)
