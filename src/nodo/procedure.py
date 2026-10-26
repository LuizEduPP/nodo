from __future__ import annotations

from nodo.domain import (
    BOXED,
    EMPTY,
    HEARD,
    PENDING,
    REC_GAP,
    REC_LEFTOVER,
    REC_NONE,
    REC_PRESENCE,
    REC_REPLAY,
    REC_UNKNOWN,
    SESSION_TABLE,
    WAITING,
)


class Unspecified(Exception):
    pass


def start() -> tuple:
    vacant = (EMPTY, 0, 0, 0, 0)
    return (vacant, vacant, 0, 0, 0, 0, 0, 0)


def session_outcome(state: str, event: str) -> tuple[str, str]:
    try:
        return SESSION_TABLE[(state, event)]
    except KeyError as exc:
        raise Unspecified((state, event)) from exc


def inbound(world: tuple, action: str) -> tuple:
    handler = {
        "emit_l": lambda: _emit(world, 0),
        "emit_g": lambda: _emit(world, 1),
        "lose_notice_l": lambda: _lose(world, 2),
        "lose_notice_g": lambda: _lose(world, 3),
        "lose_open": lambda: _lose(world, 4),
        "lose_accept": lambda: _lose(world, 5),
        "lose_record_l": lambda: _lose(world, 6),
        "lose_record_g": lambda: _lose(world, 7),
        "take_notice_l": lambda: _take_notice(world, 1),
        "take_notice_g": lambda: _take_notice(world, 0),
        "take_open": lambda: _take_open(world),
        "take_accept": lambda: _take_accept(world),
        "take_record_l": lambda: _take_record(world, 1),
        "take_record_g": lambda: _take_record(world, 0),
        "foreign": lambda: world,
        "oversize": lambda: world,
        "open_self": lambda: world,
        "open_greater": lambda: world,
        "accept_without_pending": lambda: _accept_without_pending(world),
        "type_before_keys": lambda: _before_keys(world),
        "clear_new_box": lambda: _clear_new_box(world),
        "same_eph": lambda: _same_eph(world),
        "different_eph": lambda: _different_eph(world),
        "seq_gap": lambda: _seq(world, REC_GAP),
        "seq_replay": lambda: _seq(world, REC_REPLAY),
        "unknown_type": lambda: _seq(world, REC_UNKNOWN),
        "leftover": lambda: _seq(world, REC_LEFTOVER),
    }.get(action)
    if handler is None:
        raise Unspecified(action)
    return handler()


def enabled(world: tuple) -> list[str]:
    actions = ["emit_l", "emit_g", "foreign", "oversize", "open_self", "open_greater", "type_before_keys"]
    L, G, nl, ng, op, ac, rl, rg = world
    if nl:
        actions.extend(["lose_notice_l", "take_notice_l"])
    if ng:
        actions.extend(["lose_notice_g", "take_notice_g"])
    if op:
        actions.extend(["lose_open", "take_open"])
    if ac:
        actions.extend(["lose_accept", "take_accept"])
    if rl:
        actions.extend(["lose_record_l", "take_record_l"])
    if rg:
        actions.extend(["lose_record_g", "take_record_g"])
    if L[0] in {PENDING, WAITING, HEARD} or G[0] in {PENDING, WAITING, HEARD}:
        actions.append("clear_new_box")
    if L[0] != PENDING:
        actions.append("accept_without_pending")
    if G[0] in {WAITING, HEARD}:
        actions.extend(["same_eph", "different_eph"])
    if L[0] in {WAITING, HEARD} or G[0] in {WAITING, HEARD}:
        actions.extend(["seq_gap", "seq_replay", "unknown_type", "leftover"])
    return actions


def stable(world: tuple) -> bool:
    L, G, nl, ng, op, ac, rl, rg = world
    if nl or ng or op or ac or rl or rg:
        return True
    if L[0] == HEARD and G[0] == HEARD:
        return True
    if L[0] not in {WAITING, HEARD} and G[0] not in {WAITING, HEARD}:
        return True
    if L[0] in {EMPTY, BOXED, PENDING, WAITING} or G[0] in {EMPTY, BOXED, PENDING, WAITING}:
        return True
    return False


def _set(world: tuple, who: int, side: tuple) -> tuple:
    parts = list(world)
    parts[who] = side
    return tuple(parts)


def _chan(world: tuple, index: int, value: int) -> tuple:
    parts = list(world)
    parts[index] = value
    return tuple(parts)


def _emit(world: tuple, who: int) -> tuple:
    phase = world[who][0]
    if phase == HEARD:
        return world
    octets = world[who][2] or 1
    side = (world[who][0], world[who][1], octets, world[who][3], world[who][4])
    world = _set(world, who, side)
    world = _chan(world, 2 + who, octets)
    if phase == PENDING and who == 0 and world[0][3]:
        world = _chan(world, 4, world[0][3])
    return world


def _lose(world: tuple, index: int) -> tuple:
    if world[index] == 0:
        raise Unspecified("lose")
    return _chan(world, index, 0)


def _take_notice(world: tuple, who: int) -> tuple:
    src = 1 - who
    octets = world[2 + src]
    if octets == 0:
        raise Unspecified("notice")
    world = _chan(world, 2 + src, 0)
    return _presence(world, who, octets, octets, True)


def _presence(world: tuple, who: int, octets: int, box: int, clear: bool) -> tuple:
    phase, held_box, held_octets, eph, peer_eph = world[who]
    if held_octets == octets and octets != 0:
        if phase == PENDING and clear and who == 0:
            return _chan(world, 4, eph or 1)
        return world
    pending_or_keys = phase in {PENDING, WAITING, HEARD}
    if held_box not in {0, box} and clear and pending_or_keys:
        return world
    if held_box not in {0, box} and pending_or_keys and not clear:
        world = _set(world, who, (BOXED, box, octets, 0, 0))
        world = _drop_pair(world, who)
        return _consider(world, who)
    world = _set(world, who, (BOXED if phase == EMPTY else phase, box, octets, eph, peer_eph))
    if phase == EMPTY:
        other = 1 - who
        if world[other][0] != HEARD:
            world = _chan(world, 2 + who, world[who][2] or 1)
    return _consider(world, who)


def _consider(world: tuple, who: int) -> tuple:
    phase = world[who][0]
    if phase in {WAITING, HEARD}:
        return world
    if phase == PENDING:
        if who == 0:
            return _chan(world, 4, world[0][3] or 1)
        return world
    if who == 1:
        return world
    eph = world[0][3] or 1
    world = _set(world, 0, (PENDING, world[0][1] or 1, world[0][2] or 1, eph, world[0][4]))
    return _chan(world, 4, eph)


def _drop_pair(world: tuple, who: int) -> tuple:
    other = 1 - who
    ophase, obox, ooct, oeph, opeer = world[other]
    if ophase in {WAITING, HEARD, PENDING}:
        world = _set(world, other, (BOXED if obox else EMPTY, obox, ooct, 0, 0))
    world = _chan(world, 4, 0)
    world = _chan(world, 5, 0)
    world = _chan(world, 6, 0)
    world = _chan(world, 7, 0)
    return world


def _take_open(world: tuple) -> tuple:
    if world[4] == 0:
        raise Unspecified("open")
    eph = world[4]
    world = _chan(world, 4, 0)
    L = world[0]
    if L[0] != EMPTY and L[3] and eph != L[3] and world[1][0] in {WAITING, HEARD}:
        pass
    G = world[1]
    if G[0] in {WAITING, HEARD} and G[4] == eph:
        return _chan(world, 5, G[3] or 1)
    if G[0] in {WAITING, HEARD} and G[4] != eph:
        world = _drop_pair(world, 1)
        G = (BOXED, world[1][1] or 1, world[1][2] or 1, 0, 0)
        world = _set(world, 1, G)
    accept = 1
    world = _set(world, 1, (WAITING, world[1][1] or 1, world[1][2] or 1, accept, eph))
    return _chan(world, 5, accept)


def _take_accept(world: tuple) -> tuple:
    if world[5] == 0:
        raise Unspecified("accept")
    ac = world[5]
    world = _chan(world, 5, 0)
    if world[0][0] != PENDING:
        return world
    L = (WAITING, world[0][1] or 1, world[0][2] or 1, world[0][3] or 1, ac)
    world = _set(world, 0, L)
    return _chan(world, 6, REC_PRESENCE)


def _take_record(world: tuple, who: int) -> tuple:
    index = 6 if who == 1 else 7
    kind = world[index]
    if kind == REC_NONE:
        raise Unspecified("record")
    world = _chan(world, index, 0)
    phase = world[who][0]
    if phase not in {WAITING, HEARD}:
        return world
    if kind == REC_GAP or kind == REC_UNKNOWN or kind == REC_LEFTOVER:
        dropped = (BOXED if world[who][1] else EMPTY, world[who][1], world[who][2], 0, 0)
        world = _set(world, who, dropped)
        return _drop_pair(world, who)
    if kind == REC_REPLAY:
        return world
    if phase == WAITING:
        world = _set(world, who, (HEARD, world[who][1], world[who][2], world[who][3], world[who][4]))
        other = 1 - who
        if world[other][0] == WAITING and world[7 if other == 0 else 6] == REC_NONE:
            world = _chan(world, 7 if other == 0 else 6, REC_PRESENCE)
        return world
    return world


def _accept_without_pending(world: tuple) -> tuple:
    if world[0][0] == PENDING:
        return world
    return world


def _before_keys(world: tuple) -> tuple:
    if world[0][0] in {WAITING, HEARD} or world[1][0] in {WAITING, HEARD}:
        return world
    return world


def _clear_new_box(world: tuple) -> tuple:
    if world[0][0] in {PENDING, WAITING, HEARD}:
        return _presence(world, 0, (world[0][2] % 2) + 1, (world[0][1] % 2) + 1 if world[0][1] else 2, True)
    if world[1][0] in {PENDING, WAITING, HEARD}:
        return _presence(world, 1, (world[1][2] % 2) + 1, (world[1][1] % 2) + 1 if world[1][1] else 2, True)
    return world


def _same_eph(world: tuple) -> tuple:
    if world[1][0] not in {WAITING, HEARD}:
        return world
    return _chan(world, 5, world[1][3] or 1)


def _different_eph(world: tuple) -> tuple:
    if world[1][0] not in {WAITING, HEARD}:
        return world
    eph = 2 if world[1][4] != 2 else 1
    world = _chan(world, 4, eph)
    return _take_open(world)


def _seq(world: tuple, kind: int) -> tuple:
    if world[1][0] in {WAITING, HEARD}:
        world = _chan(world, 6, kind)
        return _take_record(world, 1)
    if world[0][0] in {WAITING, HEARD}:
        world = _chan(world, 7, kind)
        return _take_record(world, 0)
    return world


def _walk(begin: tuple, enabled_fn, inbound_fn, stable_fn, reached_fn) -> tuple[set[tuple], bool]:
    seen: set[tuple] = set()
    stack = [begin]
    reached = False
    while stack:
        world = stack.pop()
        if world in seen:
            continue
        seen.add(world)
        if reached_fn(world):
            reached = True
        if not stable_fn(world):
            raise Unspecified(("deadlock", world))
        for action in enabled_fn(world):
            nxt = inbound_fn(world, action)
            if nxt not in seen:
                stack.append(nxt)
    return seen, reached


def explore() -> tuple[set[tuple], bool]:
    return _walk(
        start(),
        enabled,
        inbound,
        stable,
        lambda world: world[0][0] == HEARD and world[1][0] == HEARD,
    )


def flood_start() -> tuple:
    stored = ((0, 0, 0), (0, 0, 0), (0, 0, 0))
    keys = ((0, 0, 0), (0, 0, 0), (0, 0, 0))
    return (stored, keys, (0, 0, 0), (), (0, 0, 0))


def flood_inbound(world: tuple, action: str) -> tuple:
    stored, keys, medium, floods, emitted = world
    if action.startswith("emit_"):
        who = int(action[-1])
        if emitted[who]:
            return world
        bits = list(medium)
        bits[who] = 1
        sent = list(emitted)
        sent[who] = 1
        return (stored, keys, tuple(bits), floods, tuple(sent))
    if action.startswith("take_medium_"):
        who = int(action[-1])
        src = int(action[-3])
        if medium[src] == 0:
            raise Unspecified(action)
        return _flood_store(stored, keys, medium, floods, emitted, who, src)
    if action.startswith("take_flood_"):
        item = _flood_item(action)
        if item not in floods:
            raise Unspecified(action)
        left = tuple(x for x in floods if x != item)
        return _flood_store(stored, keys, medium, left, emitted, item[1], item[2])
    raise Unspecified(action)


def flood_enabled(world: tuple) -> list[str]:
    stored, keys, medium, floods, emitted = world
    actions = []
    for who in range(3):
        if not emitted[who]:
            actions.append("emit_" + str(who))
    for src in range(3):
        if medium[src]:
            for who in range(3):
                if who != src:
                    actions.append("take_medium_" + str(src) + "_" + str(who))
    for item in floods:
        tag = str(item[0]) + str(item[1]) + str(item[2])
        actions.append("take_flood_" + tag)
    return actions


def flood_stable(_world: tuple) -> bool:
    return True


def _flood_item(action: str) -> tuple[int, int, int]:
    tag = action.rsplit("_", 1)[-1]
    if len(tag) != 3:
        raise Unspecified(action)
    return (int(tag[0]), int(tag[1]), int(tag[2]))


def _flood_store(
    stored: tuple,
    keys: tuple,
    medium: tuple,
    floods: tuple,
    emitted: tuple,
    who: int,
    subject: int,
) -> tuple:
    if who == subject:
        return (stored, keys, medium, floods, emitted)
    grid = [list(row) for row in stored]
    bind = [list(row) for row in keys]
    pending = set(floods)
    first = grid[who][subject] == 0
    grid[who][subject] = 1
    if first and grid[subject][who]:
        bind[who][subject] = 1
        bind[subject][who] = 1
        for other in range(3):
            if other in {who, subject}:
                continue
            if grid[who][other]:
                pending.add((who, subject, other))
            if grid[subject][other]:
                pending.add((subject, who, other))
    if first:
        for other in range(3):
            if other in {who, subject}:
                continue
            if bind[who][other]:
                pending.add((who, other, subject))
    return (
        tuple(tuple(row) for row in grid),
        tuple(tuple(row) for row in bind),
        medium,
        tuple(sorted(pending)),
        emitted,
    )


def explore_flood() -> tuple[set[tuple], bool]:
    def mesh(world: tuple) -> bool:
        stored, keys, _medium, _floods, _emitted = world
        return all(keys[i][j] for i in range(3) for j in range(3) if i != j) and all(
            stored[i][j] for i in range(3) for j in range(3) if i != j
        )

    return _walk(flood_start(), flood_enabled, flood_inbound, flood_stable, mesh)
