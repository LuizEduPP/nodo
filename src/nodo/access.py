from __future__ import annotations

import os
import time
import uuid
from pathlib import Path

from nodo.domain import NOTICE_WAIT


class AccessError(Exception):
    pass


def _inbox(state: Path) -> Path:
    return state / "access"


def _ready(state: Path) -> Path:
    inbox = _inbox(state)
    inbox.mkdir(parents=True, exist_ok=True)
    return inbox


def _joined(lines: list[str]) -> str:
    return "\n".join(lines) + ("\n" if lines else "")


def _hold(handle: int, take: bool) -> None:
    if os.name == "nt":
        import msvcrt

        msvcrt.locking(handle, msvcrt.LK_NBLCK if take else msvcrt.LK_UNLCK, 1)
    else:
        import fcntl

        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB if take else fcntl.LOCK_UN)


def parse_argv(argv: list[str]) -> str | None:
    if not argv:
        return None
    return " ".join(argv)


def lock(state: Path) -> int | None:
    state.mkdir(parents=True, exist_ok=True)
    path = state / "member.lock"
    handle = os.open(path, os.O_CREAT | os.O_RDWR, 0o644)
    try:
        _hold(handle, True)
    except OSError:
        os.close(handle)
        return None
    return handle


def unlock(handle: int | None) -> None:
    if handle is None:
        return
    try:
        _hold(handle, False)
    except OSError:
        pass
    os.close(handle)


def submit(state: Path, line: str) -> tuple[list[str], list[str]] | None:
    inbox = _ready(state)
    token = uuid.uuid4().hex
    cmd = inbox / f"{token}.cmd"
    out_path = inbox / f"{token}.out"
    err_path = inbox / f"{token}.err"
    done = inbox / f"{token}.done"
    cmd.write_text(line, encoding="utf-8")
    try:
        while True:
            if done.is_file():
                out = _lines(out_path)
                err = _lines(err_path)
                return out, err
            time.sleep(NOTICE_WAIT)
    finally:
        for path in (cmd, out_path, err_path, done):
            _gone(path)
    return None


def take(state: Path) -> list[tuple[str, str]]:
    inbox = _inbox(state)
    if not inbox.is_dir():
        return []
    found = []
    for cmd in sorted(inbox.glob("*.cmd")):
        try:
            found.append((cmd.stem, cmd.read_text(encoding="utf-8")))
            cmd.unlink()
        except OSError:
            continue
    return found


def reply(state: Path, token: str, out: list[str], err: list[str]) -> None:
    inbox = _ready(state)
    (inbox / f"{token}.out").write_text(_joined(out), encoding="utf-8")
    (inbox / f"{token}.err").write_text(_joined(err), encoding="utf-8")
    (inbox / f"{token}.done").write_text("", encoding="utf-8")


def _gone(path: Path) -> None:
    try:
        path.unlink()
    except OSError:
        pass


def _lines(path: Path) -> list[str]:
    if not path.is_file():
        return []
    text = path.read_text(encoding="utf-8")
    if not text:
        return []
    return text.splitlines()
