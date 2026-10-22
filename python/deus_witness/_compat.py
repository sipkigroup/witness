"""Platform helpers (0.2.21): everything that differs between POSIX and Windows lives here, so the rest of the code has one path.
POSIX behaviour is unchanged; the Windows branches are exercised on POSIX by tests through the `windows` argument / env switches."""
import asyncio
import os
import re
import shutil
import sys
import threading
from pathlib import Path

IS_WINDOWS = os.name == "nt"
_DRIVE = re.compile(r"^[A-Za-z]:[\\/]")


def home(env=None) -> str:
    """The user's home directory. POSIX: $HOME, else the passwd entry. Windows: %USERPROFILE% (HOME there is only set by Git Bash
    and then is a /c/Users/.. style path that Python cannot open), else Path.home()."""
    e = os.environ if env is None else env
    if IS_WINDOWS:
        return e.get("USERPROFILE") or str(Path.home())
    return e.get("HOME") or str(Path.home())


def is_abs_path(p, windows: bool | None = None) -> bool:
    """Absolute path of this platform; a drive path (C:\\x, C:/x) or a UNC path counts as absolute where Windows rules apply."""
    if not isinstance(p, str) or not p:
        return False
    if windows is None:
        windows = IS_WINDOWS
    if windows:
        return bool(_DRIVE.match(p)) or p.startswith("\\\\") or p.startswith("/")
    return p.startswith("/")


def resolve_command(cmd: list, windows: bool | None = None, which=shutil.which) -> list:
    """Windows: `npx` is `npx.cmd`, which CreateProcess does not find by the bare name: the first word is replaced by the full path
    shutil.which finds (PATHEXT aware). POSIX and an unknown command: unchanged (the caller reports the failure)."""
    if windows is None:
        windows = IS_WINDOWS
    if not windows or not cmd:
        return list(cmd)
    found = which(cmd[0])
    return [found] + list(cmd[1:]) if found else list(cmd)


def private_open_flags() -> int:
    """os.open flags for a file only this user may read. O_BINARY keeps Windows from translating line ends under os.fdopen."""
    return os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0)


def write_private_text(path: str, text: str) -> None:
    """Write `text` (UTF-8) to `path` mode 0600. On Windows the mode argument is ignored by the OS (no POSIX bits): it does not fail."""
    fd = os.open(path, private_open_flags(), 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)


READER_THREAD_STARTED = False      # a reader thread may still sit in a blocking read: the process must end with exit_now(), not by interpreter shutdown


def exit_now(rc: int) -> None:
    """End the process at once when a stdin reader thread may still hold the stdin buffer lock (finalising the interpreter then aborts
    with "could not acquire lock ... at interpreter shutdown"). Streams are flushed first."""
    for st in (sys.stdout, sys.stderr):
        try:
            st.flush()
        except Exception:      # noqa: BLE001
            pass
    os._exit(rc)


class ThreadLineReader:
    """Async readline() over a blocking binary file (stdin on Windows, where the event loop cannot watch a console/pipe handle).
    A daemon thread reads lines and hands them to the loop, so a read that never returns cannot keep the process from exiting.
    readline() -> bytes, b"" at EOF; ValueError when a line is longer than `limit` (as asyncio.StreamReader does)."""

    def __init__(self, fileobj, loop: asyncio.AbstractEventLoop, limit: int):
        global READER_THREAD_STARTED
        READER_THREAD_STARTED = True
        self._q: asyncio.Queue = asyncio.Queue(maxsize=8)
        self._loop, self._f, self._limit = loop, fileobj, limit
        threading.Thread(target=self._run, daemon=True, name="stdin-reader").start()

    def _put(self, item) -> None:
        try:
            asyncio.run_coroutine_threadsafe(self._q.put(item), self._loop).result()
        except Exception:      # noqa: BLE001  loop closed: the process is going down
            pass

    def _run(self) -> None:
        while True:
            try:
                line = self._f.readline(self._limit + 1)
            except (OSError, ValueError):
                line = b""
            if len(line) > self._limit and not line.endswith(b"\n"):
                self._put(ValueError("line too long"))
                return
            self._put(line)
            if not line:
                return

    async def readline(self) -> bytes:
        item = await self._q.get()
        if isinstance(item, Exception):
            raise item
        return item


async def open_stdin_reader(limit: int, thread: bool | None = None):
    """A reader with `await readline()` for the binary stdin. POSIX: the event loop watches the pipe (as before). Windows (or
    DEUS_WITNESS_STDIN_THREAD=1, or thread=True): a reader thread."""
    loop = asyncio.get_running_loop()
    if thread is None:
        thread = IS_WINDOWS or os.environ.get("DEUS_WITNESS_STDIN_THREAD") == "1"
    if thread:
        return ThreadLineReader(sys.stdin.buffer, loop, limit)
    reader = asyncio.StreamReader(limit=limit)
    await loop.connect_read_pipe(lambda: asyncio.StreamReaderProtocol(reader), sys.stdin)
    return reader
