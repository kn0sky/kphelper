from contextlib import contextmanager
from pathlib import Path

from .constants import REMOTE_DIR
from .errors import KpcliError
from .pwn import process, remote


def local_target(run_path="./run.sh"):
    run_path = Path(run_path)
    if not run_path.is_file():
        raise KpcliError("QEMU startup script not found: %s" % run_path)
    try:
        return process(["bash", str(run_path)])
    except KpcliError:
        raise
    except Exception as error:
        raise KpcliError("failed to start local target: %s" % error) from error


def remote_target(ip, port):
    try:
        return remote(ip, port)
    except KpcliError:
        raise
    except Exception as error:
        raise KpcliError("failed to connect to %s:%s: %s" % (ip, port, error)) from error


def cd_remote_tmp(io):
    io.sendline(b"cd " + REMOTE_DIR.encode())


def interact(io):
    io.interactive()


def close_session(io):
    if io is None:
        return
    try:
        io.close()
    except Exception:
        pass


@contextmanager
def managed_session(factory, *args, **kwargs):
    io = None
    try:
        io = factory(*args, **kwargs)
        yield io
    finally:
        close_session(io)
