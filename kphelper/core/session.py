from .constants import PROMPTS, REMOTE_DIR
from .pwn import process, remote


def local_target():
    return process("./run.sh")


def remote_target(ip, port):
    return remote(ip, port)


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
