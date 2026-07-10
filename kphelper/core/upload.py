import base64
import gzip
import re
from pathlib import Path

from .constants import LOCAL_EXP, PROMPTS, REMOTE_EXP
from .errors import KphelperError
from .guest import GuestShell
from .pwn import log


def verify_remote_size(io, remote, expected_size, p=PROMPTS):
    io.sendlineafter(p, b"wc -c < %s" % remote.encode())
    try:
        data = io.recvuntil(p, timeout=5)
    except EOFError:
        raise KphelperError("upload verification failed: connection closed")

    numbers = re.findall(rb"\b([0-9]+)\b", data or b"")
    if not numbers:
        raise KphelperError("upload verification failed: cannot parse wc output")

    actual_size = int(numbers[-1])
    if actual_size != expected_size:
        raise KphelperError(
            "upload verification failed: remote size %d != local size %d"
            % (actual_size, expected_size)
        )

    log.success("upload verified: %d bytes", actual_size)
    return True


def _run_checked(shell, command, action):
    output, status = shell.run(command)
    if status != 0:
        detail = ": %s" % output if output else ""
        raise KphelperError("%s failed%s" % (action, detail))
    return output


def upload(io, local=LOCAL_EXP, remote=REMOTE_EXP, p=PROMPTS, shell=None):
    local = Path(local)
    if not local.exists():
        log.info("local exp not found, skip upload: %s", local)
        return False

    shell = shell or GuestShell(io)
    raw = local.read_bytes()
    encoded = base64.b64encode(gzip.compress(raw)).decode("ascii")
    staging = "/tmp/.kphelper-exp.b64"
    _run_checked(shell, ": > %s" % staging, "prepare upload")
    for offset in range(0, len(encoded), 512):
        chunk = encoded[offset:offset + 512]
        _run_checked(
            shell,
            "printf '%%s' '%s' >> %s" % (chunk, staging),
            "upload chunk",
        )
    _run_checked(
        shell,
        "base64 -d %s | gzip -d > %s && chmod +x %s && rm -f %s"
        % (staging, remote, remote, staging),
        "finalize upload",
    )
    output = _run_checked(shell, "wc -c < %s" % remote, "verify upload")
    numbers = re.findall(r"\b([0-9]+)\b", output)
    if not numbers or int(numbers[-1]) != len(raw):
        raise KphelperError("upload verification failed: expected %d bytes, got %s" % (len(raw), output or "no size"))

    log.success("uploaded %s -> %s", local, remote)
    return True
