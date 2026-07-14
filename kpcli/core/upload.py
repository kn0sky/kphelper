import base64
import gzip
import re
from pathlib import Path

from .constants import LOCAL_EXP, REMOTE_EXP
from .errors import KpcliError
from .guest import GuestShell
from .pwn import log


def _run_checked(shell, command, action):
    output, status = shell.run(command)
    if status != 0:
        detail = ": %s" % output if output else ""
        raise KpcliError("%s failed%s" % (action, detail))
    return output


def upload(io, local=LOCAL_EXP, remote=REMOTE_EXP, shell=None):
    local = Path(local)
    if not local.exists():
        log.info("local exp not found, skip upload: %s", local)
        return False

    shell = shell or GuestShell(io)
    raw = local.read_bytes()
    encoded = base64.b64encode(gzip.compress(raw)).decode("ascii")
    staging = "/tmp/.kpcli-exp.b64"
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
        raise KpcliError("upload verification failed: expected %d bytes, got %s" % (len(raw), output or "no size"))

    log.success("uploaded %s -> %s", local, remote)
    return True
