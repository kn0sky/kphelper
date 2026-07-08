import base64
import gzip
import re
from pathlib import Path

from .constants import LOCAL_EXP, PROMPTS, REMOTE_EXP
from .errors import KphelperError
from .pwn import log


class UploadError(KphelperError):
    pass


def verify_remote_size(io, remote, expected_size, p=PROMPTS):
    io.sendlineafter(p, b"wc -c < %s" % remote.encode())
    try:
        data = io.recvuntil(p, timeout=5)
    except EOFError:
        raise UploadError("upload verification failed: connection closed")

    numbers = re.findall(rb"\b([0-9]+)\b", data or b"")
    if not numbers:
        raise UploadError("upload verification failed: cannot parse wc output")

    actual_size = int(numbers[-1])
    if actual_size != expected_size:
        raise UploadError(
            "upload verification failed: remote size %d != local size %d"
            % (actual_size, expected_size)
        )

    log.success("upload verified: %d bytes", actual_size)
    return True


def upload(io, local=LOCAL_EXP, remote=REMOTE_EXP, p=PROMPTS):
    local = Path(local)
    if not local.exists():
        log.info("local exp not found, skip upload: %s", local)
        return False

    raw = local.read_bytes()
    b = base64.b64encode(gzip.compress(raw))
    io.sendlineafter(p, b": > /tmp/e.b64")
    for i in range(0, len(b), 512):
        io.sendlineafter(p, b"echo -n '%s' >> /tmp/e.b64" % b[i:i + 512])
    io.sendlineafter(
        p,
        b"base64 -d /tmp/e.b64|gzip -d>%s;chmod +x %s"
        % (remote.encode(), remote.encode()),
    )
    verify_remote_size(io, remote, len(raw), p)

    log.success("uploaded %s -> %s", local, remote)
    return True
