import re
import uuid

from .constants import PROMPTS
from .errors import KphelperError
from .symbols import DEFAULT_SYMBOLS


def validate_symbol_name(name):
    if not re.fullmatch(r"[A-Za-z0-9_.$]+", name):
        raise KphelperError("unsafe symbol name: %s" % name)


class GuestShell:
    def __init__(self, io, timeout=8, boot_timeout=None):
        self.io = io
        self.timeout = timeout
        self.boot_timeout = boot_timeout if boot_timeout is not None else timeout
        self.ready = False

    def wait_ready(self):
        if self.ready:
            return
        prompt_data = self.io.recvuntil(PROMPTS, timeout=self.boot_timeout) or b""
        if not prompt_data.endswith(PROMPTS):
            raise KphelperError(
                "guest shell prompt not reached within %d seconds; ensure QEMU uses serial stdio and does not boot with -S"
                % self.boot_timeout
            )
        marker = "__KPHELPER_READY_%s__" % uuid.uuid4().hex
        self.io.sendline(("echo " + marker).encode())
        data = self.io.recvuntil(marker.encode(), timeout=self.timeout) or b""
        if marker.encode() not in data:
            raise KphelperError("guest shell did not execute readiness probe")
        self.io.recvuntil(PROMPTS, timeout=self.timeout)
        self.ready = True

    def run(self, command):
        self.wait_ready()
        marker = "__KPHELPER_%s__" % uuid.uuid4().hex
        self.io.sendline(("%s; printf '\\n%s:%%s\\n' $?" % (command, marker)).encode())
        data = self.io.recvuntil((marker + ":").encode(), timeout=self.timeout) or b""
        if (marker + ":").encode() not in data:
            raise KphelperError("guest command timed out: %s" % command)
        status_line = self.io.recvline(timeout=self.timeout) or b""
        self.io.recvuntil(PROMPTS, timeout=self.timeout)
        output = data.rsplit((marker + ":").encode(), 1)[0]
        try:
            status = int(status_line.strip().split()[0])
        except (IndexError, ValueError):
            status = None
        return output.decode(errors="replace"), status


def parse_kptr_value(output):
    for line in reversed(output.splitlines()):
        line = line.strip()
        if re.fullmatch(r"[0-2]", line):
            return int(line)
    return None


def parse_kallsyms(output, names=DEFAULT_SYMBOLS):
    wanted = set(names)
    result = {}
    for line in output.splitlines():
        parts = line.strip().split()
        if len(parts) < 3:
            continue
        address, _kind, name = parts[:3]
        if name not in wanted or not re.fullmatch(r"[0-9a-fA-F]+", address):
            continue
        value = int(address, 16)
        if value:
            result[name] = value
    return result


def kallsyms_grep_command(names):
    for name in names:
        validate_symbol_name(name)
    return "for s in %s; do grep \" $s$\" /proc/kallsyms 2>/dev/null; done" % " ".join(names)


def extract_guest_ksyms(io, names=DEFAULT_SYMBOLS, timeout=8, boot_timeout=30):
    shell = GuestShell(io, timeout=timeout, boot_timeout=boot_timeout)
    shell.run("test -r /proc/kallsyms || mount -t proc none /proc 2>/dev/null || true")
    kptr_output, _status = shell.run("cat /proc/sys/kernel/kptr_restrict 2>/dev/null || echo unknown")
    kptr = parse_kptr_value(kptr_output)
    if kptr is None:
        raise KphelperError("cannot read /proc/sys/kernel/kptr_restrict")
    if kptr != 0:
        raise KphelperError("/proc/kallsyms addresses are hidden: kptr_restrict=%d" % kptr)
    output, _status = shell.run(kallsyms_grep_command(names))
    symbols = parse_kallsyms(output, names)
    if not symbols:
        raise KphelperError("no requested non-zero symbols found in /proc/kallsyms")
    return symbols
