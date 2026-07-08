import re
import uuid

from .constants import PROMPTS
from .errors import KphelperError
from .symbols import DEFAULT_SYMBOLS, render_symbols


def validate_symbol_name(name):
    if not re.fullmatch(r"[A-Za-z0-9_.$]+", name):
        raise KphelperError("unsafe symbol name: %s" % name)


class GuestShell:
    def __init__(self, io, timeout=8):
        self.io = io
        self.timeout = timeout
        self.ready = False

    def run(self, command):
        if not self.ready:
            self.io.recvuntil(PROMPTS, timeout=self.timeout)
            self.ready = True

        marker = "__KPHELPER_%s__" % uuid.uuid4().hex
        self.io.sendline(("%s; echo %s:$?" % (command, marker)).encode())
        data = self.io.recvuntil((marker + ":").encode(), timeout=self.timeout)
        status_line = self.io.recvline(timeout=self.timeout) or b""

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
        addr, _kind, name = parts[:3]
        if name not in wanted:
            continue
        if not re.fullmatch(r"[0-9a-fA-F]+", addr):
            continue
        value = int(addr, 16)
        if value == 0:
            continue
        result[name] = value
    return result


def kallsyms_grep_command(names):
    for name in names:
        validate_symbol_name(name)
    body = " ".join(names)
    return "for s in %s; do grep \" $s$\" /proc/kallsyms 2>/dev/null; done" % body


def extract_guest_ksyms(io, names=DEFAULT_SYMBOLS, timeout=8):
    shell = GuestShell(io, timeout=timeout)
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
        raise KphelperError("no requested symbols found in /proc/kallsyms")
    return symbols


def guest_ksym_report(io, names=DEFAULT_SYMBOLS, as_json=False, timeout=8):
    symbols = extract_guest_ksyms(io, names, timeout=timeout)
    return render_symbols("guest:/proc/kallsyms", symbols, names, as_json=as_json)
