import re

from .errors import KphelperError
from .guest import GuestShell, GuestTimeouts
from .symbols import DEFAULT_SYMBOLS


def validate_symbol_name(name):
    if not re.fullmatch(r"[A-Za-z0-9_.$]+", name):
        raise KphelperError("unsafe symbol name: %s" % name)


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
    return "for s in %s; do grep \" $s$\" /proc/kallsyms; done" % " ".join(names)


def extract_guest_ksyms(io, names=DEFAULT_SYMBOLS, timeouts=None):
    shell = GuestShell(io, timeouts=timeouts or GuestTimeouts())
    shell.run("test -r /proc/kallsyms || mount -t proc none /proc || true")
    kptr_output, kptr_status = shell.run("cat /proc/sys/kernel/kptr_restrict || echo unknown")
    kptr = parse_kptr_value(kptr_output)
    if kptr is None:
        detail = kptr_output.strip() or "no output"
        raise KphelperError(
            "cannot read /proc/sys/kernel/kptr_restrict "
            "(status=%s, output=%r)" % (kptr_status, detail)
        )
    if kptr != 0:
        raise KphelperError("/proc/kallsyms addresses are hidden: kptr_restrict=%d" % kptr)
    output, _status = shell.run(kallsyms_grep_command(names))
    symbols = parse_kallsyms(output, names)
    if not symbols:
        raise KphelperError("no requested non-zero symbols found in /proc/kallsyms")
    return symbols
