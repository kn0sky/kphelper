import re
import shlex

from .errors import KpcliError
from .guest import GuestShell, GuestTimeouts
from .symbols import DEFAULT_SYMBOLS


def validate_symbol_name(name):
    if not re.fullmatch(r"[A-Za-z0-9_.$]+", name):
        raise KpcliError("unsafe symbol name: %s" % name)


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
        match = re.search(r"\b([0-9a-fA-F]{8,16})\s+\S\s+(\S+)", line)
        if not match:
            continue
        address, name = match.groups()
        if name in wanted:
            result[name] = int(address, 16)
    return result


def kallsyms_query_command(names):
    names = tuple(dict.fromkeys(names))
    for name in names:
        validate_symbol_name(name)
    conditions = "|".join(re.escape(name) for name in names)
    program = '$1 !~ /^0+$/ && !seen { print; seen=1 }'
    if conditions:
        program += " $3 ~ /^(%s)$/ { print }" % conditions
    return "test -r /proc/kallsyms && awk %s /proc/kallsyms" % shlex.quote(program)


def extract_guest_ksyms(io, names=DEFAULT_SYMBOLS, timeouts=None):
    shell = GuestShell(io, timeouts=timeouts or GuestTimeouts())
    shell.run("test -r /proc/kallsyms || mount -t proc none /proc || true")
    kptr_output, kptr_status = shell.run("cat /proc/sys/kernel/kptr_restrict || echo unknown")
    kptr = parse_kptr_value(kptr_output)
    if kptr is None:
        detail = kptr_output.strip() or "no output"
        raise KpcliError(
            "cannot read /proc/sys/kernel/kptr_restrict "
            "(status=%s, output=%r)" % (kptr_status, detail)
        )
    if kptr != 0:
        raise KpcliError("/proc/kallsyms addresses are hidden: kptr_restrict=%d" % kptr)

    output, status = shell.run(kallsyms_query_command(names))
    if status != 0:
        raise KpcliError("failed to query /proc/kallsyms (status=%s)" % status)
    return parse_kallsyms(output, names)
