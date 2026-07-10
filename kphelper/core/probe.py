import re

from .findings import Finding
from .formatting import UNKNOWN
from .guest import GuestShell, GuestTimeouts
from .ksym import parse_kallsyms, parse_kptr_value
from .session import managed_session, local_target, remote_target
from .symbols import DEFAULT_SYMBOLS


SKIPPED = "Skipped"
READABLE = "Readable"
HIDDEN = "Hidden"


def _result(status, detail=None, value=None, source="runtime"):
    return Finding(status=status, detail=detail, value=value, source=source)


def _known_static_value(static_rootfs, name):
    if not static_rootfs:
        return None
    value = static_rootfs.get(name, UNKNOWN)
    return None if value == UNKNOWN else value


def _probe_sysctl(shell, name, static_rootfs=None):
    static_value = _known_static_value(static_rootfs, name)
    if static_value is not None:
        return _result(SKIPPED, "known from rootfs startup scripts", static_value)

    output, status = shell.run(
        "cat /proc/sys/kernel/%s 2>/dev/null" % name
    )
    value = parse_kptr_value(output)
    if status != 0 or value is None:
        return _result(SKIPPED, "not accessible from guest shell")
    return _result(READABLE, value=value)


def _probe_kallsyms(shell, names, kptr_result):
    if kptr_result.get("value") in {1, 2}:
        return _result(HIDDEN, "kptr_restrict=%s" % kptr_result["value"]), {}

    output, status = shell.run("cat /proc/kallsyms 2>/dev/null")
    if status != 0:
        return _result(SKIPPED, "not accessible from guest shell"), {}

    symbols = parse_kallsyms(output, names)
    nonzero = re.search(r"^(?!0+\s)[0-9a-fA-F]+\s+\S+\s+\S+", output, flags=re.MULTILINE)
    if not nonzero:
        return _result(HIDDEN, "addresses are zero or unavailable"), {}
    return _result(READABLE), symbols


def _probe_module_base(shell):
    output, status = shell.run(
        "for f in /sys/module/*/sections/.text; do "
        "test -r \"$f\" || continue; v=$(cat \"$f\" 2>/dev/null); "
        "test -n \"$v\" && printf '%s %s\\n' \"$f\" \"$v\" && break; done"
    )
    if status != 0 or not output.strip():
        return _result(SKIPPED, "no readable module .text section")
    return _result(READABLE, detail=output.strip().splitlines()[-1])


def probe_runtime(io, static_rootfs=None, timeouts=None, names=DEFAULT_SYMBOLS):
    shell = GuestShell(io, timeouts=timeouts or GuestTimeouts())
    shell.wait_ready()

    uid_output, uid_status = shell.run("id -u 2>/dev/null")
    uid = uid_output.strip().splitlines()[-1] if uid_status == 0 and uid_output.strip() else UNKNOWN

    kptr_result = _probe_sysctl(shell, "kptr_restrict", static_rootfs)
    dmesg_result = _probe_sysctl(shell, "dmesg_restrict", static_rootfs)
    kallsyms_result, symbols = _probe_kallsyms(shell, names, kptr_result)
    module_result = _probe_module_base(shell)

    return {
        "User ID": _result(READABLE, value=uid),
        "kptr_restrict": kptr_result,
        "dmesg_restrict": dmesg_result,
        "kallsyms": kallsyms_result,
        "Module base leak": module_result,
        "symbols": symbols,
    }


def probe_guest_runtime(run_path="./run.sh", static_rootfs=None, timeouts=None, names=DEFAULT_SYMBOLS):
    with managed_session(local_target, run_path) as io:
        return probe_runtime(io, static_rootfs=static_rootfs, timeouts=timeouts, names=names)


def probe_remote_runtime(ip, port, static_rootfs=None, timeouts=None, names=DEFAULT_SYMBOLS):
    with managed_session(remote_target, ip, port) as io:
        return probe_runtime(io, static_rootfs=static_rootfs, timeouts=timeouts, names=names)
