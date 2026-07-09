from .errors import KphelperError
from .session import managed_session, local_target, remote_target
from .ksym import GuestShell, parse_kptr_value, parse_kallsyms
from .symbols import DEFAULT_SYMBOLS


class LiveProbeError(KphelperError):
    pass


def _ensure_shell(shell):
    if not shell.ready:
        raise LiveProbeError("live probe did not reach an interactive shell prompt")


def probe_kallsyms(io, timeout=8, names=DEFAULT_SYMBOLS):
    shell = GuestShell(io, timeout=timeout)
    shell.run("test -r /proc/kallsyms || mount -t proc none /proc 2>/dev/null || true")
    _ensure_shell(shell)

    kptr_output, _status = shell.run("cat /proc/sys/kernel/kptr_restrict 2>/dev/null || echo unknown")
    kptr = parse_kptr_value(kptr_output)
    if kptr is None:
        raise LiveProbeError("cannot read /proc/sys/kernel/kptr_restrict")

    if kptr != 0:
        return {"kptr_restrict": kptr, "kallsyms": "Hidden", "module_base_leak": "Hidden"}

    kallsyms_output, _status = shell.run("cat /proc/kallsyms 2>/dev/null || echo unknown")
    symbols = parse_kallsyms(kallsyms_output, names)
    kallsyms_state = "Readable" if symbols else "Unknown"

    module_probe = shell.run("ls /sys/module 2>/dev/null | head -n 1")
    module_base_state = "Unknown"
    if module_probe[0].strip():
        module_name = module_probe[0].splitlines()[0].strip()
        if module_name:
            text, _status = shell.run(f"cat /sys/module/{module_name}/sections/.text 2>/dev/null || echo unknown")
            module_base_state = "Readable" if text.strip() and "unknown" not in text.lower() else "Unknown"

    return {
        "kptr_restrict": kptr,
        "kallsyms": kallsyms_state,
        "module_base_leak": module_base_state,
        "symbols": symbols,
    }


def probe_guest_runtime(run_path="./run.sh", timeout=8, names=DEFAULT_SYMBOLS):
    with managed_session(local_target, run_path) as io:
        return probe_kallsyms(io, timeout=timeout, names=names)


def probe_remote_runtime(ip, port, timeout=8, names=DEFAULT_SYMBOLS):
    with managed_session(remote_target, ip, port) as io:
        return probe_kallsyms(io, timeout=timeout, names=names)
