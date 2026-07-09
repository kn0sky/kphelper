from .errors import KphelperError
from .session import managed_session, local_target, remote_target
from .ksym import GuestShell, parse_kptr_value


def probe_kallsyms(io, timeout=8):
    shell = GuestShell(io, timeout=timeout)
    shell.run("test -r /proc/kallsyms || mount -t proc none /proc 2>/dev/null || true")
    kptr_output, _status = shell.run("cat /proc/sys/kernel/kptr_restrict 2>/dev/null || echo unknown")
    kptr = parse_kptr_value(kptr_output)
    if kptr is None:
        raise KphelperError("cannot read /proc/sys/kernel/kptr_restrict")
    return {"kptr_restrict": kptr}


def probe_guest_runtime(run_path="./run.sh", timeout=8):
    with managed_session(local_target, run_path) as io:
        return probe_kallsyms(io, timeout=timeout)


def probe_remote_runtime(ip, port, timeout=8):
    with managed_session(remote_target, ip, port) as io:
        return probe_kallsyms(io, timeout=timeout)
