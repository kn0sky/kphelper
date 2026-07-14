import re
import shutil
from pathlib import Path

from .checksec_report import render_report
from .cpio import unpack_cpio
from .discovery import find_cpio
from .errors import KpcliError
from .findings import Finding
from .formatting import DISABLED, ENABLED, UNKNOWN
from .qemu import parse_qemu_run_text, resolve_run_file


DEFAULT_CHECKSEC_ROOT = ".kpcli/checksec-root"


def _finding(value, source):
    return Finding.from_value(value, source=source)


def read_text(path):
    return Path(path).read_text(errors="replace")


def extract_cmdline(run_text):
    return parse_qemu_run_text(run_text).cmdline


def extract_initrd(run_text):
    return parse_qemu_run_text(run_text).initrd


def resolve_initrd_path(initrd, run_path):
    if not initrd or initrd == UNKNOWN:
        return None
    candidate = resolve_run_file(initrd, run_path)
    return candidate if candidate and candidate.is_file() else None


def has_any(text, needles):
    return any(needle in text for needle in needles)


def detect_runsec(run_path):
    run_path = Path(run_path)
    result = {name: _finding(value, "qemu") for name, value in {
        "run.sh": str(run_path), "cmdline": UNKNOWN, "KASLR": UNKNOWN,
        "SMEP": UNKNOWN, "SMAP": UNKNOWN, "KPTI": UNKNOWN,
        "KGDB": UNKNOWN, "Initrd": UNKNOWN,
    }.items()}
    if not run_path.exists():
        result["run.sh"] = _finding("Missing", "qemu")
        return result
    text = read_text(run_path)
    config = parse_qemu_run_text(text, run_path)
    cmdline = config.cmdline
    cpu_args = config.cpu
    result["cmdline"] = _finding(cmdline or UNKNOWN, "qemu")
    if "nokaslr" in cmdline:
        result["KASLR"] = _finding(DISABLED, "qemu")
    elif re.search(r"(^|\s)kaslr(\s|$)", cmdline):
        result["KASLR"] = _finding(ENABLED, "qemu")
    if "nopti" in cmdline:
        result["KPTI"] = _finding(DISABLED, "qemu")
    elif has_any(cmdline, ["kpti=1", "pti=on"]):
        result["KPTI"] = _finding(ENABLED, "qemu")
    if has_any(cpu_args, ["-smep", "smep=off"]) or "nosmep" in cmdline:
        result["SMEP"] = _finding(DISABLED, "qemu")
    elif has_any(cpu_args, ["+smep", "smep"]):
        result["SMEP"] = _finding(ENABLED, "qemu")
    if has_any(cpu_args, ["-smap", "smap=off"]) or "nosmap" in cmdline:
        result["SMAP"] = _finding(DISABLED, "qemu")
    elif has_any(cpu_args, ["+smap", "smap"]):
        result["SMAP"] = _finding(ENABLED, "qemu")
    result["KGDB"] = _finding(ENABLED if config.gdb_enabled else DISABLED, "qemu")
    initrd = config.initrd
    if initrd:
        result["Initrd"] = _finding(initrd, "qemu")
    return result


def startup_script_paths(root_dir):
    root_dir = Path(root_dir)
    candidates = [root_dir / "init", root_dir / "etc/inittab", root_dir / "etc/rcS", root_dir / "etc/init.d/rcS"]
    init_d = root_dir / "etc/init.d"
    if init_d.is_dir():
        candidates.extend(sorted(path for path in init_d.iterdir() if path.is_file()))
    return list(dict.fromkeys(path for path in candidates if path.exists()))


def detect_sysctl_write(text, name):
    match = re.search(rf"echo\s+([0-9]+)\s*>\s*/proc/sys/kernel/{re.escape(name)}", text)
    return match.group(1) if match else UNKNOWN


def scan_init(root_dir):
    root_dir = Path(root_dir)
    scripts = startup_script_paths(root_dir)
    result = {name: _finding(value, "rootfs") for name, value in {
        "Rootfs": str(root_dir), "Init": "Missing", "Scripts": "Missing",
        "Root shell": UNKNOWN, "Module load": UNKNOWN, "kptr_restrict": UNKNOWN,
        "dmesg_restrict": UNKNOWN, "kallsyms": UNKNOWN,
        "Module base leak": UNKNOWN, "Device permissions": UNKNOWN,
    }.items()}
    if not scripts:
        return result
    text = "\n".join(read_text(path) for path in scripts)
    init = root_dir / "init"
    if init.exists():
        result["Init"] = _finding(str(init), "rootfs")
    result["Scripts"] = _finding(", ".join(str(path) for path in scripts), "rootfs")
    if has_any(text, ["setuidgid", "su "]):
        result["Root shell"] = _finding("Likely non-root", "rootfs")
    elif re.search(r"\b(sh|bash|cttyhack\s+sh)\b", text):
        result["Root shell"] = _finding("Likely root", "rootfs")
    if re.search(r"\binsmod\b|\bmodprobe\b", text):
        result["Module load"] = _finding("Found", "rootfs")
    result["kptr_restrict"] = _finding(detect_sysctl_write(text, "kptr_restrict"), "rootfs")
    result["dmesg_restrict"] = _finding(detect_sysctl_write(text, "dmesg_restrict"), "rootfs")
    if "/proc/kallsyms" in text:
        result["kallsyms"] = _finding("Referenced", "rootfs")
    if "/sys/module/" in text and "/sections/" in text:
        result["Module base leak"] = _finding("Referenced", "rootfs")
    if re.search(r"\bchmod\b|\bchown\b|mknod", text):
        result["Device permissions"] = _finding("Configured in init", "rootfs")
    return result


def collect_checksec(run_path="run.sh", cpio_path=None, root_dir=DEFAULT_CHECKSEC_ROOT):
    run_result = detect_runsec(run_path)
    init_result = None
    cpio_path = (
        cpio_path
        or resolve_initrd_path(run_result["Initrd"].status, run_path)
        or find_cpio(Path(run_path).parent)
    )
    if cpio_path:
        run_result["Initrd"] = _finding(str(cpio_path), "filesystem")
        if not shutil.which("cpio"):
            raise KpcliError("cpio not found")
        init_result = scan_init(unpack_cpio(cpio_path, root_dir))
    return run_result, init_result


def run_checksec(run_path="run.sh", cpio_path=None, root_dir=DEFAULT_CHECKSEC_ROOT, color=True):
    return render_report(*collect_checksec(run_path, cpio_path, root_dir), color=color)
