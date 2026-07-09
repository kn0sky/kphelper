import re
import shutil
from pathlib import Path

from .formatting import DISABLED, ENABLED, UNKNOWN
from .checksec_report import render_report
from .cpio import unpack_cpio
from .discovery import find_cpio
from .errors import KphelperError


def read_text(path):
    return Path(path).read_text(errors="replace")


def extract_cmdline(run_text):
    matches = re.findall(r"-append\s+(['\"])(.*?)\1", run_text, flags=re.DOTALL)
    if matches:
        return " ".join(match[1] for match in matches)
    match = re.search(r"-append\s+([^\n]+)", run_text)
    if not match:
        return ""
    return match.group(1).strip()


def extract_initrd(run_text):
    match = re.search(r"-(?:initrd|initramfs)\s+([^\s\\]+)", run_text)
    if not match:
        return None
    return match.group(1).strip("'\"")


def resolve_initrd_path(initrd, run_path):
    if not initrd or initrd == UNKNOWN:
        return None
    path = Path(initrd)
    if path.exists():
        return path
    run_dir = Path(run_path).parent
    candidate = run_dir / path
    if candidate.exists():
        return candidate
    return None


def has_any(text, needles):
    return any(needle in text for needle in needles)


def detect_runsec(run_path):
    run_path = Path(run_path)
    result = {
        "run.sh": str(run_path),
        "cmdline": UNKNOWN,
        "KASLR": UNKNOWN,
        "SMEP": UNKNOWN,
        "SMAP": UNKNOWN,
        "KPTI": UNKNOWN,
        "KGDB": UNKNOWN,
        "Initrd": UNKNOWN,
    }
    if not run_path.exists():
        result["run.sh"] = "Missing"
        return result

    text = read_text(run_path)
    cmdline = extract_cmdline(text)
    cpu_args = " ".join(re.findall(r"-cpu\s+([^\s\\]+)", text))
    result["cmdline"] = cmdline if cmdline else UNKNOWN

    if "nokaslr" in cmdline:
        result["KASLR"] = DISABLED
    elif re.search(r"(^|\s)kaslr(\s|$)", cmdline):
        result["KASLR"] = ENABLED

    if "nopti" in cmdline:
        result["KPTI"] = DISABLED
    elif has_any(cmdline, ["kpti=1", "pti=on"]):
        result["KPTI"] = ENABLED

    if has_any(cpu_args, ["-smep", "smep=off"]) or "nosmep" in cmdline:
        result["SMEP"] = DISABLED
    elif has_any(cpu_args, ["+smep", "smep"]):
        result["SMEP"] = ENABLED

    if has_any(cpu_args, ["-smap", "smap=off"]) or "nosmap" in cmdline:
        result["SMAP"] = DISABLED
    elif has_any(cpu_args, ["+smap", "smap"]):
        result["SMAP"] = ENABLED

    if re.search(r"(^|\s)(-s|-S)(\s|$)", text) or "-gdb" in text:
        result["KGDB"] = ENABLED
    else:
        result["KGDB"] = DISABLED

    initrd = extract_initrd(text)
    if initrd:
        result["Initrd"] = initrd

    return result


def startup_script_paths(root_dir):
    root_dir = Path(root_dir)
    candidates = [
        root_dir / "init",
        root_dir / "etc" / "inittab",
        root_dir / "etc" / "rcS",
        root_dir / "etc" / "init.d" / "rcS",
    ]
    init_d = root_dir / "etc" / "init.d"
    if init_d.is_dir():
        candidates.extend(sorted(path for path in init_d.iterdir() if path.is_file()))
    return [path for path in candidates if path.exists()]


def scan_init(root_dir):
    root_dir = Path(root_dir)
    scripts = startup_script_paths(root_dir)
    result = {
        "Rootfs": str(root_dir),
        "Init": "Missing",
        "Scripts": "Missing",
        "Root shell": UNKNOWN,
        "Module load": UNKNOWN,
        "kptr_restrict": UNKNOWN,
        "dmesg_restrict": UNKNOWN,
        "kallsyms": UNKNOWN,
        "Module base leak": UNKNOWN,
        "Device permissions": UNKNOWN,
    }
    if not scripts:
        return result

    texts = {path: read_text(path) for path in scripts}
    text = "\n".join(texts.values())
    init = root_dir / "init"
    if init.exists():
        result["Init"] = str(init)
    result["Scripts"] = ", ".join(str(path) for path in scripts)

    if has_any(text, ["setuidgid", "su "]):
        result["Root shell"] = "Likely non-root"
    elif re.search(r"\b(sh|bash|cttyhack\s+sh)\b", text):
        result["Root shell"] = "Likely root"

    if re.search(r"\binsmod\b|\bmodprobe\b", text):
        result["Module load"] = "Found"

    result["kptr_restrict"] = detect_sysctl_write(text, "kptr_restrict")
    result["dmesg_restrict"] = detect_sysctl_write(text, "dmesg_restrict")

    if "/proc/kallsyms" in text:
        result["kallsyms"] = "Referenced"
    if "/sys/module/" in text and "/sections/" in text:
        result["Module base leak"] = "Referenced"
    if re.search(r"\bchmod\b|\bchown\b|mknod", text):
        result["Device permissions"] = "Configured in init"

    return result


def detect_sysctl_write(text, name):
    pattern = rf"echo\s+([0-9]+)\s*>\s*/proc/sys/kernel/{re.escape(name)}"
    match = re.search(pattern, text)
    if not match:
        return UNKNOWN
    return match.group(1)


def run_checksec(run_path="run.sh", cpio_path=None, root_dir="root", color=True, live=False):
    run_result = detect_runsec(run_path)
    init_result = None
    if cpio_path is None:
        cpio_path = resolve_initrd_path(run_result["Initrd"], run_path)
    if cpio_path is None:
        cpio_path = find_cpio()
    if cpio_path:
        run_result["Initrd"] = str(cpio_path)
        if not shutil.which("cpio"):
            raise KphelperError("cpio not found")
        unpacked = unpack_cpio(cpio_path, root_dir)
        init_result = scan_init(unpacked)
    # live 参数预留给后续动态探测；当前保留接口，不改变静态行为。
    return render_report(run_result, init_result, color=color)
