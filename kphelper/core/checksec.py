import re
import shutil
import subprocess
from pathlib import Path

from .discovery import find_cpio
from .errors import KphelperError


UNKNOWN = "Unknown"
ENABLED = "Enabled"
DISABLED = "Disabled"

RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"
DIM = "\033[2m"


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


def cpio_command(cpio_path):
    name = str(cpio_path)
    if name.endswith(".gz"):
        return f"gzip -dc {sh_quote(name)} | cpio -idm --quiet"
    if name.endswith(".xz"):
        return f"xz -dc {sh_quote(name)} | cpio -idm --quiet"
    if name.endswith(".bz2"):
        return f"bzip2 -dc {sh_quote(name)} | cpio -idm --quiet"
    if name.endswith(".lz4"):
        return f"lz4 -dc {sh_quote(name)} | cpio -idm --quiet"
    return f"cpio -idm --quiet < {sh_quote(name)}"


def sh_quote(value):
    return "'" + value.replace("'", "'\"'\"'") + "'"


def unpack_cpio(cpio_path, root_dir="root"):
    cpio_path = Path(cpio_path).resolve()
    root_dir = Path(root_dir)
    root_dir.mkdir(exist_ok=True)
    cmd = cpio_command(cpio_path)
    try:
        subprocess.run(cmd, shell=True, cwd=root_dir, check=True)
    except subprocess.CalledProcessError as e:
        raise KphelperError("failed to unpack %s, exit code: %d" % (cpio_path, e.returncode)) from e
    return root_dir


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


def colorize(text, color, enabled=True):
    if not enabled:
        return str(text)
    return f"{color}{text}{RESET}"


def status_color(name, value):
    if value in {ENABLED, "Found", "Likely non-root", "Configured in init", "Referenced"}:
        return GREEN
    if value in {DISABLED, "Missing", "Likely root"}:
        return RED
    if value == UNKNOWN:
        return YELLOW
    if name in {"run.sh", "Initrd", "Cmdline", "Rootfs", "Init"}:
        return CYAN
    if name in {"kptr_restrict", "dmesg_restrict"}:
        if value == "0":
            return RED
        if value in {"1", "2"}:
            return GREEN
    return BLUE


def status_line(name, value, detail=None, color=True):
    value = colorize(value, status_color(name, value), color)
    label = colorize(f"{name:<18}", BOLD, color)
    if detail:
        return f"    {label}: {value} {colorize(f'({detail})', DIM, color)}"
    return f"    {label}: {value}"


def render_report(run_result, init_result=None, color=True):
    lines = [colorize("[*] Kernel checksec", MAGENTA + BOLD, color)]
    lines.append(status_line("run.sh", run_result["run.sh"], color=color))
    lines.append(status_line("KASLR", run_result["KASLR"], color=color))
    lines.append(status_line("SMEP", run_result["SMEP"], color=color))
    lines.append(status_line("SMAP", run_result["SMAP"], color=color))
    lines.append(status_line("KPTI", run_result["KPTI"], color=color))
    lines.append(status_line("KGDB", run_result["KGDB"], color=color))
    lines.append(status_line("Initrd", run_result["Initrd"], color=color))

    cmdline = run_result.get("cmdline")
    if cmdline and cmdline != UNKNOWN:
        lines.append(status_line("Cmdline", cmdline, color=color))

    if init_result:
        lines.append("")
        lines.append(colorize("[*] Rootfs checksec", MAGENTA + BOLD, color))
        for key in [
            "Rootfs",
            "Init",
            "Scripts",
            "Root shell",
            "Module load",
            "kptr_restrict",
            "dmesg_restrict",
            "kallsyms",
            "Module base leak",
            "Device permissions",
        ]:
            lines.append(status_line(key, init_result[key], color=color))

    return "\n".join(lines)


def run_checksec(run_path="run.sh", cpio_path=None, root_dir="root", color=True):
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
    return render_report(run_result, init_result, color=color)
