import re
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple

from .formatting import UNKNOWN


@dataclass(frozen=True)
class QemuRunConfig:
    run_path: Path
    text: str
    arguments: Tuple[str, ...]
    cmdline: str = ""
    initrd: Optional[str] = None
    cpu: str = ""
    gdb_enabled: bool = False


def _tokenize_qemu_command(text):
    for logical_line in re.sub(r"\\\s*\n", " ", text).splitlines():
        line = logical_line.strip()
        if not line or line.startswith("#") or "qemu-system-" not in line:
            continue
        try:
            tokens = shlex.split(line, comments=True, posix=True)
        except ValueError:
            continue
        for index, token in enumerate(tokens):
            if Path(token).name.startswith("qemu-system-"):
                return tuple(tokens[index:])
    return ()


def _option_value(arguments, names):
    for index, argument in enumerate(arguments[:-1]):
        if argument in names:
            value = arguments[index + 1]
            if "$" not in value:
                return value
    return None


def parse_qemu_run_text(text, run_path="run.sh"):
    arguments = _tokenize_qemu_command(text)
    cmdline = _option_value(arguments, {"-append"}) or ""
    initrd = _option_value(arguments, {"-initrd", "-initramfs"})
    cpu = _option_value(arguments, {"-cpu"}) or ""
    gdb_enabled = "-s" in arguments or "-gdb" in arguments
    return QemuRunConfig(Path(run_path), text, arguments, cmdline, initrd, cpu, gdb_enabled)


def load_qemu_run(run_path="run.sh"):
    run_path = Path(run_path)
    text = run_path.read_text(encoding="utf-8", errors="replace")
    return parse_qemu_run_text(text, run_path)


def display_value(value):
    return value if value else UNKNOWN
