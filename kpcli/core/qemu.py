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
    kernel: Optional[str] = None

    def resolve_file(self, value):
        return resolve_run_file(value, self.run_path)


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


def resolve_run_file(value, run_path):
    if not value or "$" in value:
        return None
    path = Path(value).expanduser()
    if path.is_absolute():
        return path
    candidates = (path, Path(run_path).parent / path)
    return next((candidate for candidate in candidates if candidate.is_file()), candidates[-1])


def parse_qemu_run_text(text, run_path="run.sh"):
    arguments = _tokenize_qemu_command(text)
    cmdline = _option_value(arguments, {"-append"}) or ""
    initrd = _option_value(arguments, {"-initrd", "-initramfs"})
    cpu = _option_value(arguments, {"-cpu"}) or ""
    gdb_enabled = "-s" in arguments or "-gdb" in arguments
    kernel = _option_value(arguments, {"-kernel"})
    return QemuRunConfig(
        run_path=Path(run_path),
        text=text,
        arguments=arguments,
        cmdline=cmdline,
        initrd=initrd,
        cpu=cpu,
        gdb_enabled=gdb_enabled,
        kernel=kernel,
    )


def load_qemu_run(run_path="run.sh"):
    run_path = Path(run_path)
    text = run_path.read_text(encoding="utf-8", errors="replace")
    return parse_qemu_run_text(text, run_path)


def display_value(value):
    return value if value else UNKNOWN
