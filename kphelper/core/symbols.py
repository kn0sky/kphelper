import json
import shutil
import subprocess
from pathlib import Path

from .discovery import find_vmlinux
from .errors import KphelperError


DEFAULT_SYMBOLS = (
    "commit_creds",
    "prepare_kernel_cred",
    "init_cred",
    "swapgs_restore_regs_and_return_to_usermode",
)


def resolve_symbol_file(symbol_file=None):
    if symbol_file:
        path = Path(symbol_file)
    else:
        path = find_vmlinux()
    if not path:
        raise KphelperError("vmlinux not found; pass a symbol file explicitly")
    if not path.exists():
        raise KphelperError("%s not found" % path)
    return path


def extract_symbols(symbol_file=None, names=DEFAULT_SYMBOLS):
    if not shutil.which("nm"):
        raise KphelperError("nm not found")

    symbol_file = resolve_symbol_file(symbol_file)
    wanted = set(names)
    result = {}
    try:
        output = subprocess.check_output(
            ["nm", "-n", str(symbol_file)],
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
        )
    except subprocess.CalledProcessError as e:
        raise KphelperError("nm failed for %s: %s" % (symbol_file, e.output.strip())) from e

    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        addr, _kind, name = parts[:3]
        if name in wanted:
            result[name] = int(addr, 16)

    return symbol_file, result


def render_symbols(symbol_file, symbols, names=DEFAULT_SYMBOLS, as_json=False):
    if as_json:
        return json.dumps(
            {
                "file": str(symbol_file),
                "symbols": {name: "0x%x" % value for name, value in symbols.items()},
                "missing": [name for name in names if name not in symbols],
            },
            indent=2,
        )

    lines = ["[*] Symbols from %s" % symbol_file]
    for name in names:
        if name in symbols:
            lines.append("#define %-48s 0x%x" % (name.upper(), symbols[name]))
        else:
            lines.append("// missing: %s" % name)
    return "\n".join(lines)


def symbols_report(symbol_file=None, names=DEFAULT_SYMBOLS, as_json=False):
    symbol_file, symbols = extract_symbols(symbol_file, names)
    return render_symbols(symbol_file, symbols, names, as_json=as_json)
