import json
import shutil
import subprocess
from pathlib import Path

from .discovery import find_vmlinux
from .errors import KpcliError


DEFAULT_SYMBOLS = (
    "commit_creds",
    "prepare_kernel_cred",
    "init_cred",
    "init_task",
    "modprobe_path",
    "core_pattern",
    "poweroff_cmd",
    "swapgs_restore_regs_and_return_to_usermode",
    "entry_SYSCALL_64_after_hwframe",
    "find_task_by_vpid",
    "switch_task_namespaces",
    "init_nsproxy",
    "kernel_read_file",
    "call_usermodehelper_exec",
)

KASLR_ANCHORS = ("_stext", "_text", "startup_64")

FUNCTION_SYMBOLS = frozenset((
    "commit_creds",
    "prepare_kernel_cred",
    "find_task_by_vpid",
    "switch_task_namespaces",
    "kernel_read_file",
    "call_usermodehelper_exec",
))


def resolve_symbol_file(symbol_file=None):
    path = Path(symbol_file) if symbol_file else find_vmlinux()
    if not path:
        raise KpcliError("vmlinux not found; pass --file explicitly")
    if not path.exists():
        raise KpcliError("%s not found" % path)
    return path


def parse_nm_output(output, names):
    wanted = set(names)
    result = {}
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        address, _kind, name = parts[:3]
        if name not in wanted:
            continue
        try:
            result[name] = int(address, 16)
        except ValueError:
            continue
    return result


def extract_symbols(symbol_file=None, names=DEFAULT_SYMBOLS):
    if not shutil.which("nm"):
        raise KpcliError("nm not found")

    symbol_file = resolve_symbol_file(symbol_file)
    requested = tuple(dict.fromkeys(tuple(names) + KASLR_ANCHORS))
    try:
        output = subprocess.check_output(
            ["nm", "-n", str(symbol_file)],
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
        )
    except subprocess.CalledProcessError as error:
        raise KpcliError(
            "nm failed for %s: %s" % (symbol_file, error.output.strip())
        ) from error
    return symbol_file, parse_nm_output(output, requested)


def calculate_kaslr_slide(runtime_symbols, static_symbols):
    for name in KASLR_ANCHORS:
        if runtime_symbols.get(name) and static_symbols.get(name):
            return name, runtime_symbols[name] - static_symbols[name]
    return None, None


def _hex(value):
    return "-0x%x" % -value if value < 0 else "0x%x" % value


def _c_identifier(name):
    return "".join(character if character.isalnum() or character == "_" else "_" for character in name)


def render_symbol_assignments(symbols, names=DEFAULT_SYMBOLS, function_pointers=False):
    def declaration(name):
        identifier = _c_identifier(name)
        if function_pointers and name in FUNCTION_SYMBOLS:
            return "%-58s = (unsigned long (*)())%s;" % (
                "unsigned long (*%s)()" % identifier,
                _hex(symbols.get(name, 0)),
            )
        return "unsigned long %-44s = %s;" % (identifier, _hex(symbols.get(name, 0)))

    return "\n".join(
        declaration(name) for name in names
    )


def render_symbol_offsets(offsets, names=DEFAULT_SYMBOLS, anchor="_stext"):
    return "\n".join(
        "unsigned long %-44s = %s;" % (
            _c_identifier(name) + "_offset",
            _hex(offsets.get(name, 0)),
        )
        for name in names
    )


def render_symbols(
    symbol_file,
    symbols,
    names=DEFAULT_SYMBOLS,
    as_json=False,
    kaslr=None,
    output_format="macro",
):
    kaslr = kaslr or {}
    payload = {
        "file": str(symbol_file),
        "symbols": {name: "0x%x" % value for name, value in symbols.items() if name in names},
        "missing": [name for name in names if name not in symbols],
        "kaslr": kaslr,
    }
    if as_json:
        return json.dumps(payload, indent=2)

    lines = ["[*] Symbols from %s" % symbol_file]
    if kaslr:
        lines.append("[*] KASLR: %s" % kaslr.get("status", "Unknown"))
        if kaslr.get("slide") is not None:
            lines.append("[*] KASLR slide: 0x%x (anchor: %s)" % (kaslr["slide"], kaslr["anchor"]))
        elif kaslr.get("detail"):
            lines.append("[*] KASLR note: %s" % kaslr["detail"])
    if output_format in ("assignment", "pointer"):
        lines.append(render_symbol_assignments(
            symbols,
            names,
            function_pointers=output_format == "pointer",
        ))
    else:
        for name in names:
            lines.append("#define %-48s %s" % (name.upper(), _hex(symbols.get(name, 0))))

    offsets = kaslr.get("offsets") or {}
    if offsets:
        lines.append("")
        lines.append("[*] Stable offsets relative to %s" % kaslr["offset_anchor"])
        lines.append(render_symbol_offsets(offsets, names, kaslr["offset_anchor"]))
    return "\n".join(lines)


def symbols_report(symbol_file=None, names=DEFAULT_SYMBOLS, as_json=False):
    symbol_file, symbols = extract_symbols(symbol_file, names)
    return render_symbols(symbol_file, symbols, names, as_json=as_json)
