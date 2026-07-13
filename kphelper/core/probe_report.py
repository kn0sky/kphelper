from .findings import Finding, RuntimeProbeReport
from .formatting import BOLD, BLUE, DIM, GREEN, MAGENTA, RED, UNKNOWN, YELLOW, colorize
from .symbols import DEFAULT_SYMBOLS, render_symbol_assignments, render_symbol_offsets


STATUS_COLORS = {
    "Readable": GREEN,
    "Hidden": RED,
    "Skipped": YELLOW,
    UNKNOWN: YELLOW,
}


def live_status_line(name, result, color=True, label_width=18):
    result = Finding.from_mapping(result)
    status = result.status
    value = result.value
    detail = result.detail
    display = f"{status}: {value}" if value is not None else status
    colored_value = colorize(display, STATUS_COLORS.get(status, BLUE), color)
    label = colorize(f"{name:<{label_width}}", BOLD, color)
    if detail:
        return f"    {label}: {colored_value} {colorize(f'({detail})', DIM, color)}"
    return f"    {label}: {colored_value}"


def render_live_report(live_result, color=True, kaslr=None):
    if kaslr is None and not isinstance(live_result, RuntimeProbeReport):
        kaslr = live_result.get("kaslr") or {}
    report = RuntimeProbeReport.from_mapping(live_result)
    lines = [colorize("[*] Live runtime probe", MAGENTA + BOLD, color)]
    for name in ["User ID", "kptr_restrict", "dmesg_restrict", "kallsyms", "Module base leak"]:
        lines.append(live_status_line(name, report.findings.get(name, Finding(UNKNOWN)), color=color))

    symbols = report.symbols
    if symbols:
        lines.append("")
        lines.append(colorize("[*] Live symbols", MAGENTA + BOLD, color))
        symbol_names = [name for name in DEFAULT_SYMBOLS if name in symbols]
        label_width = max(18, *(len(name) for name in symbol_names))
        for name in symbol_names:
            lines.append(live_status_line(
                name,
                {"status": "Readable", "value": f"0x{symbols[name]:x}"},
                color=color,
                label_width=label_width,
            ))

    lines.append("")
    lines.append(colorize("[*] C assignments", MAGENTA + BOLD, color))
    lines.append(render_symbol_assignments(symbols, DEFAULT_SYMBOLS))

    kaslr = kaslr or {}
    offsets = kaslr.get("offsets") or {}
    if offsets:
        lines.append("")
        lines.append(colorize("[*] Stable KASLR offsets", MAGENTA + BOLD, color))
        lines.append("// relative to %s" % kaslr["offset_anchor"])
        lines.append(render_symbol_offsets(offsets, DEFAULT_SYMBOLS, kaslr["offset_anchor"]))

    return "\n".join(lines)
