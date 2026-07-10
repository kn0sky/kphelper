from .findings import Finding
from .formatting import BOLD, BLUE, DIM, GREEN, MAGENTA, RED, UNKNOWN, YELLOW, colorize


STATUS_COLORS = {
    "Readable": GREEN,
    "Hidden": RED,
    "Skipped": YELLOW,
    UNKNOWN: YELLOW,
}


def live_status_line(name, result, color=True):
    result = Finding.from_mapping(result)
    status = result.status
    value = result.value
    detail = result.detail
    display = f"{status}: {value}" if value is not None else status
    colored_value = colorize(display, STATUS_COLORS.get(status, BLUE), color)
    label = colorize(f"{name:<18}", BOLD, color)
    if detail:
        return f"    {label}: {colored_value} {colorize(f'({detail})', DIM, color)}"
    return f"    {label}: {colored_value}"


def render_live_report(live_result, color=True):
    lines = [colorize("[*] Live runtime probe", MAGENTA + BOLD, color)]
    for name in ["User ID", "kptr_restrict", "dmesg_restrict", "kallsyms", "Module base leak"]:
        lines.append(live_status_line(name, live_result.get(name, {"status": UNKNOWN}), color=color))

    symbols = live_result.get("symbols") or {}
    if symbols:
        lines.append("")
        lines.append(colorize("[*] Live symbols", MAGENTA + BOLD, color))
        for name, value in symbols.items():
            lines.append(live_status_line(name, {"status": "Readable", "value": f"0x{value:x}"}, color=color))

    return "\n".join(lines)
