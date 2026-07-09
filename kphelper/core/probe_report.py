from .formatting import BOLD, BLUE, CYAN, DIM, GREEN, MAGENTA, RED, UNKNOWN, YELLOW, colorize


def live_status_color(name, value):
    if value in {"Readable"}:
        return GREEN
    if value in {"Hidden"}:
        return RED
    if value == UNKNOWN:
        return YELLOW
    if name in {"kptr_restrict"}:
        if value == 0:
            return RED
        if value in {1, 2}:
            return GREEN
    return BLUE


def live_status_line(name, value, detail=None, color=True):
    value = colorize(value, live_status_color(name, value), color)
    label = colorize(f"{name:<18}", BOLD, color)
    if detail:
        return f"    {label}: {value} {colorize(f'({detail})', DIM, color)}"
    return f"    {label}: {value}"


def render_live_report(live_result, color=True):
    lines = [colorize("[*] Live runtime probe", MAGENTA + BOLD, color)]
    lines.append(live_status_line("kptr_restrict", live_result.get("kptr_restrict", UNKNOWN), color=color))
    lines.append(live_status_line("kallsyms", live_result.get("kallsyms", UNKNOWN), color=color))
    lines.append(live_status_line("Module base leak", live_result.get("module_base_leak", UNKNOWN), color=color))

    symbols = live_result.get("symbols") or {}
    if symbols:
        lines.append("")
        lines.append(colorize("[*] Live symbols", MAGENTA + BOLD, color))
        for name, value in symbols.items():
            lines.append(live_status_line(name, f"0x{value:x}", color=color))

    return "\n".join(lines)
