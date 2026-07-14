from .findings import Finding
from .formatting import BOLD, BLUE, CYAN, DIM, DISABLED, ENABLED, GREEN, MAGENTA, RED, UNKNOWN, YELLOW, colorize


def status_color(name, value):
    if value in {ENABLED, "Found", "Likely non-root", "Configured in init", "Referenced", "Readable"}:
        return GREEN
    if value in {DISABLED, "Missing", "Likely root", "Hidden"}:
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


def status_line(name, result, color=True):
    finding = Finding.from_mapping(result)
    value = finding.status
    detail = finding.detail
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

    cmdline = Finding.from_mapping(run_result.get("cmdline", UNKNOWN))
    if cmdline.status != UNKNOWN:
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
