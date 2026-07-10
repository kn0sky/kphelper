import json
import re
import shutil
from dataclasses import dataclass
from pathlib import Path

from .cpio import unpack_cpio
from .errors import KphelperError
from .qemu import load_qemu_run
from .runfile import update_run_initrd


DEFAULT_ANALYSIS_ROOT = ".kphelper/analysis-root"
DEFAULT_ANALYSIS_CPIO = ".kphelper/analysis-rootfs.cpio.gz"
DEFAULT_ANALYSIS_RUN = ".kphelper/run-analysis.sh"
ANALYSIS_MANIFEST = ".kphelper-analysis.json"


@dataclass(frozen=True)
class AnalysisEnvironment:
    cpio_path: Path
    run_path: Path
    root_dir: Path
    modifications: tuple


def _patch_init_for_root(text):
    replacements = (
        (r"\bsetuidgid\s+\d+\s+", ""),
        (r"\bsu\s+[^\s]+\s+-c\s+(['\"]?)(?:/bin/)?(?:ba)?sh\1", "sh"),
        (r"\bchroot\s+--userspec=[^\s]+\s+", "chroot "),
        (r"\brunuser\s+-u\s+[^\s]+\s+--\s+", ""),
    )
    modified = text
    changes = []
    for pattern, replacement in replacements:
        modified, count = re.subn(pattern, replacement, modified)
        if count:
            changes.append("removed privilege drop matching %s" % pattern)

    sysctl_lines = (
        "echo 0 > /proc/sys/kernel/kptr_restrict 2>/dev/null || true\n"
        "echo 0 > /proc/sys/kernel/dmesg_restrict 2>/dev/null || true\n"
    )
    insertion = re.search(r"(?m)^\s*(?:exec\s+)?(?:setsid\s+)?(?:cttyhack\s+)?(?:setuidgid\s+\d+\s+)?(?:/bin/)?(?:ba)?sh\b", modified)
    if insertion:
        modified = modified[:insertion.start()] + sysctl_lines + modified[insertion.start():]
        changes.append("enabled root symbol and dmesg access before final shell")
    else:
        modified += "\n" + sysctl_lines
        changes.append("appended symbol access sysctl configuration")
    return modified, changes


def prepare_analysis_root(root_dir):
    init_path = Path(root_dir) / "init"
    if not init_path.is_file():
        raise KphelperError("analysis rootfs requires an /init script")
    original = init_path.read_text(encoding="utf-8", errors="replace")
    patched, changes = _patch_init_for_root(original)
    if patched == original:
        raise KphelperError("cannot identify a safe root shell patch in /init")
    backup = init_path.with_name("init.kphelper-original")
    shutil.copy2(init_path, backup)
    init_path.write_text(patched, encoding="utf-8")
    init_path.chmod(init_path.stat().st_mode | 0o100)
    return changes


def create_analysis_environment(
    cpio_path=None,
    run_path="run.sh",
    root_dir=DEFAULT_ANALYSIS_ROOT,
    output=DEFAULT_ANALYSIS_CPIO,
    analysis_run=DEFAULT_ANALYSIS_RUN,
):
    from .pack import ensure_clean_pack_root, repack_cpio, select_cpio

    source = select_cpio(run_path, cpio_path)
    root_dir = ensure_clean_pack_root(root_dir)
    unpack_cpio(source, root_dir, reuse_existing=False)
    changes = prepare_analysis_root(root_dir)

    manifest = {
        "source_cpio": str(Path(source).resolve()),
        "source_run": str(Path(run_path).resolve()),
        "modifications": changes,
        "warning": "analysis environment only; runtime addresses may be boot-specific when KASLR is enabled",
    }
    (root_dir / ANALYSIS_MANIFEST).write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    output = repack_cpio(root_dir, output)

    source_run = Path(run_path)
    analysis_run = Path(analysis_run)
    analysis_run.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source_run, analysis_run)
    update_run_initrd(analysis_run, output, backup=False)
    analysis_run.chmod(source_run.stat().st_mode | 0o100)
    return AnalysisEnvironment(Path(output), analysis_run, Path(root_dir), tuple(changes))


def resolve_analysis_run(run_path=DEFAULT_ANALYSIS_RUN):
    path = Path(run_path)
    if not path.is_file():
        raise KphelperError(
            "analysis environment not found; create it with: kphelper rootfs make-analysis"
        )
    return path


def analysis_address_scope(run_path):
    config = load_qemu_run(run_path)
    return "stable for matching kernel and boot configuration" if "nokaslr" in config.cmdline.split() else "current boot only"
