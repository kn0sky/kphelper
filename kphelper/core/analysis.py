import json
import os
import re
import shutil
import subprocess
import tempfile
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
    pattern = r"(?m)^(\s*setsid\s+cttyhack\s+setuidgid\s+)1337(\s+sh\s*)$"
    modified, count = re.subn(pattern, r"\g<1>0\g<2>", text)
    changes = []
    if count:
        changes.append("changed setsid cttyhack setuidgid 1337 sh to UID/GID 0")
    return modified, changes


def _startup_files(root_dir):
    root_dir = Path(root_dir)
    candidates = [root_dir / "init", root_dir / "etc/inittab", root_dir / "etc/rcS"]
    init_d = root_dir / "etc/init.d"
    try:
        if init_d.is_dir():
            candidates.extend(sorted(path for path in init_d.iterdir() if path.is_file()))
        return [path for path in candidates if path.is_file()]
    except PermissionError as error:
        raise KphelperError(
            "cannot read privileged analysis root; rerun the command with sudo access"
        ) from error


def prepare_analysis_root(root_dir, install_file=None):
    files = _startup_files(root_dir)
    if not files:
        raise KphelperError("analysis rootfs has no supported startup scripts")

    changes = []
    for path in files:
        original = path.read_text(encoding="utf-8", errors="replace")
        patched, file_changes = _patch_init_for_root(original)
        if patched == original:
            continue
        if install_file:
            install_file(path, patched)
        else:
            path.write_text(patched, encoding="utf-8")
        changes.extend("%s: %s" % (path.relative_to(root_dir), change) for change in file_changes)

    if not changes:
        raise KphelperError(
            "cannot find exact startup line: setsid cttyhack setuidgid 1337 sh"
        )
    return changes


def _sudo_run(arguments, cwd=None):
    try:
        subprocess.run(["sudo"] + list(arguments), cwd=cwd, check=True)
    except FileNotFoundError as error:
        raise KphelperError("sudo not found; privileged analysis requires sudo") from error
    except subprocess.CalledProcessError as error:
        raise KphelperError("privileged analysis command failed, exit code: %d" % error.returncode) from error


def _validate_analysis_root(root_dir):
    root_dir = Path(root_dir)
    resolved = root_dir.resolve()
    cwd = Path.cwd().resolve()
    if resolved in {cwd, cwd.parent, Path(resolved.anchor)} or root_dir.name in {"", ".", ".."}:
        raise KphelperError("refusing unsafe analysis root: %s" % root_dir)
    return root_dir


def _privileged_unpack(source, root_dir):
    from .cpio import cpio_command

    root_dir = _validate_analysis_root(root_dir)
    _sudo_run(["-v"])
    if root_dir.exists():
        _sudo_run(["rm", "-rf", "--", str(root_dir.resolve())])
    root_dir.mkdir(parents=True)
    _sudo_run(["bash", "-o", "pipefail", "-c", cpio_command(Path(source).resolve())], cwd=root_dir)
    return root_dir


def _privileged_installer(path, content):
    mode = path.stat().st_mode & 0o7777
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as temporary:
        temporary.write(content)
        temporary_path = Path(temporary.name)
    try:
        _sudo_run(["install", "-m", "%o" % mode, "--", str(temporary_path), str(path.resolve())])
    finally:
        temporary_path.unlink(missing_ok=True)


def _privileged_repack(root_dir, output):
    output = Path(output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    command = "find . -print0 | cpio -o --format=newc --null --quiet | gzip -9 > \"$1\""
    _sudo_run(["bash", "-o", "pipefail", "-c", command, "bash", str(output)], cwd=root_dir)
    if hasattr(os, "getuid") and hasattr(os, "getgid"):
        _sudo_run(["chown", "%d:%d" % (os.getuid(), os.getgid()), "--", str(output)])
    return output


def create_analysis_environment(
    cpio_path=None,
    run_path="run.sh",
    root_dir=DEFAULT_ANALYSIS_ROOT,
    output=DEFAULT_ANALYSIS_CPIO,
    analysis_run=DEFAULT_ANALYSIS_RUN,
    privileged=False,
):
    from .pack import ensure_clean_pack_root, repack_cpio, select_cpio

    source = select_cpio(run_path, cpio_path)
    if privileged:
        root_dir = _privileged_unpack(source, root_dir)
        changes = prepare_analysis_root(root_dir, install_file=_privileged_installer)
    else:
        root_dir = ensure_clean_pack_root(root_dir)
        unpack_cpio(source, root_dir, reuse_existing=False)
        changes = prepare_analysis_root(root_dir)

    manifest = {
        "source_cpio": str(Path(source).resolve()),
        "source_run": str(Path(run_path).resolve()),
        "privileged": privileged,
        "modifications": changes,
        "warning": "analysis environment only; runtime addresses may be boot-specific when KASLR is enabled",
    }
    manifest_path = Path(output).parent / "analysis-manifest.json"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    output = _privileged_repack(root_dir, output) if privileged else repack_cpio(root_dir, output)

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
