import shutil
import subprocess
from pathlib import Path

from .build import build_exp
from .checksec import detect_runsec, resolve_initrd_path
from .constants import LOCAL_EXP
from .cpio import sh_quote, unpack_cpio
from .discovery import find_cpio
from .errors import KphelperError
from .pwn import log
from .runfile import update_run_initrd


DEFAULT_PACK_ROOT = "root-pack"
DEFAULT_OUTPUT = "packed-rootfs.cpio.gz"
DEFAULT_TARGET = "tmp/exp"


def select_cpio(run_path="run.sh", cpio_path=None):
    if cpio_path:
        return Path(cpio_path)

    runsec = detect_runsec(run_path)
    found = resolve_initrd_path(runsec["Initrd"], run_path)
    if found:
        return found

    found = find_cpio()
    if found:
        return found

    raise KphelperError("cannot find initramfs cpio; pass it explicitly: kphelper pack <cpio>")


def ensure_clean_pack_root(root_dir):
    root_dir = Path(root_dir)
    resolved = root_dir.resolve()
    cwd = Path.cwd().resolve()
    if resolved in {cwd, cwd.parent, Path(resolved.anchor)}:
        raise KphelperError("refusing unsafe pack root: %s" % root_dir)
    if root_dir.name in {"", ".", ".."}:
        raise KphelperError("refusing unsafe pack root: %s" % root_dir)
    if root_dir.exists() and not root_dir.is_dir():
        raise KphelperError("pack root exists and is not a directory: %s" % root_dir)
    if root_dir.exists():
        shutil.rmtree(root_dir)
    root_dir.mkdir(parents=True)
    return root_dir


def copy_exp_into_root(root_dir, local_exp=LOCAL_EXP, target=DEFAULT_TARGET):
    local_exp = Path(local_exp)
    if not local_exp.exists():
        raise KphelperError("exp not found; provide exp or exp.c before packing")

    target_path = Path(root_dir) / target
    target_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(local_exp, target_path)
    target_path.chmod(0o755)
    log.success("packed %s -> %s", local_exp, target_path)
    return target_path


def repack_cpio(root_dir, output):
    root_dir = Path(root_dir)
    output_path = Path(output)
    try:
        output_path.resolve().relative_to(root_dir.resolve())
    except ValueError:
        pass
    else:
        raise KphelperError("output must not be inside pack root: %s" % output_path)
    cmd_output = output_path.resolve()
    cmd = "find . | cpio -o -H newc --quiet | gzip -9 > %s" % sh_quote(str(cmd_output))
    try:
        subprocess.run(["bash", "-o", "pipefail", "-c", cmd], cwd=root_dir, check=True)
    except FileNotFoundError as error:
        raise KphelperError("bash not found; initramfs operations require Linux/WSL") from error
    except subprocess.CalledProcessError as error:
        raise KphelperError("failed to repack %s, exit code: %d" % (output_path, error.returncode)) from error
    log.success("repacked initramfs -> %s", output_path)
    return output_path


def pack_exp(cpio_path=None, run_path="run.sh", root_dir=DEFAULT_PACK_ROOT, output=DEFAULT_OUTPUT, target=DEFAULT_TARGET, update_run=True):
    build_exp()
    cpio_path = select_cpio(run_path, cpio_path)
    root_dir = ensure_clean_pack_root(root_dir)
    unpack_cpio(cpio_path, root_dir)
    copy_exp_into_root(root_dir, LOCAL_EXP, target)
    output = repack_cpio(root_dir, output)
    if update_run:
        update_run_initrd(run_path, output)
        log.success("updated %s initrd -> %s", run_path, output)
    return output
