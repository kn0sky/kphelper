import os
import shutil
import stat
import subprocess
from pathlib import Path

from .build import build_exp
from .constants import LOCAL_EXP
from .cpio import CPIO_MARKER, preserved_metadata_state, run_cpio_command, unpack_cpio
from .discovery import find_cpio
from .errors import KphelperError
from .pwn import log
from .qemu import load_qemu_run
from .runfile import update_run_initrd


DEFAULT_PACK_ROOT = "root-pack"
DEFAULT_OUTPUT = "packed-rootfs.cpio.gz"
DEFAULT_TARGET = "tmp/exp"
DEFAULT_ROOTFS_ROOT = ".kphelper/rootfs"
DEFAULT_ROOTFS_OUTPUT = ".kphelper/rootfs-repacked.cpio.gz"


def _make_directories_writable(root_dir):
    root_dir = Path(root_dir)
    root_dir.chmod(root_dir.stat().st_mode | stat.S_IRWXU)
    for current, directories, _files in os.walk(root_dir):
        current = Path(current)
        current.chmod(current.stat().st_mode | stat.S_IRWXU)
        directories[:] = [
            name for name in directories if not (current / name).is_symlink()
        ]


def select_cpio(run_path="run.sh", cpio_path=None):
    if cpio_path:
        return Path(cpio_path)

    if Path(run_path).is_file():
        config = load_qemu_run(run_path)
        found = config.resolve_file(config.initrd)
        if found and found.is_file():
            return found

    found = find_cpio(Path(run_path).parent)
    if found:
        return found

    raise KphelperError("cannot find initramfs cpio; pass the archive path explicitly")


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
        try:
            _make_directories_writable(root_dir)
            shutil.rmtree(root_dir)
        except OSError as error:
            raise KphelperError(
                "cannot clean %s; remove the root-owned directory with sudo and retry"
                % root_dir
            ) from error
    root_dir.mkdir(parents=True)
    return root_dir


def fakeroot_state_path(root_dir):
    root_dir = Path(root_dir)
    return root_dir.with_name(root_dir.name + ".fakeroot-state").resolve()


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


def repack_cpio(root_dir, output, fakeroot_state=None):
    root_dir = Path(root_dir)
    output_path = Path(output)
    try:
        output_path.resolve().relative_to(root_dir.resolve())
    except ValueError:
        pass
    else:
        raise KphelperError("output must not be inside pack root: %s" % output_path)
    cmd_output = output_path.resolve()
    cmd_output.parent.mkdir(parents=True, exist_ok=True)
    cmd = (
        "find . ! -path './%s' -print0 | "
        "cpio -o --format=newc --null --quiet | gzip -9 > \"$1\""
        % CPIO_MARKER
    )
    try:
        run_cpio_command(
            cmd,
            root_dir,
            fakeroot_state=fakeroot_state,
            load_state=fakeroot_state is not None and Path(fakeroot_state).is_file(),
            command_args=(cmd_output,),
        )
    except FileNotFoundError as error:
        raise KphelperError("bash not found; initramfs operations require Linux/WSL") from error
    except subprocess.CalledProcessError as error:
        raise KphelperError("failed to repack %s, exit code: %d" % (output_path, error.returncode)) from error
    log.success("repacked initramfs -> %s", output_path)
    return output_path


def extract_rootfs(cpio_path=None, run_path="run.sh", root_dir=DEFAULT_ROOTFS_ROOT):
    source = select_cpio(run_path, cpio_path)
    root_dir = ensure_clean_pack_root(root_dir)
    state_path = fakeroot_state_path(root_dir)
    state_path.unlink(missing_ok=True)
    with preserved_metadata_state(state_path) as fakeroot_state:
        unpack_cpio(
            source,
            root_dir,
            reuse_existing=False,
            fakeroot_state=fakeroot_state,
        )
    (Path(root_dir) / CPIO_MARKER).unlink(missing_ok=True)
    log.success("extracted initramfs -> %s", root_dir)
    return root_dir


def repack_rootfs(root_dir=DEFAULT_ROOTFS_ROOT, output=DEFAULT_ROOTFS_OUTPUT):
    root_dir = Path(root_dir)
    if not root_dir.is_dir():
        raise KphelperError("rootfs directory not found: %s" % root_dir)
    state_path = fakeroot_state_path(root_dir)
    fakeroot_state = state_path if state_path.is_file() else None
    if hasattr(os, "geteuid") and os.geteuid() != 0 and fakeroot_state is None:
        raise KphelperError(
            "fakeroot metadata state not found; extract with: kphelper rootfs extract"
        )
    return repack_cpio(root_dir, output, fakeroot_state=fakeroot_state)


def pack_exp(cpio_path=None, run_path="run.sh", root_dir=DEFAULT_PACK_ROOT, output=DEFAULT_OUTPUT, target=DEFAULT_TARGET, update_run=True):
    build_exp()
    cpio_path = select_cpio(run_path, cpio_path)
    with preserved_metadata_state() as fakeroot_state:
        root_dir = ensure_clean_pack_root(root_dir)
        unpack_cpio(
            cpio_path,
            root_dir,
            reuse_existing=False,
            fakeroot_state=fakeroot_state,
        )
        (Path(root_dir) / CPIO_MARKER).unlink(missing_ok=True)
        copy_exp_into_root(root_dir, LOCAL_EXP, target)
        output = repack_cpio(root_dir, output, fakeroot_state=fakeroot_state)
    if update_run:
        update_run_initrd(run_path, output)
        log.success("updated %s initrd -> %s", run_path, output)
    return output
