import json
import os
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path

from .errors import KpcliError


CPIO_MARKER = ".kpcli-cpio-source"
LEGACY_CPIO_MARKER = ".kphelper-cpio-source"


def sh_quote(value):
    return "'" + value.replace("'", "'\"'\"'") + "'"


def cpio_command(cpio_path):
    name = str(cpio_path)
    if name.endswith(".gz"):
        return f"gzip -dc {sh_quote(name)} | cpio -idm --quiet"
    if name.endswith(".xz"):
        return f"xz -dc {sh_quote(name)} | cpio -idm --quiet"
    if name.endswith(".bz2"):
        return f"bzip2 -dc {sh_quote(name)} | cpio -idm --quiet"
    if name.endswith(".lz4"):
        return f"lz4 -dc {sh_quote(name)} | cpio -idm --quiet"
    return f"cpio -idm --quiet < {sh_quote(name)}"


def source_fingerprint(path):
    stat_result = path.stat()
    return {
        "source": str(path),
        "size": stat_result.st_size,
        "mtime_ns": stat_result.st_mtime_ns,
    }


def read_marker(marker):
    try:
        value = json.loads(marker.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else None
    except (OSError, ValueError):
        return None


@contextmanager
def preserved_metadata_state(state_path=None):
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        yield None
        return
    if not shutil.which("fakeroot"):
        raise KpcliError("fakeroot not found; install fakeroot for initramfs operations")
    if state_path is not None:
        state_path = Path(state_path).resolve()
        state_path.parent.mkdir(parents=True, exist_ok=True)
        yield state_path
        return
    with tempfile.TemporaryDirectory(prefix="kpcli-fakeroot-") as temporary:
        yield Path(temporary) / "state"


def run_cpio_command(
    command,
    cwd,
    fakeroot_state=None,
    load_state=False,
    command_args=(),
):
    arguments = ["bash", "-o", "pipefail", "-c", command]
    if command_args:
        arguments.extend(["bash"] + [str(argument) for argument in command_args])
    if fakeroot_state is not None:
        state_option = "-i" if load_state else "-s"
        arguments = ["fakeroot", state_option, str(fakeroot_state), "--"] + arguments
    environment = os.environ.copy()
    if fakeroot_state is not None:
        environment["FAKEROOTDONTTRYCHOWN"] = "1"
    subprocess.run(arguments, cwd=cwd, check=True, env=environment)


def unpack_cpio(cpio_path, root_dir="root", reuse_existing=True, fakeroot_state=None):
    cpio_path = Path(cpio_path).resolve()
    if not cpio_path.is_file():
        raise KpcliError("initramfs not found: %s" % cpio_path)
    root_dir = Path(root_dir)
    root_dir.mkdir(parents=True, exist_ok=True)

    marker = root_dir / CPIO_MARKER
    fingerprint = source_fingerprint(cpio_path)
    if reuse_existing and read_marker(marker) == fingerprint:
        return root_dir

    if any(root_dir.iterdir()):
        if not marker.exists():
            raise KpcliError(
                "refusing to replace non-empty directory without %s marker: %s"
                % (CPIO_MARKER, root_dir)
            )
        shutil.rmtree(root_dir)
        root_dir.mkdir(parents=True)

    cmd = cpio_command(cpio_path)
    try:
        run_cpio_command(cmd, root_dir, fakeroot_state=fakeroot_state)
    except FileNotFoundError as error:
        raise KpcliError("bash not found; initramfs operations require Linux/WSL") from error
    except subprocess.CalledProcessError as error:
        raise KpcliError("failed to unpack %s, exit code: %d" % (cpio_path, error.returncode)) from error

    marker.write_text(json.dumps(fingerprint, indent=2), encoding="utf-8")
    return root_dir
