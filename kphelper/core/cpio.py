import shutil
import subprocess
from pathlib import Path

from .errors import KphelperError


CPIO_MARKER = ".kphelper-cpio-source"


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


def unpack_cpio(cpio_path, root_dir="root", reuse_existing=True):
    cpio_path = Path(cpio_path).resolve()
    root_dir = Path(root_dir)
    root_dir.mkdir(exist_ok=True)

    marker = root_dir / CPIO_MARKER
    if reuse_existing and marker.exists():
        try:
            if marker.read_text(errors="replace").strip() == str(cpio_path):
                return root_dir
        except OSError:
            pass

    if reuse_existing and any(root_dir.iterdir()):
        shutil.rmtree(root_dir)
        root_dir.mkdir(exist_ok=True)

    cmd = cpio_command(cpio_path)
    try:
        subprocess.run(cmd, shell=True, cwd=root_dir, check=True)
    except subprocess.CalledProcessError as e:
        raise KphelperError("failed to unpack %s, exit code: %d" % (cpio_path, e.returncode)) from e

    marker.write_text(str(cpio_path))
    return root_dir
