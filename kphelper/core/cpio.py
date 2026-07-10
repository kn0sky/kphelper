import json
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


def unpack_cpio(cpio_path, root_dir="root", reuse_existing=True):
    cpio_path = Path(cpio_path).resolve()
    if not cpio_path.is_file():
        raise KphelperError("initramfs not found: %s" % cpio_path)
    root_dir = Path(root_dir)
    root_dir.mkdir(parents=True, exist_ok=True)

    marker = root_dir / CPIO_MARKER
    fingerprint = source_fingerprint(cpio_path)
    if reuse_existing and read_marker(marker) == fingerprint:
        return root_dir

    if any(root_dir.iterdir()):
        if not marker.exists():
            raise KphelperError(
                "refusing to replace non-empty directory without %s marker: %s"
                % (CPIO_MARKER, root_dir)
            )
        shutil.rmtree(root_dir)
        root_dir.mkdir(parents=True)

    cmd = cpio_command(cpio_path)
    try:
        subprocess.run(["bash", "-o", "pipefail", "-c", cmd], cwd=root_dir, check=True)
    except FileNotFoundError as error:
        raise KphelperError("bash not found; initramfs operations require Linux/WSL") from error
    except subprocess.CalledProcessError as error:
        raise KphelperError("failed to unpack %s, exit code: %d" % (cpio_path, error.returncode)) from error

    marker.write_text(json.dumps(fingerprint, indent=2), encoding="utf-8")
    return root_dir
