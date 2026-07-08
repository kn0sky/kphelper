from pathlib import Path


SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".venv",
    "venv",
    "env",
    "root",
}

CPIO_SUFFIXES = (
    ".cpio",
    ".cpio.gz",
    ".cpio.xz",
    ".cpio.bz2",
    ".cpio.lz4",
    ".img",
    ".initramfs",
)


def iter_files(base="."):
    base = Path(base)
    for path in base.rglob("*"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.is_file():
            yield path


def prefer_shortest(paths):
    paths = list(paths)
    if not paths:
        return None
    return sorted(paths, key=lambda path: (len(path.parts), str(path)))[0]


def find_vmlinux(base="."):
    return prefer_shortest(path for path in iter_files(base) if path.name == "vmlinux")


def is_cpio_candidate(path):
    name = path.name.lower()
    if any(name.endswith(suffix) for suffix in CPIO_SUFFIXES):
        return True
    return "rootfs" in name or "initramfs" in name


def find_cpio(base="."):
    return prefer_shortest(path for path in iter_files(base) if is_cpio_candidate(path))
