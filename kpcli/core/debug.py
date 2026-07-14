from pathlib import Path
import os
import signal

from .discovery import find_vmlinux
from .errors import KpcliError


def kgdb(symbol_file="vmlinux"):
    try:
        from pwnlib.util.misc import run_in_new_terminal
    except ImportError as error:
        raise KpcliError(
            "pwntools is required for debug sessions; install with: pip install 'pwntools>=4.12,<5'"
        ) from error

    symbol_path = Path(symbol_file)
    is_module = symbol_path.suffix == ".ko"
    gdb_file = str(find_vmlinux() or "vmlinux") if is_module else str(symbol_file)

    # 连 qemu gdbserver,不是 attach 进程
    cmd = [
        "gdb", gdb_file,
        "-ex", "set architecture i386:x86-64",
        "-ex", "target remote localhost:1234",
    ]
    if is_module:
        module_name = symbol_path.stem
        cmd.extend([
            "-ex",
            f"echo Module symbols not auto-loaded for {symbol_file}.\\n",
            "-ex",
            f"echo In guest: cat /sys/module/{module_name}/sections/.text\\n",
            "-ex",
            f"echo Then in gdb: add-symbol-file {symbol_file} <base>\\n",
        ])
    # "-ex", "b prepare_kernel_cred",   # 按需下断
    try:
        return run_in_new_terminal(cmd)   # 在 tmux 右屏开 gdb
    except Exception as error:
        raise KpcliError("failed to start GDB terminal: %s" % error) from error


def close_debugger(handle):
    if handle is None:
        return
    try:
        if isinstance(handle, int):
            os.kill(handle, signal.SIGTERM)
            return
        if hasattr(handle, "terminate"):
            handle.terminate()
    except Exception:
        pass
