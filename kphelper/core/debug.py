from pathlib import Path
import os
import signal

from pwnlib.util.misc import run_in_new_terminal

from .discovery import find_vmlinux


def kgdb(symbol_file="vmlinux"):
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
    return run_in_new_terminal(cmd)   # 在 tmux 右屏开 gdb


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
