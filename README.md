# kphelper

`kphelper` is a small CLI helper for local kernel pwn challenge workflows. It can start a local QEMU script, upload a statically compiled exploit, connect KGDB, connect remote shells, and inspect common kernel challenge security settings.

The intended runtime environment is Linux/WSL.

Supported baseline:

```text
Python >= 3.8
pwntools >= 4.12, < 5
```

## Install

From this repository:

```bash
pip3 install -e .
```

After installation, use:

```bash
kphelper
```

Running without arguments prints the help text.

Run the regression tests with:

```bash
python3 -m unittest
```

## Directory Requirements

For `run` and `debug` modes, run `kphelper` inside a challenge directory containing:

```text
run.sh
```

For `debug`, the directory should also contain the symbol file you pass to the command. If omitted, `kphelper` recursively searches the current tree for:

```text
vmlinux
```

Exploit upload is optional:

```text
exp.c    # compiled to exp before target startup
exp      # uploaded to /tmp/exp
```

If `exp.c` exists, it is compiled before QEMU is started. `kphelper` tries `musl-gcc` first and falls back to:

```bash
gcc -static -Os -s -o exp exp.c
```

If both compilers fail, the command exits before starting QEMU. If neither `exp.c` nor `exp` exists, upload is skipped.

The target shell prompt may be either:

```text
$ 
# 
```

After upload, `kphelper` checks the remote file size with `wc -c < /tmp/exp`. If verification succeeds, it switches to `/tmp`; it does not execute `/tmp/exp` automatically.

## Commands

### `kphelper run`

Compile `exp.c` if present, start local `./run.sh`, upload `exp` if available, switch to `/tmp`, then enter interactive mode.

```bash
kphelper run
```

### `kphelper debug [symbol]`

Pre-check `run.sh`, compile `exp.c` if present, start local `./run.sh`, prepare the target, then open KGDB in a tmux split.

```bash
kphelper debug
kphelper debug ./vmlinux
kphelper debug ./module.ko
```

The default symbol file is `vmlinux`.

`debug` requires `run.sh` to expose a QEMU gdbstub through `-s`, `-S`, or `-gdb`. If KASLR is detected, `kphelper` warns but continues.

For `vmlinux`, `kphelper` only connects with:

```text
target remote localhost:1234
```

For `.ko` files, module symbols are not auto-loaded because the module base is runtime-dependent. GDB prints the manual steps:

```text
cat /sys/module/<module>/sections/.text
add-symbol-file <module.ko> <base>
```

### `kphelper remote <ip> <port>`

Compile `exp.c` if present, connect to a remote shell, upload `exp` if available, switch to `/tmp`, then enter interactive mode.

```bash
kphelper remote 127.0.0.1 1337
```

### `kphelper pack [cpio]`

Inject `exp` into an initramfs and update `run.sh` to use the repacked archive. This is the offline fallback path for challenges where shell upload is inconvenient or unavailable.

```bash
kphelper pack
kphelper pack rootfs.cpio
kphelper pack rootfs.cpio.gz -o packed-rootfs.cpio.gz
kphelper pack --target tmp/exp --no-update-run
```

Default behavior:

```text
1. compile exp.c to exp if exp.c exists
2. find the initramfs from run.sh -initrd or current tree
3. unpack it into ./root-pack
4. copy exp to ./root-pack/tmp/exp and chmod 755
5. repack as newc+gzip into packed-rootfs.cpio.gz
6. backup run.sh to run.sh.bak
7. rewrite run.sh -initrd to point to packed-rootfs.cpio.gz
```

Current limitation: `pack` only rewrites direct `-initrd path` arguments. It does not rewrite variable-built QEMU arguments.

### `kphelper checksec [cpio]`

Inspect common kernel challenge security settings from `run.sh`. Optionally unpack an initramfs cpio into `./root` and scan its `init`.
If the cpio path is omitted, `kphelper` first tries the `-initrd` path in `run.sh`, then recursively searches the current tree for common rootfs/initramfs files.

```bash
kphelper checksec
kphelper checksec rootfs.cpio
kphelper checksec rootfs.cpio.gz --root root
kphelper checksec -r ./run.sh rootfs.cpio --no-color
```

The output uses color by default:

- Green: enabled or favorable status
- Red: disabled, missing, or risky status
- Yellow: unknown
- Cyan: paths and informational values

Current limitation: `checksec` parses `run.sh` statically with regexes. It works for ordinary direct QEMU invocations, but does not reliably resolve shell variables or argument construction such as:

```bash
cmdline="console=ttyS0 nokaslr"
qemu-system-x86_64 -append "$cmdline"
```

In those cases `Unknown` means "not statically resolved", not necessarily disabled or absent.

## Command Extension

Commands are loaded dynamically from:

```text
kphelper/commands/
```

Command files must use the prefix:

```text
kp_<command>.py
```

Each command module exports:

```python
def register(subparsers):
    parser = subparsers.add_parser("name", help="...")
    parser.set_defaults(handler=handle)
    return parser


def handle(args):
    ...
    return 0
```

For example, `kphelper/commands/kp_snapshot.py` automatically becomes:

```bash
kphelper snapshot
```

Shared reusable logic lives under:

```text
kphelper/core/
```
