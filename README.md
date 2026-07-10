# kphelper

`kphelper` is a small CLI helper for local kernel pwn challenge workflows. It can start a local QEMU script, upload a statically compiled exploit, connect KGDB, connect remote shells, inspect common kernel challenge security settings, and repack initramfs images.

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

## How the project is organized

The code is split into four layers:

- `kphelper/commands/`
  - command entry points and argument parsing
- `kphelper/core/`
  - reusable implementation logic
- `tests/`
  - automated regression tests
- `README.md` and docs files
  - usage and developer guidance

If you are new to the project, start with:

- `kphelper/cli.py`
- `kphelper/commands/kp_run.py`
- `kphelper/core/session.py`
- `kphelper/core/workflow.py`
- `kphelper/core/checksec.py`
- `kphelper/core/symbols.py`
- `kphelper/core/ksym.py`

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

### `kphelper init`

Create an `exp.c` kernel pwn skeleton in the current directory.

```bash
kphelper init
kphelper init -o exploit.c
kphelper init --force
```

The template includes notes for:

- `open /dev/xxx`
- `save_state()`
- userland return shell stubs
- `commit_creds` / `prepare_kernel_cred` ROP
- `msg_msg` / `userfaultfd` / `modprobe_path` primitives

### `kphelper run`

Compile `exp.c` if present, start local `./run.sh`, upload `exp` if available, switch to `/tmp`, then enter interactive mode.

```bash
kphelper run
```

### `kphelper debug [symbol]`

Generate a temporary debug copy of `run.sh`, preserve its original KASLR configuration, inject `-s -S`, compile `exp.c` if present, start that temporary script, prepare the target, then open KGDB in a tmux split. Pass `--nokaslr` only when you explicitly want the generated debug environment to disable KASLR.

```bash
kphelper debug
kphelper debug ./vmlinux
kphelper debug ./module.ko
kphelper debug --nokaslr
```

The default symbol file is `vmlinux`.

The original `run.sh` is not modified. The temporary debug script is `.kphelper-run-debug.sh`.

For `vmlinux`, `kphelper` only connects with:

```text
target remote localhost:1234
```

For `.ko` files, module symbols are not auto-loaded because the module base is runtime-dependent. GDB prints the manual steps:

```text
cat /sys/module/<module>/sections/.text
add-symbol-file <module.ko> <base>
```

### `kphelper symbols`

Extract kernel symbols. Runtime extraction from the guest `/proc/kallsyms` is the default; use `--file` for static `vmlinux` extraction.

```bash
kphelper symbols
kphelper symbols --run ./run.sh
kphelper symbols --remote 127.0.0.1 1337
kphelper symbols --file ./vmlinux
kphelper symbols -s commit_creds -s prepare_kernel_cred
kphelper symbols --json
```

Runtime mode waits for a verified guest shell prompt. `--boot-timeout` controls QEMU boot waiting and `--command-timeout` controls each guest command. Ensure QEMU uses serial stdio (`-nographic` or equivalent), does not run in the background, and does not include `-S` unless a debugger resumes the CPU.

If a matching local `vmlinux` and a common anchor such as `_stext` are both available, runtime mode calculates and displays the KASLR slide. Otherwise it emphasizes the detected KASLR state and explains that the slide cannot be calculated.

Default symbols:

```text
commit_creds
prepare_kernel_cred
init_cred
init_task
modprobe_path
core_pattern
poweroff_cmd
swapgs_restore_regs_and_return_to_usermode
entry_SYSCALL_64_after_hwframe
find_task_by_vpid
switch_task_namespaces
init_nsproxy
kernel_read_file
call_usermodehelper_exec
```

Default output is C macro style for quick copy/paste into `exp.c`.

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
kphelper checksec --live
kphelper checksec --all --boot-timeout 30
```

The default mode performs static analysis only. `--live` starts `run.sh` and performs runtime probes only. `--all` always renders the static report and then appends live results; if no interactive guest shell is reached, the live section is marked `Skipped` instead of discarding the static report. Use `--boot-timeout` and `--command-timeout` for slow guests.

Live probes only supplement information that static analysis cannot confirm. For example, statically detected `kptr_restrict` and `dmesg_restrict` values are reused rather than read again. Permission-dependent probes are reported as `Skipped` or `Hidden` instead of aborting the complete report.

The output uses color by default:

- Green: enabled or favorable status
- Red: disabled, missing, or risky status
- Yellow: unknown
- Cyan: paths and informational values

Implementation note: the `checksec` output renderer now lives in `kphelper/core/checksec_report.py`, while parsing and detection stay in `kphelper/core/checksec.py`.

Current limitation: `checksec` parses `run.sh` statically with regexes. It works for ordinary direct QEMU invocations, but does not reliably resolve shell variables or argument construction such as:

```bash
cmdline="console=ttyS0 nokaslr"
qemu-system-x86_64 -append "$cmdline"
```

In those cases `Unknown` means "not statically resolved", not necessarily disabled or absent.

## Privileged analysis rootfs

Create a separate local analysis image when the original guest drops privileges or restricts symbol information:

```bash
kphelper rootfs make-analysis --sudo
kphelper rootfs make-analysis rootfs.cpio.gz --sudo
```

`--sudo` runs only the extraction, target script installation, repacking, and required cleanup with elevated privileges so cpio ownership, permissions, and device nodes are preserved. The generated archive is returned to the invoking user. Running without `--sudo` remains available for initramfs images that contain no privileged metadata.

This creates `.kphelper/analysis-rootfs.cpio.gz` and `.kphelper/run-analysis.sh`. The original initramfs and `run.sh` are never modified. The generator makes only the supported final shell identity change and does not place backup scripts in startup directories.

Use the generated environment directly with runtime features:

```bash
kphelper symbols --analysis
kphelper checksec --live --analysis
kphelper checksec --all --analysis
```

The analysis image deliberately differs from the original privilege configuration and is intended only for local investigation. If the original command line enables KASLR, collected absolute addresses are valid for the current boot only. Module addresses can also depend on module load order even with `nokaslr`.

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

## Developer templates

### Command template

A copyable command template is available at:

```text
kphelper/commands/kp_example.py
```

It shows how to structure a new command module and explains which parts belong in `commands/` and which parts should be moved into `core/`.