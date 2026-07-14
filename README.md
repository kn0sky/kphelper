# kpcli

`kpcli` is a small CLI helper for local kernel pwn challenge workflows. It can start a local QEMU script, upload a statically compiled exploit, connect KGDB, connect remote shells, inspect common kernel challenge security settings, and repack initramfs images.

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
kpcli
```

Running without arguments prints the help text.

Run the regression tests with:

```bash
python3 -m unittest
```

## How the project is organized

The code is split into four layers:

- `kpcli/commands/`
  - command entry points and argument parsing
- `kpcli/core/`
  - reusable implementation logic
- `tests/`
  - automated regression tests
- `README.md` and docs files
  - usage and developer guidance

If you are new to the project, start with:

- `kpcli/cli.py`
- `kpcli/commands/kp_run.py`
- `kpcli/core/session.py`
- `kpcli/core/checksec.py`
- `kpcli/core/symbols.py`
- `kpcli/core/ksym.py`

## Directory Requirements

For `run` and `debug` modes, run `kpcli` inside a challenge directory containing:

```text
run.sh
```

For `debug`, the directory should also contain the symbol file you pass to the command. If omitted, `kpcli` recursively searches the current tree for:

```text
vmlinux
```

Exploit upload is optional:

```text
exp.c    # compiled to exp before target startup
exp      # uploaded to /tmp/exp
```

If `exp.c` exists, it is compiled before QEMU is started. `kpcli` tries `musl-gcc` first and falls back to:

```bash
gcc -static -Os -s -o exp exp.c
```

If both compilers fail, the command exits before starting QEMU. If neither `exp.c` nor `exp` exists, upload is skipped.

The target shell prompt may be either:

```text
$ 
# 
```

After upload, `kpcli` checks the remote file size with `wc -c < /tmp/exp`. If verification succeeds, it switches to `/tmp`; it does not execute `/tmp/exp` automatically.

## Commands

### `kpcli init`

Create an `exp.c` kernel pwn skeleton in the current directory.

```bash
kpcli init
kpcli init -o exploit.c
kpcli init --force
```

The template includes notes for:

- `open /dev/xxx`
- `save_state()`
- userland return shell stubs
- `commit_creds` / `prepare_kernel_cred` ROP
- `msg_msg` / `userfaultfd` / `modprobe_path` primitives

### `kpcli run`

Compile `exp.c` if present, start local `./run.sh`, upload `exp` if available, switch to `/tmp`, then enter interactive mode.

```bash
kpcli run
```

### `kpcli debug [symbol]`

Generate a temporary debug copy of `run.sh`, preserve its original KASLR configuration, inject `-s -S`, compile `exp.c` if present, start that temporary script, prepare the target, then open KGDB in a tmux split. Pass `--nokaslr` only when you explicitly want the generated debug environment to disable KASLR.

```bash
kpcli debug
kpcli debug ./vmlinux
kpcli debug ./module.ko
kpcli debug --nokaslr
```

The default symbol file is `vmlinux`.

The original `run.sh` is not modified. The temporary debug script is `.kpcli-run-debug.sh`.

For `vmlinux`, `kpcli` only connects with:

```text
target remote localhost:1234
```

For `.ko` files, module symbols are not auto-loaded because the module base is runtime-dependent. GDB prints the manual steps:

```text
cat /sys/module/<module>/sections/.text
add-symbol-file <module.ko> <base>
```

### `kpcli symbols`

Extract kernel symbols. Runtime extraction from the guest `/proc/kallsyms` is the default; use `--file` for static `vmlinux` extraction.

```bash
kpcli symbols
kpcli symbols --run ./run.sh
kpcli symbols --remote 127.0.0.1 1337
kpcli symbols --file ./vmlinux
kpcli symbols -s commit_creds -s prepare_kernel_cred
kpcli symbols -p
kpcli symbols --json
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

Default output is C macro style for quick copy/paste into `exp.c`. Pass `-p` to
render callable symbols as C function pointers; data symbols and stable KASLR
offsets remain integer assignments.

### `kpcli remote <ip> <port>`

Compile `exp.c` if present, connect to a remote shell, upload `exp` if available, switch to `/tmp`, then enter interactive mode.

```bash
kpcli remote 127.0.0.1 1337
```

### `kpcli pack [cpio]`

Inject `exp` into an initramfs and update `run.sh` to use the repacked archive. This is the offline fallback path for challenges where shell upload is inconvenient or unavailable.

```bash
kpcli pack
kpcli pack rootfs.cpio
kpcli pack rootfs.cpio.gz -o packed-rootfs.cpio.gz
kpcli pack --target tmp/exp --no-update-run
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

### `kpcli checksec [cpio]`

Inspect common kernel challenge security settings from `run.sh`. Optionally unpack an initramfs cpio into the internal `.kpcli/checksec-root` cache and scan its startup scripts.
If the cpio path is omitted, `kpcli` first tries the `-initrd` path in `run.sh`, then recursively searches the current tree for common rootfs/initramfs files.

```bash
kpcli checksec
kpcli checksec rootfs.cpio
kpcli checksec rootfs.cpio.gz
kpcli checksec -r ./run.sh rootfs.cpio --no-color
kpcli checksec --live
kpcli checksec --live -p
kpcli checksec --all --boot-timeout 30
kpcli checksec --all
```

The default mode performs static analysis only. `--live` and `--all` automatically create a separate analysis rootfs with fakeroot, change the supported challenge shell from UID/GID 1337 to UID/GID 0, and boot the generated run script. `--live` renders runtime probes only. `--all` renders the generated rootfs static report and then appends live results; if no interactive guest shell is reached, the live section is marked `Skipped` instead of discarding the static report. Add `-p` to either live mode to render callable symbols as function pointers. Use `--boot-timeout` and `--command-timeout` for slow guests.

```bash
kpcli checksec --live
kpcli checksec --all
```

Live probes only supplement information that static analysis cannot confirm. For example, statically detected `kptr_restrict` and `dmesg_restrict` values are reused rather than read again. Permission-dependent probes are reported as `Skipped` or `Hidden` instead of aborting the complete report.

The output uses color by default:

- Green: enabled or favorable status
- Red: disabled, missing, or risky status
- Yellow: unknown
- Cyan: paths and informational values

Implementation note: the `checksec` output renderer now lives in `kpcli/core/checksec_report.py`, while parsing and detection stay in `kpcli/core/checksec.py`.

Current limitation: `checksec` parses `run.sh` statically with regexes. It works for ordinary direct QEMU invocations, but does not reliably resolve shell variables or argument construction such as:

```bash
cmdline="console=ttyS0 nokaslr"
qemu-system-x86_64 -append "$cmdline"
```

In those cases `Unknown` means "not statically resolved", not necessarily disabled or absent.

## Rootfs extraction and repacking

Extract an initramfs into a workspace without changing its contents:

```bash
kpcli rootfs extract
kpcli rootfs extract rootfs.cpio.gz
kpcli rootfs extract rootfs.cpio.gz --root .kpcli/rootfs
```

The default extraction directory is `.kpcli/rootfs`. The command stores fakeroot metadata beside it in `.kpcli/rootfs.fakeroot-state`, preserving ownership and device metadata across separate commands.

Repack the extracted tree without injecting files or rewriting `run.sh`:

```bash
kpcli rootfs repack
kpcli rootfs repack .kpcli/rootfs -o .kpcli/rootfs-repacked.cpio.gz
```

The extraction workspace contains only archive entries; fakeroot state is stored beside it. The internal `.kpcli-cpio-source` cache marker is also excluded defensively during repacking. Any edits made manually between extraction and repacking are included; kpcli applies no content changes by default. Repacking preserves paths, regular-file contents, modes, ownership, and device metadata, while archive ordering, compression, and some directory timestamps may differ.

## Analysis rootfs

Create a separate local analysis image when the original guest drops privileges or restricts symbol information:

```bash
kpcli rootfs make-analysis
kpcli rootfs make-analysis rootfs.cpio.gz
```

The flow uses `fakeroot` to preserve cpio ownership and device metadata without requesting a password. Set `FAKEROOTDONTTRYCHOWN=1` for fakeroot subprocesses so the workflow also operates inside user namespaces where real ownership changes are rejected.

This creates `.kpcli/analysis-rootfs.cpio.gz` and `.kpcli/run-analysis.sh`. The original initramfs and `run.sh` are never modified. The generator makes only the supported final shell identity change and does not place backup scripts in startup directories.

`checksec --live/--all` always creates this environment automatically. The standalone command remains available when only the generated files are needed:

```bash
kpcli symbols --analysis --refresh
kpcli checksec --live
kpcli checksec --all
```

The analysis image deliberately differs from the original privilege configuration and is intended only for local investigation. If the original command line enables KASLR, collected absolute addresses are valid for the current boot only. Module addresses can also depend on module load order even with `nokaslr`.

## Command Extension

Command entry points live under:

```text
kpcli/commands/
```

Each production command is explicitly listed in `kpcli/commands/__init__.py`. Command files use the prefix:

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

After adding `kpcli/commands/kp_snapshot.py`, register `kp_snapshot` in `COMMAND_MODULES` to expose:

```bash
kpcli snapshot
```

Shared reusable logic lives under:

```text
kpcli/core/
```
