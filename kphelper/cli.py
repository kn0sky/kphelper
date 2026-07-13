import argparse
import importlib
import sys

from . import commands
from .core.errors import KphelperError
from .core.pwn import log


HELP_EPILOG = """\
current directory requirements:
  run/debug mode:
    required: ./run.sh
    debug auto-generates .kphelper-run-debug.sh with -s -S
    pass --nokaslr to explicitly disable KASLR in the debug copy
    debug also requires: symbol file
    default debug symbol file: ./vmlinux

  remote mode:
    required: target shell is already reachable at ip:port
    not required: ./run.sh, symbol file

  exploit upload:
    optional: ./exp.c  -> compile with: musl-gcc -static -o exp exp.c
    optional: ./exp    -> upload to: /tmp/exp
    if neither exp.c nor exp exists, upload is skipped
    after upload, helper only runs: cd /tmp

target shell prompt:
  supported prompts: "$ " and "# "

examples:
  project setup:
    kphelper init

  security inspection:
    kphelper checksec
    kphelper checksec rootfs.cpio.gz --no-color
    kphelper checksec --live
    kphelper checksec --all

  rootfs workflows:
    kphelper rootfs extract rootfs.cpio.gz --root .kphelper/rootfs
    kphelper rootfs repack .kphelper/rootfs -o repacked.cpio.gz
    kphelper rootfs make-analysis
    kphelper pack rootfs.cpio.gz -o packed-rootfs.cpio.gz

  kernel symbols:
    kphelper symbols
    kphelper symbols --refresh
    kphelper symbols --file ./vmlinux
    kphelper symbols --analysis --refresh

  target sessions:
    kphelper run
    kphelper debug ./vmlinux
    kphelper debug ./vmlinux --nokaslr
    kphelper remote 127.0.0.1 1337
"""


def load_command_modules():
    return [
        importlib.import_module(f"{commands.__name__}.{name}")
        for name in commands.COMMAND_MODULES
    ]


def build_parser():
    parser = argparse.ArgumentParser(
        description="kernel pwn helper: local run.sh / kgdb / remote upload helper",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=HELP_EPILOG,
    )
    subparsers = parser.add_subparsers(dest="mode")

    for module in load_command_modules():
        register = getattr(module, "register", None)
        if register is None:
            continue
        register(subparsers)

    return parser


def parse_args(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    parser = build_parser()
    if not argv:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args(argv)
    if not hasattr(args, "handler"):
        parser.print_help()
        sys.exit(1)
    return args


def main(argv=None):
    args = parse_args(argv)
    try:
        return args.handler(args)
    except KeyboardInterrupt:
        log.failure("interrupted")
        return 130
    except KphelperError as e:
        log.failure(str(e))
        return 1
