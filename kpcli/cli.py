import argparse
import importlib
import sys

from . import commands
from .core.errors import KpcliError
from .core.pwn import log


HELP_EPILOG = """\
current directory requirements:
  run/debug mode:
    required: ./run.sh
    debug auto-generates .kpcli-run-debug.sh with -s -S
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
    kpcli init

  security inspection:
    kpcli checksec
    kpcli checksec rootfs.cpio.gz --no-color
    kpcli checksec --live
    kpcli checksec --all

  rootfs workflows:
    kpcli rootfs extract rootfs.cpio.gz --root .kpcli/rootfs
    kpcli rootfs repack .kpcli/rootfs -o repacked.cpio.gz
    kpcli rootfs make-analysis
    kpcli pack rootfs.cpio.gz -o packed-rootfs.cpio.gz

  kernel symbols:
    kpcli symbols
    kpcli symbols --refresh
    kpcli symbols --file ./vmlinux
    kpcli symbols --analysis --refresh

  target sessions:
    kpcli run
    kpcli debug ./vmlinux
    kpcli debug ./vmlinux --nokaslr
    kpcli remote 127.0.0.1 1337
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
    except KpcliError as e:
        log.failure(str(e))
        return 1
