import argparse
import importlib
import pkgutil
import sys

from . import commands
from .core.errors import KphelperError
from .core.pwn import log


HELP_EPILOG = """\
current directory requirements:
  run/debug mode:
    required: ./run.sh
    debug also requires: symbol file and qemu gdbstub on localhost:1234
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

command extension:
  add command modules under kphelper/commands/
  file name format: kp_<command>.py
  each module exports: register(subparsers)

examples:
  kphelper checksec
  kphelper checksec rootfs.cpio
  kphelper run
  kphelper debug
  kphelper debug ./vmlinux
  kphelper debug ./module.ko
  kphelper remote 127.0.0.1 1337
"""


def load_command_modules():
    modules = []
    prefix = commands.COMMAND_PREFIX
    for module_info in pkgutil.iter_modules(commands.__path__):
        if not module_info.name.startswith(prefix):
            continue
        module_name = f"{commands.__name__}.{module_info.name}"
        modules.append(importlib.import_module(module_name))
    return modules


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
