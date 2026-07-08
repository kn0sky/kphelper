from kphelper import core
from kphelper.core.checksec import detect_runsec
from kphelper.core.pwn import log


def register(subparsers):
    parser = subparsers.add_parser(
        "debug",
        help="start ./run.sh, upload exp if present, then connect kgdb",
    )
    parser.add_argument(
        "symbol",
        nargs="?",
        help="debug symbol file passed to gdb, default: auto-detect vmlinux",
    )
    parser.set_defaults(handler=handle)
    return parser


def handle(args):
    runsec = detect_runsec("run.sh")
    if runsec["KGDB"] != "Enabled":
        log.failure("run.sh gdbstub is disabled, add -s or -S/-gdb to qemu args")
        return 1
    if runsec["KASLR"] == "Enabled":
        log.warning("KASLR is enabled; fixed vmlinux symbols may be invalid until you leak base and add-symbol-file at runtime")

    symbol = args.symbol
    if symbol is None:
        found = core.find_vmlinux()
        symbol = str(found) if found else "vmlinux"

    core.build_only()
    io = None
    debugger = None
    try:
        io = core.local_target()
        core.upload_and_cd(io)
        debugger = core.kgdb(symbol)
        core.interact(io)
    finally:
        core.close_debugger(debugger)
        core.close_session(io)
    return 0
