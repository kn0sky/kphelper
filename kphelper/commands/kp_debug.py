from kphelper.core.debug import close_debugger, kgdb
from kphelper.core.discovery import find_vmlinux
from kphelper.core.pwn import log
from kphelper.core.runfile import create_debug_run_copy
from kphelper.core.session import interact, local_target, managed_session
from kphelper.core.workflow import build_only, upload_and_cd


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
    parser.add_argument(
        "--nokaslr",
        action="store_true",
        help="explicitly disable KASLR in the generated debug script",
    )
    parser.set_defaults(handler=handle)
    return parser


def handle(args):
    symbol = args.symbol
    if symbol is None:
        found = find_vmlinux()
        symbol = str(found) if found else "vmlinux"

    build_only()
    debug_run = create_debug_run_copy(nokaslr=args.nokaslr)
    log.success("generated debug run script: %s", debug_run)
    if args.nokaslr:
        log.warning("KASLR disabled in debug script by explicit request")
    else:
        log.info("preserved original kernel KASLR configuration")

    debugger = None
    try:
        with managed_session(local_target, "./" + str(debug_run)) as io:
            upload_and_cd(io)
            debugger = kgdb(symbol)
            interact(io)
    finally:
        close_debugger(debugger)
    return 0
