from kphelper import core
from kphelper.core.ksym import guest_ksym_report
from kphelper.core.symbols import DEFAULT_SYMBOLS


def register(subparsers):
    parser = subparsers.add_parser(
        "ksym",
        help="boot/connect guest and extract symbols from /proc/kallsyms",
    )
    parser.add_argument(
        "-s",
        "--symbol",
        action="append",
        dest="symbols",
        help="symbol name to extract, can be repeated",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="print JSON output",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=8,
        help="shell command timeout in seconds, default: 8",
    )
    parser.add_argument(
        "--remote",
        nargs=2,
        metavar=("IP", "PORT"),
        help="connect to an existing remote shell instead of starting run.sh",
    )
    parser.set_defaults(handler=handle)
    return parser


def handle(args):
    names = tuple(args.symbols) if args.symbols else DEFAULT_SYMBOLS
    io = None
    try:
        if args.remote:
            io = core.remote_target(args.remote[0], int(args.remote[1]))
        else:
            io = core.local_target()
        print(guest_ksym_report(io, names, as_json=args.json, timeout=args.timeout))
    finally:
        core.close_session(io)
    return 0
