from kphelper.core.symbols import DEFAULT_SYMBOLS, symbols_report


def register(subparsers):
    parser = subparsers.add_parser(
        "symbols",
        help="extract common kernel symbol addresses from vmlinux",
    )
    parser.add_argument(
        "symbol_file",
        nargs="?",
        help="symbol file, default: auto-detect vmlinux",
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
    parser.set_defaults(handler=handle)
    return parser


def handle(args):
    names = tuple(args.symbols) if args.symbols else DEFAULT_SYMBOLS
    print(symbols_report(args.symbol_file, names, as_json=args.json))
    return 0
