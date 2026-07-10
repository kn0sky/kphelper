from kphelper.core.checksec import detect_runsec
from kphelper.core.errors import KphelperError
from kphelper.core.guest import add_guest_timeout_arguments, timeouts_from_args
from kphelper.core.ksym import extract_guest_ksyms
from kphelper.core.session import managed_session, local_target, remote_target
from kphelper.core.symbols import (
    DEFAULT_SYMBOLS,
    KASLR_ANCHORS,
    calculate_kaslr_slide,
    extract_symbols,
    render_symbols,
)


def register(subparsers):
    parser = subparsers.add_parser(
        "symbols",
        help="extract kernel symbols; runtime /proc/kallsyms mode is the default",
    )
    parser.add_argument("--file", help="use static vmlinux extraction instead of runtime mode")
    parser.add_argument("-s", "--symbol", action="append", dest="symbols", help="symbol to extract; repeatable")
    parser.add_argument("--run", default="run.sh", help="QEMU startup script, default: run.sh")
    parser.add_argument("--remote", nargs=2, metavar=("IP", "PORT"), help="probe an existing remote shell")
    add_guest_timeout_arguments(parser)
    parser.add_argument("--json", action="store_true", help="print JSON output")
    parser.set_defaults(handler=handle)
    return parser


def _runtime_symbols(args, names):
    requested = tuple(dict.fromkeys(tuple(names) + KASLR_ANCHORS))
    if args.remote:
        factory, factory_args = remote_target, (args.remote[0], int(args.remote[1]))
        source = "guest:/proc/kallsyms"
    else:
        run_result = detect_runsec(args.run)
        if run_result["run.sh"] == "Missing":
            raise KphelperError("%s not found" % args.run)
        factory, factory_args = local_target, (args.run,)
        source = "guest:/proc/kallsyms"

    with managed_session(factory, *factory_args) as io:
        runtime = extract_guest_ksyms(
            io,
            requested,
            timeouts=timeouts_from_args(args),
        )

    kaslr = {"status": "Unknown", "detail": "runtime symbols collected; no vmlinux available to calculate slide"}
    try:
        symbol_file, static = extract_symbols(None, requested)
    except KphelperError:
        symbol_file, static = None, {}
    anchor, slide = calculate_kaslr_slide(runtime, static)
    if slide is not None:
        kaslr = {
            "status": "Enabled" if slide else "Disabled",
            "anchor": anchor,
            "slide": slide,
            "detail": "calculated from runtime and vmlinux anchor addresses",
        }
    elif not args.remote:
        state = detect_runsec(args.run)["KASLR"]
        kaslr = {"status": state, "detail": "from run.sh; slide requires a matching vmlinux anchor"}
    return render_symbols(source, runtime, names, as_json=args.json, kaslr=kaslr)


def handle(args):
    names = tuple(args.symbols) if args.symbols else DEFAULT_SYMBOLS
    if args.file:
        symbol_file, symbols = extract_symbols(args.file, names)
        kaslr = {"status": "Static only", "detail": "addresses are link-time values; runtime slide is not available"}
        print(render_symbols(symbol_file, symbols, names, as_json=args.json, kaslr=kaslr))
        return 0
    print(_runtime_symbols(args, names))
    return 0
