from kpcli.core.analysis import analysis_address_scope, resolve_analysis_run
from kpcli.core.checksec import detect_runsec
from kpcli.core.errors import KpcliError
from kpcli.core.findings import RuntimeProbeReport
from kpcli.core.guest import add_guest_timeout_arguments, timeouts_from_args
from kpcli.core.ksym import extract_guest_ksyms
from kpcli.core.runtime_cache import (
    DEFAULT_RUNTIME_REPORT,
    load_runtime_report,
    save_runtime_report,
)
from kpcli.core.session import managed_session, local_target, remote_target
from kpcli.core.symbols import (
    DEFAULT_SYMBOLS,
    KASLR_ANCHORS,
    extract_symbols,
    render_symbols,
)


def register(subparsers):
    parser = subparsers.add_parser(
        "symbols",
        help="render the latest runtime symbols; use --refresh to query a guest",
    )
    parser.add_argument("--file", help="use static vmlinux extraction instead of runtime mode")
    parser.add_argument("-s", "--symbol", action="append", dest="symbols", help="symbol to extract; repeatable")
    parser.add_argument("--run", default="run.sh", help="QEMU startup script, default: run.sh")
    parser.add_argument(
        "--refresh",
        action="store_true",
        help="start QEMU and replace the cached runtime report",
    )
    parser.add_argument(
        "--analysis",
        action="store_true",
        help="collect symbols using the generated privileged analysis rootfs",
    )
    parser.add_argument("--remote", nargs=2, metavar=("IP", "PORT"), help="probe an existing remote shell")
    add_guest_timeout_arguments(parser)
    parser.add_argument(
        "--format",
        choices=("macro", "assignment", "pointer"),
        default="macro",
        help="C output format, default: %(default)s",
    )
    parser.add_argument(
        "-p",
        "--function-pointers",
        action="store_const",
        const="pointer",
        dest="format",
        help="render callable symbols as C function pointers",
    )
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
        if run_result["run.sh"].status == "Missing":
            raise KpcliError("%s not found" % args.run)
        factory, factory_args = local_target, (args.run,)
        source = "guest:/proc/kallsyms"

    with managed_session(factory, *factory_args) as io:
        runtime = extract_guest_ksyms(
            io,
            requested,
            timeouts=timeouts_from_args(args),
        )

    if args.remote:
        kaslr = {
            "status": "Unknown",
            "detail": "remote runtime addresses are valid for the current remote boot",
            "absolute_addresses_reusable": False,
        }
    else:
        cached = save_runtime_report(
            RuntimeProbeReport(findings={}, symbols=runtime),
            args.run,
            analysis=args.analysis,
        )
        kaslr = cached["kaslr"]
    return render_symbols(
        source,
        runtime,
        names,
        as_json=args.json,
        kaslr=kaslr,
        output_format=args.format,
    )


def _cached_symbols(args, names):
    cached = load_runtime_report()
    return render_symbols(
        "cache:%s" % DEFAULT_RUNTIME_REPORT,
        cached.get("symbols") or {},
        names,
        as_json=args.json,
        kaslr=cached.get("kaslr") or {},
        output_format=args.format,
    )


def handle(args):
    names = tuple(args.symbols) if args.symbols else DEFAULT_SYMBOLS
    if args.analysis:
        if args.remote or args.file:
            raise KpcliError("--analysis cannot be combined with --remote or --file")
        if not args.refresh:
            raise KpcliError("--analysis selects the refresh source; add --refresh")
        args.run = str(resolve_analysis_run())
    if args.file:
        if args.refresh:
            raise KpcliError("--refresh cannot be combined with --file")
        symbol_file, symbols = extract_symbols(args.file, names)
        kaslr = {"status": "Static only", "detail": "addresses are link-time values; runtime slide is not available"}
        print(render_symbols(
            symbol_file,
            symbols,
            names,
            as_json=args.json,
            kaslr=kaslr,
            output_format=args.format,
        ))
        return 0
    if not args.refresh and not args.remote:
        print(_cached_symbols(args, names))
        return 0

    output = _runtime_symbols(args, names)
    if args.analysis and not args.json:
        output += "\n[*] Analysis address scope: %s" % analysis_address_scope(args.run)
    print(output)
    return 0
