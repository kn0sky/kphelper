from kpcli.core.analysis import analysis_address_scope, create_analysis_environment
from kpcli.core.checksec import DEFAULT_CHECKSEC_ROOT, collect_checksec, run_checksec
from kpcli.core.checksec_report import render_report
from kpcli.core.errors import KpcliError
from kpcli.core.findings import Finding, RuntimeProbeReport
from kpcli.core.guest import add_guest_timeout_arguments, timeouts_from_args
from kpcli.core.pwn import log
from kpcli.core.probe import probe_guest_runtime
from kpcli.core.probe_report import render_live_report
from kpcli.core.runtime_cache import (
    DEFAULT_RUNTIME_HEADER,
    DEFAULT_RUNTIME_REPORT,
    save_runtime_report,
)
from kpcli.core.symbols import DEFAULT_SYMBOLS, KASLR_ANCHORS


def register(subparsers):
    parser = subparsers.add_parser(
        "checksec",
        help="inspect kernel challenge security settings from run.sh and optional cpio",
    )
    parser.add_argument(
        "-r",
        "--run",
        default="run.sh",
        help="qemu startup script to analyze, default: run.sh",
    )
    parser.add_argument(
        "cpio",
        nargs="?",
        help="optional initramfs cpio archive, default: auto-detect from run.sh or current tree",
    )
    parser.add_argument(
        "--root",
        default=DEFAULT_CHECKSEC_ROOT,
        help="initramfs cache directory, default: %(default)s",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="disable ANSI color output",
    )
    parser.add_argument(
        "-p",
        "--function-pointers",
        action="store_true",
        help="render callable live symbols as C function pointers",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--live",
        action="store_true",
        help="run live runtime probe only",
    )
    mode.add_argument(
        "--all",
        action="store_true",
        help="run static checksec and live probe together",
    )
    add_guest_timeout_arguments(parser)
    parser.set_defaults(handler=handle)
    return parser


def _run_live(args, static_rootfs=None):
    return probe_guest_runtime(
        args.run,
        static_rootfs=static_rootfs,
        timeouts=timeouts_from_args(args),
        names=tuple(dict.fromkeys(DEFAULT_SYMBOLS + KASLR_ANCHORS)),
    )


def _render_and_cache_live(args, live_result, color):
    cached = save_runtime_report(live_result, args.run, analysis=args.analysis)
    report = render_live_report(
        live_result,
        color=color,
        kaslr=cached["kaslr"],
        function_pointers=getattr(args, "function_pointers", False),
    )
    report += "\n[*] Runtime report: %s" % DEFAULT_RUNTIME_REPORT
    report += "\n[*] C assignments: %s" % DEFAULT_RUNTIME_HEADER
    return report


def handle(args):
    color = not args.no_color
    if args.live or args.all:
        environment = create_analysis_environment(
            cpio_path=args.cpio,
            run_path=args.run,
        )
        args.analysis = True
        args.run = str(environment.run_path)
        args.cpio = str(environment.cpio_path)
        log.success("analysis rootfs: %s", environment.cpio_path)
        log.success("analysis run script: %s", environment.run_path)
    if args.live:
        live_result = _run_live(args)
        report = _render_and_cache_live(args, live_result, color)
        report += "\n[*] Analysis address scope: %s" % analysis_address_scope(args.run)
        print(report)
        return 0

    if args.all:
        run_result, init_result = collect_checksec(args.run, args.cpio, args.root)
        static_report = render_report(run_result, init_result, color=color)
        try:
            live_result = _run_live(args, static_rootfs=init_result)
            live_report = _render_and_cache_live(args, live_result, color)
        except KpcliError as error:
            fallback = RuntimeProbeReport(
                findings={
                    name: Finding(
                        "Skipped",
                        detail=str(error) if name == "User ID" else "live probe unavailable",
                    )
                    for name in [
                        "User ID",
                        "kptr_restrict",
                        "dmesg_restrict",
                        "kallsyms",
                        "Module base leak",
                    ]
                },
                symbols={},
            )
            live_report = render_live_report(
                fallback,
                color=color,
                function_pointers=getattr(args, "function_pointers", False),
            )
        combined = static_report + "\n\n" + live_report
        combined += "\n[*] Analysis address scope: %s" % analysis_address_scope(args.run)
        print(combined)
        return 0

    print(run_checksec(args.run, args.cpio, args.root, color=color))
    return 0
