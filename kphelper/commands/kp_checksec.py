from kphelper.core.analysis import analysis_address_scope, create_analysis_environment
from kphelper.core.checksec import DEFAULT_CHECKSEC_ROOT, collect_checksec, run_checksec
from kphelper.core.checksec_report import render_report
from kphelper.core.errors import KphelperError
from kphelper.core.findings import Finding, RuntimeProbeReport
from kphelper.core.guest import add_guest_timeout_arguments, timeouts_from_args
from kphelper.core.pwn import log
from kphelper.core.probe import probe_guest_runtime
from kphelper.core.probe_report import render_live_report
from kphelper.core.runtime_cache import (
    DEFAULT_RUNTIME_HEADER,
    DEFAULT_RUNTIME_REPORT,
    save_runtime_report,
)
from kphelper.core.symbols import DEFAULT_SYMBOLS, KASLR_ANCHORS


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
    parser.add_argument(
        "--analysis",
        action="store_true",
        help="create and use an analysis rootfs for --live or --all",
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
    report = render_live_report(live_result, color=color, kaslr=cached["kaslr"])
    report += "\n[*] Runtime report: %s" % DEFAULT_RUNTIME_REPORT
    report += "\n[*] C assignments: %s" % DEFAULT_RUNTIME_HEADER
    return report


def handle(args):
    color = not args.no_color
    if args.analysis:
        if not (args.live or args.all):
            raise KphelperError("--analysis requires --live or --all")
        environment = create_analysis_environment(
            cpio_path=args.cpio,
            run_path=args.run,
        )
        args.run = str(environment.run_path)
        args.cpio = str(environment.cpio_path)
        log.success("analysis rootfs: %s", environment.cpio_path)
        log.success("analysis run script: %s", environment.run_path)
    if args.live:
        live_result = _run_live(args)
        report = _render_and_cache_live(args, live_result, color)
        if args.analysis:
            report += "\n[*] Analysis address scope: %s" % analysis_address_scope(args.run)
        print(report)
        return 0

    if args.all:
        run_result, init_result = collect_checksec(args.run, args.cpio, args.root)
        static_report = render_report(run_result, init_result, color=color)
        try:
            live_result = _run_live(args, static_rootfs=init_result)
            live_report = _render_and_cache_live(args, live_result, color)
        except KphelperError as error:
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
            live_report = render_live_report(fallback, color=color)
        combined = static_report + "\n\n" + live_report
        if args.analysis:
            combined += "\n[*] Analysis address scope: %s" % analysis_address_scope(args.run)
        print(combined)
        return 0

    print(run_checksec(args.run, args.cpio, args.root, color=color))
    return 0
