from kphelper.core.checksec import collect_checksec, run_checksec
from kphelper.core.checksec_report import render_report
from kphelper.core.errors import KphelperError
from kphelper.core.findings import Finding
from kphelper.core.guest import add_guest_timeout_arguments, timeouts_from_args
from kphelper.core.probe import probe_guest_runtime
from kphelper.core.probe_report import render_live_report


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
        default="root",
        help="directory used for unpacked cpio, default: root",
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
    add_guest_timeout_arguments(parser)
    parser.set_defaults(handler=handle)
    return parser


def _run_live(args, static_rootfs=None):
    return probe_guest_runtime(
        args.run,
        static_rootfs=static_rootfs,
        timeouts=timeouts_from_args(args),
    )


def handle(args):
    color = not args.no_color
    if args.live:
        live_result = _run_live(args)
        print(render_live_report(live_result, color=color))
        return 0

    if args.all:
        run_result, init_result = collect_checksec(args.run, args.cpio, args.root)
        static_report = render_report(run_result, init_result, color=color)
        try:
            live_result = _run_live(args, static_rootfs=init_result)
            live_report = render_live_report(live_result, color=color)
        except KphelperError as error:
            live_report = render_live_report(
                {
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
                color=color,
            )
        print(static_report + "\n\n" + live_report)
        return 0

    print(run_checksec(args.run, args.cpio, args.root, color=color))
    return 0
