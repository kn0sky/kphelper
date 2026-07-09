from kphelper.core.checksec import run_checksec
from kphelper.core.probe import probe_guest_runtime


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
    parser.add_argument(
        "--live",
        action="store_true",
        help="reserve live runtime probing mode for future dynamic checks",
    )
    parser.set_defaults(handler=handle)
    return parser


def handle(args):
    if args.live:
        print(probe_guest_runtime(args.run, timeout=8))
        return 0
    print(run_checksec(args.run, args.cpio, args.root, color=not args.no_color, live=args.live))
    return 0
