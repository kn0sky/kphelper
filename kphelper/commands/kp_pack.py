from kphelper import core


def register(subparsers):
    parser = subparsers.add_parser(
        "pack",
        help="inject exp into initramfs and update run.sh initrd path",
    )
    parser.add_argument(
        "cpio",
        nargs="?",
        help="optional initramfs cpio, default: auto-detect from run.sh or current tree",
    )
    parser.add_argument(
        "-r",
        "--run",
        default="run.sh",
        help="qemu startup script to update, default: run.sh",
    )
    parser.add_argument(
        "--root",
        default="root-pack",
        help="temporary unpack directory, default: root-pack",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="packed-rootfs.cpio.gz",
        help="output initramfs path, default: packed-rootfs.cpio.gz",
    )
    parser.add_argument(
        "--target",
        default="tmp/exp",
        help="path inside initramfs for exp, default: tmp/exp",
    )
    parser.add_argument(
        "--no-update-run",
        action="store_true",
        help="do not rewrite run.sh -initrd path",
    )
    parser.set_defaults(handler=handle)
    return parser


def handle(args):
    core.pack_exp(
        cpio_path=args.cpio,
        run_path=args.run,
        root_dir=args.root,
        output=args.output,
        target=args.target,
        update_run=not args.no_update_run,
    )
    return 0
