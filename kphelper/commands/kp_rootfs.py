from kphelper.core.analysis import (
    DEFAULT_ANALYSIS_CPIO,
    DEFAULT_ANALYSIS_ROOT,
    DEFAULT_ANALYSIS_RUN,
    analysis_address_scope,
    create_analysis_environment,
)
from kphelper.core.pack import (
    DEFAULT_ROOTFS_OUTPUT,
    DEFAULT_ROOTFS_ROOT,
    extract_rootfs,
    repack_rootfs,
)
from kphelper.core.pwn import log


def register(subparsers):
    parser = subparsers.add_parser("rootfs", help="extract, repack, and create analysis rootfs images")
    actions = parser.add_subparsers(dest="rootfs_action", required=True)
    extract = actions.add_parser(
        "extract",
        help="extract an initramfs without modifying its contents",
    )
    extract.add_argument("cpio", nargs="?", help="source initramfs, default: discover from run.sh")
    extract.add_argument("--run", default="run.sh", help="QEMU startup script used for discovery")
    extract.add_argument("--root", default=DEFAULT_ROOTFS_ROOT, help="extraction directory")
    extract.set_defaults(handler=handle_extract)

    repack = actions.add_parser(
        "repack",
        help="repack an extracted rootfs without modifying its contents",
    )
    repack.add_argument("root", nargs="?", default=DEFAULT_ROOTFS_ROOT, help="extracted rootfs directory")
    repack.add_argument("-o", "--output", default=DEFAULT_ROOTFS_OUTPUT, help="output initramfs path")
    repack.set_defaults(handler=handle_repack)

    make = actions.add_parser(
        "make-analysis",
        help="create a root analysis image without modifying original files",
    )
    make.add_argument("cpio", nargs="?", help="source initramfs, default: discover from run.sh")
    make.add_argument("--run", default="run.sh", help="source QEMU startup script")
    make.add_argument("--root", default=DEFAULT_ANALYSIS_ROOT, help="temporary analysis root directory")
    make.add_argument("-o", "--output", default=DEFAULT_ANALYSIS_CPIO, help="analysis initramfs output")
    make.add_argument("--analysis-run", default=DEFAULT_ANALYSIS_RUN, help="generated analysis startup script")
    make.set_defaults(handler=handle_make_analysis)
    return parser


def handle_extract(args):
    extract_rootfs(cpio_path=args.cpio, run_path=args.run, root_dir=args.root)
    return 0


def handle_repack(args):
    repack_rootfs(root_dir=args.root, output=args.output)
    return 0


def handle_make_analysis(args):
    environment = create_analysis_environment(
        cpio_path=args.cpio,
        run_path=args.run,
        root_dir=args.root,
        output=args.output,
        analysis_run=args.analysis_run,
    )
    log.success("analysis rootfs: %s", environment.cpio_path)
    log.success("analysis run script: %s", environment.run_path)
    for modification in environment.modifications:
        log.info("analysis modification: %s", modification)
    log.warning("analysis environment differs from the original privilege configuration")
    log.info("address scope: %s", analysis_address_scope(environment.run_path))
    return 0
