from kphelper.core.analysis import (
    DEFAULT_ANALYSIS_CPIO,
    DEFAULT_ANALYSIS_ROOT,
    DEFAULT_ANALYSIS_RUN,
    analysis_address_scope,
    create_analysis_environment,
)
from kphelper.core.pwn import log


def register(subparsers):
    parser = subparsers.add_parser("rootfs", help="create and manage analysis rootfs images")
    actions = parser.add_subparsers(dest="rootfs_action")
    make = actions.add_parser(
        "make-analysis",
        help="create a root analysis image without modifying original files",
    )
    make.add_argument("cpio", nargs="?", help="source initramfs, default: discover from run.sh")
    make.add_argument("--run", default="run.sh", help="source QEMU startup script")
    make.add_argument("--root", default=DEFAULT_ANALYSIS_ROOT, help="temporary analysis root directory")
    make.add_argument("-o", "--output", default=DEFAULT_ANALYSIS_CPIO, help="analysis initramfs output")
    make.add_argument("--analysis-run", default=DEFAULT_ANALYSIS_RUN, help="generated analysis startup script")
    make.add_argument(
        "--sudo",
        action="store_true",
        help="preserve root ownership, permissions, and device nodes using sudo",
    )
    make.set_defaults(handler=handle_make_analysis)
    return parser


def handle_make_analysis(args):
    environment = create_analysis_environment(
        cpio_path=args.cpio,
        run_path=args.run,
        root_dir=args.root,
        output=args.output,
        analysis_run=args.analysis_run,
        privileged=args.sudo,
    )
    log.success("analysis rootfs: %s", environment.cpio_path)
    log.success("analysis run script: %s", environment.run_path)
    for modification in environment.modifications:
        log.info("analysis modification: %s", modification)
    log.warning("analysis environment differs from the original privilege configuration")
    log.info("address scope: %s", analysis_address_scope(environment.run_path))
    return 0
