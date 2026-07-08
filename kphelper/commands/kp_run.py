from kphelper import core


def register(subparsers):
    parser = subparsers.add_parser("run", help="start ./run.sh and upload exp if present")
    parser.set_defaults(handler=handle)
    return parser


def handle(args):
    core.build_only()
    io = None
    try:
        io = core.local_target()
        core.upload_and_cd(io)
        core.interact(io)
    finally:
        core.close_session(io)
    return 0
