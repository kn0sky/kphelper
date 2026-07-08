from kphelper import core


def register(subparsers):
    parser = subparsers.add_parser("remote", help="connect remote target")
    parser.add_argument("ip")
    parser.add_argument("port", type=int)
    parser.set_defaults(handler=handle)
    return parser


def handle(args):
    core.build_only()
    io = None
    try:
        io = core.remote_target(args.ip, args.port)
        core.upload_and_cd(io)
        core.interact(io)
    finally:
        core.close_session(io)
    return 0
