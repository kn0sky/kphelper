from kpcli.core.session import interact, managed_session, remote_target
from kpcli.core.workflow import build_only, upload_and_cd


def register(subparsers):
    parser = subparsers.add_parser("remote", help="connect remote target")
    parser.add_argument("ip")
    parser.add_argument("port", type=int)
    parser.set_defaults(handler=handle)
    return parser


def handle(args):
    build_only()
    with managed_session(remote_target, args.ip, args.port) as io:
        upload_and_cd(io)
        interact(io)
    return 0
