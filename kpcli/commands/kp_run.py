from kpcli.core.session import interact, local_target, managed_session
from kpcli.core.workflow import build_only, upload_and_cd


def register(subparsers):
    parser = subparsers.add_parser("run", help="start ./run.sh and upload exp if present")
    parser.set_defaults(handler=handle)
    return parser


def handle(args):
    build_only()
    with managed_session(local_target) as io:
        upload_and_cd(io)
        interact(io)
    return 0
