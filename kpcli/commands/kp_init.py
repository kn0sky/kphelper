from kpcli.core.templates import write_exp_template


def register(subparsers):
    parser = subparsers.add_parser("init", help="create an exp.c kernel pwn skeleton")
    parser.add_argument(
        "-o",
        "--output",
        default="exp.c",
        help="output C file, default: exp.c",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="overwrite existing output file",
    )
    parser.set_defaults(handler=handle)
    return parser


def handle(args):
    write_exp_template(args.output, force=args.force)
    return 0
