import importlib
import sys

from .errors import KpcliError


_pwn = None
_pwn_load_attempted = False


def _load_pwntools(required=True):
    global _pwn, _pwn_load_attempted
    if not _pwn_load_attempted:
        _pwn_load_attempted = True
        try:
            _pwn = importlib.import_module("pwn")
        except ImportError:
            _pwn = None
        if _pwn is not None:
            _pwn.context.terminal = ["tmux", "splitw", "-h"]
    if required and _pwn is None:
        raise KpcliError(
            "pwntools is required for guest sessions; install with: pip install 'pwntools>=4.12,<5'"
        )
    return _pwn


class _LogProxy:
    _prefixes = {
        "debug": "[.]",
        "info": "[*]",
        "success": "[+]",
        "warning": "[!]",
        "failure": "[-]",
    }

    def _write(self, level, message, *args):
        pwn = _load_pwntools(required=False)
        if pwn is not None:
            getattr(pwn.log, level)(message, *args)
            return
        if args:
            message = message % args
        print("%s %s" % (self._prefixes[level], message), file=sys.stderr)

    def debug(self, message, *args):
        self._write("debug", message, *args)

    def info(self, message, *args):
        self._write("info", message, *args)

    def success(self, message, *args):
        self._write("success", message, *args)

    def warning(self, message, *args):
        self._write("warning", message, *args)

    def failure(self, message, *args):
        self._write("failure", message, *args)


log = _LogProxy()


def process(*args, **kwargs):
    return _load_pwntools().process(*args, **kwargs)


def remote(*args, **kwargs):
    return _load_pwntools().remote(*args, **kwargs)
