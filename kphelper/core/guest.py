import uuid
from dataclasses import dataclass

from .constants import PROMPTS
from .errors import KphelperError


DEFAULT_BOOT_TIMEOUT = 30
DEFAULT_COMMAND_TIMEOUT = 8


@dataclass(frozen=True)
class GuestTimeouts:
    boot: int = DEFAULT_BOOT_TIMEOUT
    command: int = DEFAULT_COMMAND_TIMEOUT


def add_guest_timeout_arguments(parser):
    parser.add_argument(
        "--boot-timeout",
        type=int,
        default=DEFAULT_BOOT_TIMEOUT,
        help="seconds to wait for the guest shell prompt, default: %(default)s",
    )
    parser.add_argument(
        "--command-timeout",
        type=int,
        default=DEFAULT_COMMAND_TIMEOUT,
        help="seconds to wait for each guest command, default: %(default)s",
    )


def timeouts_from_args(args):
    return GuestTimeouts(
        boot=args.boot_timeout,
        command=args.command_timeout,
    )


class GuestShell:
    def __init__(self, io, timeouts=None):
        self.io = io
        self.timeouts = timeouts or GuestTimeouts()
        self.ready = False

    def _receive_prompt(self, timeout):
        data = self.io.recvuntil(PROMPTS, timeout=timeout) or b""
        if not data.endswith(PROMPTS):
            raise KphelperError(
                "guest shell prompt not reached within %d seconds; ensure QEMU uses serial stdio and does not boot with -S"
                % timeout
            )
        return data

    def wait_ready(self):
        if self.ready:
            return
        self._receive_prompt(self.timeouts.boot)
        marker = "__KPHELPER_READY_%s__" % uuid.uuid4().hex
        self.io.sendline(("echo " + marker).encode())
        data = self.io.recvuntil(marker.encode(), timeout=self.timeouts.command) or b""
        if marker.encode() not in data:
            raise KphelperError("guest shell did not execute readiness probe")
        self._receive_prompt(self.timeouts.command)
        self.ready = True

    def run(self, command):
        self.wait_ready()
        marker = "__KPHELPER_%s__" % uuid.uuid4().hex
        self.io.sendline(("%s; printf '\\n%s:%%s\\n' $?" % (command, marker)).encode())
        data = self.io.recvuntil((marker + ":").encode(), timeout=self.timeouts.command) or b""
        if (marker + ":").encode() not in data:
            raise KphelperError("guest command timed out after %d seconds: %s" % (self.timeouts.command, command))
        status_line = self.io.recvline(timeout=self.timeouts.command) or b""
        self._receive_prompt(self.timeouts.command)
        output = data.rsplit((marker + ":").encode(), 1)[0]
        try:
            status = int(status_line.strip().split()[0])
        except (IndexError, ValueError):
            status = None
        return output.decode(errors="replace"), status
