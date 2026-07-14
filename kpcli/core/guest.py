import uuid
from dataclasses import dataclass

from .constants import PROMPTS
from .errors import KpcliError


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
    return GuestTimeouts(boot=args.boot_timeout, command=args.command_timeout)


class GuestShell:
    def __init__(self, io, timeouts=None):
        self.io = io
        self.timeouts = timeouts or GuestTimeouts()
        self.ready = False

    def _receive_prompt(self, timeout):
        data = self.io.recvuntil(PROMPTS, timeout=timeout) or b""
        if not data.endswith(PROMPTS):
            raise KpcliError(
                "guest shell prompt not reached within %d seconds; ensure QEMU uses serial stdio and does not boot with -S"
                % timeout
            )
        return data

    @staticmethod
    def _marker_printf(marker, format_string="%s%s\\n", extra_arguments=""):
        midpoint = len(marker) // 2
        first, second = marker[:midpoint], marker[midpoint:]
        command = "printf '%s' '%s' '%s'" % (format_string, first, second)
        return command + extra_arguments

    def wait_ready(self):
        if self.ready:
            return
        self._receive_prompt(self.timeouts.boot)
        marker = "__KPCLI_READY_%s__" % uuid.uuid4().hex
        self.io.sendline(self._marker_printf(marker).encode())
        data = self.io.recvuntil(marker.encode(), timeout=self.timeouts.command) or b""
        if marker.encode() not in data:
            raise KpcliError("guest shell did not execute readiness probe")
        self._receive_prompt(self.timeouts.command)
        self.ready = True

    def run(self, command):
        self.wait_ready()
        token = uuid.uuid4().hex
        start_marker = "__KPCLI_START_%s__" % token
        end_marker = "__KPCLI_END_%s__" % token
        end_prefix = (end_marker + ":").encode()
        payload = "%s; { %s; }; __kpcli_status=$?; %s" % (
            self._marker_printf(start_marker),
            command,
            self._marker_printf(
                end_marker,
                format_string="%s%s:%s\\n",
                extra_arguments=' "$__kpcli_status"',
            ),
        )
        self.io.sendline(payload.encode())

        start_data = self.io.recvuntil(start_marker.encode(), timeout=self.timeouts.command) or b""
        if start_marker.encode() not in start_data:
            raise KpcliError(
                "guest command timed out after %d seconds: %s"
                % (self.timeouts.command, command)
            )
        data = self.io.recvuntil(end_prefix, timeout=self.timeouts.command) or b""
        if end_prefix not in data:
            raise KpcliError(
                "guest command timed out after %d seconds: %s"
                % (self.timeouts.command, command)
            )
        status_data = self.io.recvuntil(PROMPTS, timeout=self.timeouts.command) or b""
        if not status_data.endswith(PROMPTS):
            raise KpcliError("guest command completed without returning a shell prompt")
        status_text = status_data[:-2].decode(errors="replace").strip()
        try:
            status = int(status_text.splitlines()[0])
        except (IndexError, ValueError):
            status = None
        output = data.rsplit(end_prefix, 1)[0]
        return output.decode(errors="replace").strip(), status
