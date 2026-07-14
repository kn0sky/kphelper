import subprocess
from pathlib import Path

from .constants import LOCAL_EXP, LOCAL_EXP_C
from .errors import KpcliError
from .pwn import log


def run_compiler(cmd, source):
    try:
        subprocess.run(cmd, check=True)
        return True
    except FileNotFoundError:
        log.warning("%s not found", cmd[0])
        return False
    except subprocess.CalledProcessError as e:
        log.warning("%s failed to compile %s, exit code: %d", cmd[0], source, e.returncode)
        return False


def build_exp(source=LOCAL_EXP_C, output=LOCAL_EXP):
    source = Path(source)
    output = Path(output)
    if not source.exists():
        return False

    log.info("found %s, compiling static exp with musl-gcc", source)
    musl_cmd = ["musl-gcc", "-static", "-o", str(output), str(source)]
    if run_compiler(musl_cmd, source):
        log.success("compiled %s -> %s", source, output)
        return True

    log.warning("falling back to gcc -static -Os -s")
    gcc_cmd = ["gcc", "-static", "-Os", "-s", "-o", str(output), str(source)]
    if run_compiler(gcc_cmd, source):
        log.success("compiled %s -> %s", source, output)
        return True

    message = "failed to compile exp.c with musl-gcc or gcc"
    log.failure(message)
    raise KpcliError(message)
