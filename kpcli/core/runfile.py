import re
import shutil
import stat
from pathlib import Path

from .errors import KpcliError


def update_run_initrd(run_path, output, backup=True):
    run_path = Path(run_path)
    if not run_path.exists():
        raise KpcliError("%s not found; cannot update initrd path" % run_path)

    text = run_path.read_text(errors="replace")
    output = str(output)
    pattern = r"(-(?:initrd|initramfs)\s+)(['\"]?)([^\s'\"\\]+)(\2)"
    if not re.search(pattern, text):
        raise KpcliError("cannot find a direct -initrd path in %s" % run_path)

    if backup:
        backup_path = run_path.with_suffix(run_path.suffix + ".bak")
        shutil.copy2(run_path, backup_path)

    def replace(match):
        quote = match.group(2)
        return "%s%s%s%s" % (match.group(1), quote, output, quote)

    run_path.write_text(re.sub(pattern, replace, text, count=1))


def ensure_append_token(text, token):
    pattern = r"(-append\s+)(['\"])(.*?)(\2)"

    def replace(match):
        cmdline = match.group(3)
        tokens = cmdline.split()
        if token not in tokens:
            cmdline = (cmdline + " " + token).strip()
        return "%s%s%s%s" % (match.group(1), match.group(2), cmdline, match.group(4))

    new_text, count = re.subn(pattern, replace, text, count=1, flags=re.DOTALL)
    if count:
        return new_text
    raise KpcliError("cannot find direct quoted -append in run.sh")


def ensure_qemu_flag(text, flag):
    if re.search(r"(^|\s)%s(\s|$)" % re.escape(flag), text):
        return text
    match = re.search(r"(qemu-system-[^\s\\]+)", text)
    if not match:
        raise KpcliError("cannot find qemu-system command in run.sh")
    insert_at = match.end()
    return text[:insert_at] + " " + flag + text[insert_at:]


def create_debug_run_copy(run_path="run.sh", output=".kpcli-run-debug.sh", nokaslr=False):
    run_path = Path(run_path)
    output = Path(output)
    if not run_path.exists():
        raise KpcliError("%s not found" % run_path)

    text = run_path.read_text(errors="replace")
    if nokaslr:
        text = ensure_append_token(text, "nokaslr")
    text = ensure_qemu_flag(text, "-s")
    text = ensure_qemu_flag(text, "-S")
    output.write_text(text)

    mode = run_path.stat().st_mode
    output.chmod(mode | stat.S_IXUSR)
    return output
