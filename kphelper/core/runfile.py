import re
import shutil
from pathlib import Path

from .errors import KphelperError


def update_run_initrd(run_path, output, backup=True):
    run_path = Path(run_path)
    if not run_path.exists():
        raise KphelperError("%s not found; cannot update initrd path" % run_path)

    text = run_path.read_text(errors="replace")
    output = str(output)
    pattern = r"(-(?:initrd|initramfs)\s+)(['\"]?)([^\s'\"\\]+)(\2)"
    if not re.search(pattern, text):
        raise KphelperError("cannot find a direct -initrd path in %s" % run_path)

    if backup:
        backup_path = run_path.with_suffix(run_path.suffix + ".bak")
        shutil.copy2(run_path, backup_path)

    def replace(match):
        quote = match.group(2)
        return "%s%s%s%s" % (match.group(1), quote, output, quote)

    run_path.write_text(re.sub(pattern, replace, text, count=1))
