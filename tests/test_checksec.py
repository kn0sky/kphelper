import tempfile
import unittest
from pathlib import Path

from kphelper.core.checksec import detect_runsec, extract_cmdline, extract_initrd
from kphelper.core.discovery import find_cpio, find_vmlinux


class ChecksecParsingTests(unittest.TestCase):
    def test_extracts_quoted_append_cmdline(self):
        run_sh = 'qemu-system-x86_64 -append "console=ttyS0 nokaslr nopti" -s\n'

        self.assertEqual(extract_cmdline(run_sh), "console=ttyS0 nokaslr nopti")

    def test_extracts_single_quoted_append_cmdline(self):
        run_sh = "qemu-system-x86_64 -append 'console=ttyS0 kaslr kpti=1' -S\n"

        self.assertEqual(extract_cmdline(run_sh), "console=ttyS0 kaslr kpti=1")

    def test_extracts_initrd_path(self):
        run_sh = 'qemu-system-x86_64 -initrd ./dist/rootfs.cpio.gz -append "console=ttyS0"\n'

        self.assertEqual(extract_initrd(run_sh), "./dist/rootfs.cpio.gz")

    def test_detect_runsec_common_disabled_settings(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_path = Path(tmp) / "run.sh"
            run_path.write_text(
                "qemu-system-x86_64 "
                "-cpu kvm64,+smep,-smap "
                "-initrd rootfs.cpio "
                '-append "console=ttyS0 nokaslr nopti" '
                "-s\n"
            )

            result = detect_runsec(run_path)

        self.assertEqual(result["KASLR"], "Disabled")
        self.assertEqual(result["KPTI"], "Disabled")
        self.assertEqual(result["SMEP"], "Enabled")
        self.assertEqual(result["SMAP"], "Disabled")
        self.assertEqual(result["KGDB"], "Enabled")
        self.assertEqual(result["Initrd"], "rootfs.cpio")

    def test_detect_runsec_common_enabled_settings(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_path = Path(tmp) / "run.sh"
            run_path.write_text(
                "qemu-system-x86_64 "
                "-cpu qemu64,+smep,+smap "
                '-append "console=ttyS0 kaslr kpti=1" '
                "-gdb tcp::1234\n"
            )

            result = detect_runsec(run_path)

        self.assertEqual(result["KASLR"], "Enabled")
        self.assertEqual(result["KPTI"], "Enabled")
        self.assertEqual(result["SMEP"], "Enabled")
        self.assertEqual(result["SMAP"], "Enabled")
        self.assertEqual(result["KGDB"], "Enabled")


class DiscoveryTests(unittest.TestCase):
    def test_find_vmlinux_prefers_shallow_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "nested").mkdir()
            (base / "nested" / "vmlinux").write_text("")
            (base / "vmlinux").write_text("")

            self.assertEqual(find_vmlinux(base), base / "vmlinux")

    def test_find_cpio_skips_unpacked_root_directory_but_finds_dist(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "root").mkdir()
            (base / "root" / "old_rootfs.cpio").write_text("")
            (base / "dist").mkdir()
            (base / "dist" / "rootfs.cpio.gz").write_text("")

            self.assertEqual(find_cpio(base), base / "dist" / "rootfs.cpio.gz")


if __name__ == "__main__":
    unittest.main()
