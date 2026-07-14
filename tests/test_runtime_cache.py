import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from kpcli.core.errors import KpcliError
from kpcli.core.findings import Finding, RuntimeProbeReport
from kpcli.core.runtime_cache import (
    build_kaslr_metadata,
    load_runtime_report,
    save_runtime_report,
)


class RuntimeCacheTests(unittest.TestCase):
    def _challenge(self, base, cmdline="console=ttyS0 nokaslr"):
        base = Path(base)
        kernel = base / "bzImage"
        initrd = base / "rootfs.cpio"
        run_path = base / "run.sh"
        kernel.write_bytes(b"kernel")
        initrd.write_bytes(b"initrd")
        run_path.write_text(
            "qemu-system-x86_64 -kernel bzImage -initrd rootfs.cpio "
            "-append '%s'\n" % cmdline
        )
        return run_path, kernel

    @patch("kpcli.core.runtime_cache.extract_symbols", side_effect=KpcliError("no vmlinux"))
    def test_report_round_trip_and_assignment_header(self, _extract):
        with tempfile.TemporaryDirectory() as tmp:
            run_path, _kernel = self._challenge(tmp)
            report_path = Path(tmp) / ".kpcli/runtime-report.json"
            header_path = Path(tmp) / ".kpcli/runtime-symbols.h"

            saved = save_runtime_report(
                RuntimeProbeReport(
                    findings={"User ID": Finding("Readable", value="0")},
                    symbols={"commit_creds": 0xffffffff81070000},
                ),
                run_path,
                report_path=report_path,
                header_path=header_path,
            )
            loaded = load_runtime_report(report_path)

            self.assertEqual(loaded["fingerprint"]["digest"], saved["fingerprint"]["digest"])
            self.assertEqual(loaded["runtime"]["User ID"]["value"], "0")
            self.assertEqual(loaded["symbols"]["commit_creds"], 0xffffffff81070000)
            self.assertIn("unsigned long commit_creds", header_path.read_text())

    @patch("kpcli.core.runtime_cache.extract_symbols", side_effect=KpcliError("no vmlinux"))
    def test_changed_kernel_invalidates_cached_report(self, _extract):
        with tempfile.TemporaryDirectory() as tmp:
            run_path, kernel = self._challenge(tmp)
            report_path = Path(tmp) / "runtime-report.json"
            header_path = Path(tmp) / "runtime-symbols.h"
            save_runtime_report(
                RuntimeProbeReport(findings={}, symbols={}),
                run_path,
                report_path=report_path,
                header_path=header_path,
            )
            kernel.write_bytes(b"changed kernel")

            with self.assertRaisesRegex(KpcliError, "stale"):
                load_runtime_report(report_path)

    @patch("kpcli.core.runtime_cache.extract_symbols", side_effect=KpcliError("no vmlinux"))
    def test_kaslr_metadata_keeps_offsets_relative_to_runtime_anchor(self, _extract):
        with tempfile.TemporaryDirectory() as tmp:
            run_path, _kernel = self._challenge(tmp, cmdline="console=ttyS0 kaslr")
            metadata = build_kaslr_metadata(
                run_path,
                {"_stext": 0xffffffff82000000, "commit_creds": 0xffffffff82072540},
            )

        self.assertEqual(metadata["status"], "Enabled")
        self.assertFalse(metadata["absolute_addresses_reusable"])
        self.assertEqual(metadata["offset_anchor"], "_stext")
        self.assertEqual(metadata["offsets"]["commit_creds"], 0x72540)


if __name__ == "__main__":
    unittest.main()
