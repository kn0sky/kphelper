import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from kphelper.core.analysis import _patch_init_for_root, _privileged_repack, _sudo_run, prepare_analysis_root
from kphelper.core.checksec import (
    detect_runsec,
    detect_sysctl_write,
    extract_cmdline,
    extract_initrd,
    scan_init,
    startup_script_paths,
)
from kphelper.core.checksec_report import render_report
from kphelper.core.probe_report import render_live_report
from kphelper.core.qemu import parse_qemu_run_text
from kphelper.core.discovery import find_cpio, find_vmlinux
from kphelper.core.ksym import parse_kallsyms, parse_kptr_value
from kphelper.core.runfile import create_debug_run_copy, update_run_initrd
from kphelper.core.symbols import render_symbols


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

    def test_qemu_parser_does_not_treat_following_options_as_cmdline(self):
        config = parse_qemu_run_text(
            "qemu-system-x86_64 -append console=ttyS0 -initrd rootfs.cpio -s\n"
        )

        self.assertEqual(config.cmdline, "console=ttyS0")
        self.assertEqual(config.initrd, "rootfs.cpio")
        self.assertTrue(config.gdb_enabled)

    def test_qemu_parser_ignores_flags_outside_qemu_command(self):
        config = parse_qemu_run_text(
            "gcc -s -o exp exp.c\nqemu-system-x86_64 -append 'console=ttyS0'\n"
        )

        self.assertFalse(config.gdb_enabled)

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

    def test_detect_sysctl_write_extracts_value(self):
        text = 'echo 0 > /proc/sys/kernel/kptr_restrict\n'

        self.assertEqual(detect_sysctl_write(text, "kptr_restrict"), "0")

    def test_render_report_includes_rootfs_section(self):
        output = render_report(
            {"run.sh": "run.sh", "KASLR": "Enabled", "SMEP": "Disabled", "SMAP": "Unknown", "KPTI": "Disabled", "KGDB": "Enabled", "Initrd": "rootfs.cpio", "cmdline": "console=ttyS0"},
            {"Rootfs": "root", "Init": "root/init", "Scripts": "root/init", "Root shell": "Likely root", "Module load": "Found", "kptr_restrict": "0", "dmesg_restrict": "Unknown", "kallsyms": "Referenced", "Module base leak": "Referenced", "Device permissions": "Configured in init"},
            color=False,
        )

        self.assertIn("Rootfs checksec", output)
        self.assertIn("Root shell", output)

    def test_render_live_report_shows_skipped_detail(self):
        output = render_live_report(
            {
                "User ID": {"status": "Skipped", "detail": "guest shell unavailable"},
                "kptr_restrict": {"status": "Skipped", "value": "0", "detail": "known from rootfs startup scripts"},
            },
            color=False,
        )

        self.assertIn("Live runtime probe", output)
        self.assertIn("known from rootfs startup scripts", output)


class ScanTests(unittest.TestCase):
    def test_startup_script_paths_finds_common_entries(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "init").write_text("#!/bin/sh\n")
            (base / "etc").mkdir()
            (base / "etc" / "rcS").write_text("#!/bin/sh\n")

            paths = startup_script_paths(base)

        self.assertEqual([path.name for path in paths], ["init", "rcS"])

    def test_scan_init_detects_root_shell_and_sysctl(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "init").write_text("#!/bin/sh\necho 0 > /proc/sys/kernel/kptr_restrict\nexec sh\n")

            result = scan_init(base)

        self.assertEqual(result["Root shell"], "Likely root")
        self.assertEqual(result["kptr_restrict"], "0")


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


class AnalysisRootfsTests(unittest.TestCase):
    def test_patch_init_only_changes_exact_setuidgid_line(self):
        original = (
            "#!/bin/sh\n"
            "echo 0 > /proc/sys/kernel/kptr_restrict\n"
            "setsid cttyhack setuidgid 1337 sh\n"
        )

        patched, changes = _patch_init_for_root(original)

        self.assertEqual(
            patched,
            "#!/bin/sh\necho 0 > /proc/sys/kernel/kptr_restrict\nsetsid cttyhack setuidgid 0 sh\n",
        )
        self.assertTrue(changes)

    def test_patch_init_ignores_other_users_and_command_forms(self):
        original = "setuidgid 1337 sh\nexec setsid cttyhack setuidgid 1000 sh\n"

        patched, changes = _patch_init_for_root(original)

        self.assertEqual(patched, original)
        self.assertFalse(changes)

    def test_prepare_analysis_root_patches_privilege_drop_in_init_d(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "init").write_text("#!/bin/sh\nexec /sbin/init\n")
            init_d = root / "etc/init.d"
            init_d.mkdir(parents=True)
            shell_script = init_d / "S99ctf"
            shell_script.write_text("#!/bin/sh\nsetsid cttyhack setuidgid 1337 sh\n")

            changes = prepare_analysis_root(root)

            self.assertEqual(
                shell_script.read_text(),
                "#!/bin/sh\nsetsid cttyhack setuidgid 0 sh\n",
            )
            self.assertFalse((init_d / "S99ctf.kphelper-original").exists())
            self.assertTrue(any("S99ctf" in change for change in changes))

    @patch("kphelper.core.analysis.subprocess.run")
    def test_sudo_run_elevates_the_complete_command(self, run):
        _sudo_run(["bash", "-o", "pipefail", "-c", "cpio command"])

        run.assert_called_once_with(
            ["sudo", "bash", "-o", "pipefail", "-c", "cpio command"],
            cwd=None,
            check=True,
        )

    @patch("kphelper.core.analysis._sudo_run")
    def test_privileged_repack_uses_null_delimited_newc_pipeline(self, sudo_run):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "root"
            root.mkdir()
            output = Path(tmp) / "analysis.cpio.gz"

            _privileged_repack(root, output)

        arguments = sudo_run.call_args_list[0].args[0]
        self.assertEqual(arguments[:5], ["bash", "-o", "pipefail", "-c", arguments[4]])
        self.assertIn("find . -print0", arguments[4])
        self.assertIn("--format=newc --null", arguments[4])


class PackTests(unittest.TestCase):
    def test_update_run_initrd_rewrites_direct_path_and_creates_backup(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_path = Path(tmp) / "run.sh"
            run_path.write_text("qemu-system-x86_64 -initrd rootfs.cpio -append 'console=ttyS0'\n")

            update_run_initrd(run_path, "packed-rootfs.cpio.gz")

            self.assertIn("-initrd packed-rootfs.cpio.gz", run_path.read_text())
            self.assertTrue((Path(tmp) / "run.sh.bak").exists())

    def test_create_debug_run_copy_preserves_kaslr_by_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            run_path = base / "run.sh"
            debug_path = base / ".kphelper-run-debug.sh"
            original = 'qemu-system-x86_64 -append "console=ttyS0" -initrd rootfs.cpio\n'
            run_path.write_text(original)

            create_debug_run_copy(run_path, debug_path)

            self.assertEqual(run_path.read_text(), original)
            debug_text = debug_path.read_text()
            self.assertIn("-s", debug_text)
            self.assertIn("-S", debug_text)
            self.assertNotIn("nokaslr", debug_text)

    def test_create_debug_run_copy_adds_nokaslr_when_requested(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            run_path = base / "run.sh"
            debug_path = base / ".kphelper-run-debug.sh"
            run_path.write_text('qemu-system-x86_64 -append "console=ttyS0"\n')

            create_debug_run_copy(run_path, debug_path, nokaslr=True)

            self.assertIn("console=ttyS0 nokaslr", debug_path.read_text())


class SymbolTests(unittest.TestCase):
    def test_render_symbols_outputs_c_macros_and_missing(self):
        output = render_symbols(
            "vmlinux",
            {"commit_creds": 0xffffffff81080000},
            names=("commit_creds", "prepare_kernel_cred"),
        )

        self.assertIn("#define COMMIT_CREDS", output)
        self.assertIn("0xffffffff81080000", output)
        self.assertIn("// missing: prepare_kernel_cred", output)

    def test_parse_guest_kptr_value(self):
        output = "cat /proc/sys/kernel/kptr_restrict\n0\n"

        self.assertEqual(parse_kptr_value(output), 0)

    def test_parse_kallsyms_preserves_hidden_zero_addresses(self):
        output = "\n".join([
            "0000000000000000 T commit_creds",
            "ffffffff81081234 T prepare_kernel_cred",
        ])

        symbols = parse_kallsyms(output, ("commit_creds", "prepare_kernel_cred"))

        self.assertEqual(symbols["commit_creds"], 0)
        self.assertEqual(symbols["prepare_kernel_cred"], 0xffffffff81081234)


if __name__ == "__main__":
    unittest.main()
