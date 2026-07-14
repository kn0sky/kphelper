import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from kpcli.core.analysis import (
    _patch_init_for_root,
    prepare_analysis_root,
)
from kpcli.core.checksec import (
    DEFAULT_CHECKSEC_ROOT,
    detect_runsec,
    detect_sysctl_write,
    extract_cmdline,
    extract_initrd,
    resolve_initrd_path,
    scan_init,
    startup_script_paths,
)
from kpcli.core.checksec_report import render_report
from kpcli.core.guest import GuestShell
from kpcli.core.cpio import preserved_metadata_state, run_cpio_command
from kpcli.core.errors import KpcliError
from kpcli.core.probe_report import render_live_report
from kpcli.core.qemu import parse_qemu_run_text
from kpcli.core.discovery import find_cpio, find_vmlinux
from kpcli.core.ksym import kallsyms_query_command, parse_kallsyms, parse_kptr_value
from kpcli.core.pack import (
    ensure_clean_pack_root,
    extract_rootfs,
    fakeroot_state_path,
    repack_cpio,
)
from kpcli.core.runfile import create_debug_run_copy, update_run_initrd
from kpcli.core.symbols import render_symbols


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

    def test_resolves_relative_initrd_from_run_script_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            challenge = Path(tmp) / "challenge"
            initrd = challenge / "vm/rootfs.cpio"
            initrd.parent.mkdir(parents=True)
            initrd.write_bytes(b"archive")

            resolved = resolve_initrd_path("vm/rootfs.cpio", challenge / "run.sh")

        self.assertEqual(resolved, initrd)

    def test_checksec_cache_does_not_use_challenge_root_directory(self):
        self.assertEqual(DEFAULT_CHECKSEC_ROOT, ".kpcli/checksec-root")

    def test_qemu_parser_does_not_treat_following_options_as_cmdline(self):
        config = parse_qemu_run_text(
            "qemu-system-x86_64 -kernel bzImage -append console=ttyS0 -initrd rootfs.cpio -s\n"
        )

        self.assertEqual(config.cmdline, "console=ttyS0")
        self.assertEqual(config.initrd, "rootfs.cpio")
        self.assertEqual(config.kernel, "bzImage")
        self.assertTrue(config.gdb_enabled)

    def test_qemu_parser_ignores_flags_outside_qemu_command(self):
        config = parse_qemu_run_text(
            "gcc -s -o exp exp.c\nqemu-system-x86_64 -append 'console=ttyS0'\n"
        )

        self.assertFalse(config.gdb_enabled)

    def test_qemu_config_resolves_files_relative_to_run_script(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_path = Path(tmp) / "challenge/run.sh"
            kernel = run_path.parent / "images/bzImage"
            kernel.parent.mkdir(parents=True)
            kernel.write_bytes(b"kernel")
            config = parse_qemu_run_text(
                'qemu-system-x86_64 -kernel images/bzImage -initrd "$INITRD"\n',
                run_path,
            )

            self.assertEqual(config.resolve_file(config.kernel), kernel)
            self.assertIsNone(config.initrd)

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

        self.assertEqual(result["KASLR"].status, "Disabled")
        self.assertEqual(result["KPTI"].status, "Disabled")
        self.assertEqual(result["SMEP"].status, "Enabled")
        self.assertEqual(result["SMAP"].status, "Disabled")
        self.assertEqual(result["KGDB"].status, "Enabled")
        self.assertEqual(result["Initrd"].status, "rootfs.cpio")
        self.assertEqual(result["KASLR"].source, "qemu")

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

        self.assertEqual(result["KASLR"].status, "Enabled")
        self.assertEqual(result["KPTI"].status, "Enabled")
        self.assertEqual(result["SMEP"].status, "Enabled")
        self.assertEqual(result["SMAP"].status, "Enabled")
        self.assertEqual(result["KGDB"].status, "Enabled")

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

    def test_render_live_symbols_aligns_short_and_long_names(self):
        output = render_live_report(
            {
                "symbols": {
                    "commit_creds": 0xffffffff81072540,
                    "swapgs_restore_regs_and_return_to_usermode": 0xffffffff81800e10,
                },
            },
            color=False,
        )
        symbol_lines = [line for line in output.splitlines() if "Readable:" in line]

        self.assertEqual(len(symbol_lines), 2)
        self.assertEqual(symbol_lines[0].index(":"), symbol_lines[1].index(":"))

    def test_render_live_symbols_supports_function_pointers(self):
        output = render_live_report(
            {
                "symbols": {
                    "commit_creds": 0xffffffff81072540,
                    "init_cred": 0xffffffff82a6b780,
                },
            },
            color=False,
            function_pointers=True,
        )

        self.assertIn("unsigned long (*commit_creds", output)
        self.assertIn("(unsigned long (*)())0xffffffff81072540", output)
        self.assertIn("unsigned long init_cred", output)
        self.assertNotIn("(*init_cred", output)

    @patch("kpcli.core.guest.uuid.uuid4")
    def test_guest_command_markers_do_not_match_serial_echo(self, uuid4):
        uuid4.return_value.hex = "a" * 32
        start = b"__KPCLI_START_" + b"a" * 32 + b"__"
        end = b"__KPCLI_END_" + b"a" * 32 + b"__"

        class FakeIo:
            def __init__(self):
                self.sent = b""
                self.responses = [b"echoed command\r\n" + start, b"\r\n0\r\n" + end + b":", b"0\r\n/ # "]

            def sendline(self, data):
                self.sent = data

            def recvuntil(self, _delimiter, timeout=None):
                return self.responses.pop(0)

        io = FakeIo()
        shell = GuestShell(io)
        shell.ready = True

        output, status = shell.run("id -u")

        self.assertEqual(output, "0")
        self.assertEqual(status, 0)
        self.assertNotIn(start, io.sent)
        self.assertNotIn(end, io.sent)


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

        self.assertEqual(result["Root shell"].status, "Likely root")
        self.assertEqual(result["kptr_restrict"].status, "0")
        self.assertEqual(result["Root shell"].source, "rootfs")


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
            self.assertFalse((init_d / "S99ctf.kpcli-original").exists())
            self.assertTrue(any("S99ctf" in change for change in changes))

class PackTests(unittest.TestCase):
    def test_clean_pack_root_removes_readonly_directories(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "root"
            readonly = root / "usr/bin"
            readonly.mkdir(parents=True)
            (readonly / "tool").write_text("binary")
            readonly.chmod(0o555)

            cleaned = ensure_clean_pack_root(root)

            self.assertEqual(cleaned, root)
            self.assertEqual(list(root.iterdir()), [])

    @patch("kpcli.core.pack.unpack_cpio")
    @patch("kpcli.core.pack.preserved_metadata_state")
    def test_rootfs_extract_keeps_metadata_state_outside_workspace(self, metadata_state, unpack):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "rootfs"
            state = fakeroot_state_path(root)
            metadata_state.return_value.__enter__.return_value = state

            def create_marker(_source, extracted_root, **_kwargs):
                (Path(extracted_root) / ".kpcli-cpio-source").write_text("marker")

            unpack.side_effect = create_marker
            result = extract_rootfs("rootfs.cpio", root_dir=root)

            self.assertEqual(result, root)
            metadata_state.assert_called_once_with(state)
            self.assertFalse((root / ".kpcli-cpio-source").exists())

    @patch("kpcli.core.cpio.subprocess.run")
    def test_cpio_command_saves_fakeroot_state_during_extraction(self, run):
        state = Path("/tmp/fakeroot-state")

        run_cpio_command("cpio command", "/tmp/root", fakeroot_state=state)

        arguments = run.call_args.args[0]
        self.assertEqual(arguments[:4], ["fakeroot", "-s", str(state), "--"])
        self.assertEqual(arguments[4:9], ["bash", "-o", "pipefail", "-c", "cpio command"])
        self.assertEqual(
            run.call_args.kwargs["env"]["FAKEROOTDONTTRYCHOWN"],
            "1",
        )

    @patch("kpcli.core.cpio.shutil.which", return_value=None)
    @patch("kpcli.core.cpio.os.geteuid", return_value=1000)
    def test_metadata_preservation_fails_instead_of_creating_broken_archive(self, _geteuid, _which):
        with self.assertRaisesRegex(KpcliError, "fakeroot not found"):
            with preserved_metadata_state():
                pass

    @patch("kpcli.core.cpio.shutil.which", return_value="/usr/bin/fakeroot")
    @patch("kpcli.core.cpio.os.geteuid", return_value=1000)
    def test_metadata_state_can_persist_outside_temporary_directory(self, _geteuid, _which):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "rootfs.fakeroot-state"

            with preserved_metadata_state(state) as result:
                self.assertEqual(result, state.resolve())

    @patch("kpcli.core.pack.run_cpio_command")
    def test_repack_loads_saved_fakeroot_state(self, run_cpio):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "root"
            root.mkdir()
            output = Path(tmp) / "packed.cpio.gz"
            state = Path(tmp) / "fakeroot-state"
            state.write_text("fakeroot state")

            repack_cpio(root, output, fakeroot_state=state)

        self.assertEqual(run_cpio.call_args.kwargs["fakeroot_state"], state)
        self.assertTrue(run_cpio.call_args.kwargs["load_state"])
        self.assertIn("! -path './.kpcli-cpio-source'", run_cpio.call_args.args[0])
        self.assertIn("! -path './.kphelper-cpio-source'", run_cpio.call_args.args[0])

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
            debug_path = base / ".kpcli-run-debug.sh"
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
            debug_path = base / ".kpcli-run-debug.sh"
            run_path.write_text('qemu-system-x86_64 -append "console=ttyS0"\n')

            create_debug_run_copy(run_path, debug_path, nokaslr=True)

            self.assertIn("console=ttyS0 nokaslr", debug_path.read_text())


class SymbolTests(unittest.TestCase):
    def test_kallsyms_query_filters_in_guest_without_streaming_full_file(self):
        command = kallsyms_query_command(("commit_creds", "prepare_kernel_cred"))

        self.assertIn("awk", command)
        self.assertIn("commit_creds", command)
        self.assertIn("prepare_kernel_cred", command)
        self.assertNotIn("cat /proc/kallsyms", command)

    def test_render_symbols_outputs_c_macros_and_missing(self):
        output = render_symbols(
            "vmlinux",
            {"commit_creds": 0xffffffff81080000},
            names=("commit_creds", "prepare_kernel_cred"),
        )

        self.assertIn("#define COMMIT_CREDS", output)
        self.assertIn("0xffffffff81080000", output)
        self.assertIn("#define PREPARE_KERNEL_CRED", output)
        self.assertIn("0x0", output)

    def test_render_symbols_supports_c_assignments(self):
        output = render_symbols(
            "runtime cache",
            {"commit_creds": 0xffffffff81080000},
            names=("commit_creds", "prepare_kernel_cred"),
            output_format="assignment",
        )

        self.assertIn("unsigned long commit_creds", output)
        self.assertIn("unsigned long prepare_kernel_cred", output)
        self.assertIn("= 0x0;", output)

    def test_render_symbols_supports_function_pointers_and_numeric_offsets(self):
        output = render_symbols(
            "runtime cache",
            {
                "commit_creds": 0xffffffff81080000,
                "modprobe_path": 0xffffffff82a5c5c0,
            },
            names=("commit_creds", "modprobe_path"),
            kaslr={
                "offset_anchor": "_stext",
                "offsets": {"commit_creds": 0x80000, "modprobe_path": 0x125c5c0},
            },
            output_format="pointer",
        )

        self.assertIn("unsigned long (*commit_creds", output)
        self.assertIn("unsigned long modprobe_path", output)
        self.assertIn("unsigned long commit_creds_offset", output)
        self.assertNotIn("(*commit_creds_offset", output)

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
