import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from kphelper.cli import build_parser
from kphelper.commands.kp_checksec import handle as handle_checksec
from kphelper.commands.kp_debug import handle as handle_debug
from kphelper.commands.kp_symbols import handle as handle_symbols
from kphelper.core.errors import KphelperError
from kphelper.core.session import local_target, remote_target


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class CliTests(unittest.TestCase):
    def test_only_registered_commands_are_exposed(self):
        parser = build_parser()
        subparsers = next(
            action for action in parser._actions if hasattr(action, "choices") and action.choices
        )

        self.assertNotIn("example", subparsers.choices)
        self.assertIn("checksec", subparsers.choices)

    def test_top_level_help_examples_cover_core_workflows(self):
        help_text = build_parser().format_help()

        for example in [
            "kphelper init",
            "kphelper checksec --all",
            "kphelper rootfs extract rootfs.cpio.gz",
            "kphelper rootfs repack .kphelper/rootfs",
            "kphelper pack rootfs.cpio.gz",
            "kphelper symbols --refresh",
            "kphelper debug ./vmlinux --nokaslr",
            "kphelper remote 127.0.0.1 1337",
        ]:
            self.assertIn(example, help_text)

    def test_rootfs_extract_and_repack_actions_are_exposed(self):
        parser = build_parser()

        extract = parser.parse_args(["rootfs", "extract", "rootfs.cpio"])
        repack = parser.parse_args(["rootfs", "repack"])

        self.assertEqual(extract.cpio, "rootfs.cpio")
        self.assertEqual(repack.root, ".kphelper/rootfs")

    def test_checksec_live_modes_do_not_require_analysis_flag(self):
        parser = build_parser()

        live = parser.parse_args(["checksec", "--live"])
        combined = parser.parse_args(["checksec", "--all"])

        self.assertTrue(live.live)
        self.assertTrue(combined.all)
        checksec_help = parser._subparsers._group_actions[0].choices["checksec"].format_help()
        self.assertNotIn("--analysis", checksec_help)

    def test_static_checksec_runs_without_site_packages(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "run.sh").write_text(
                "qemu-system-x86_64 -append 'console=ttyS0 nokaslr nopti'\n"
            )
            env = os.environ.copy()
            env["PYTHONPATH"] = str(PROJECT_ROOT)
            result = subprocess.run(
                [sys.executable, "-S", "-m", "kphelper", "checksec", "--no-color"],
                cwd=tmp,
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Kernel checksec", result.stdout)
        self.assertIn("KASLR", result.stdout)

    @patch("kphelper.commands.kp_checksec.analysis_address_scope", return_value="current boot only")
    @patch("kphelper.commands.kp_checksec._render_and_cache_live", return_value="live report")
    @patch("kphelper.commands.kp_checksec._run_live")
    @patch("kphelper.commands.kp_checksec.create_analysis_environment")
    @patch("builtins.print")
    def test_checksec_live_prepares_and_uses_analysis_environment(
        self,
        print_output,
        create_analysis,
        _run_live,
        _render_live,
        _address_scope,
    ):
        create_analysis.return_value = SimpleNamespace(
            cpio_path=Path(".kphelper/analysis-rootfs.cpio.gz"),
            run_path=Path(".kphelper/run-analysis.sh"),
        )
        args = SimpleNamespace(
            run="run.sh",
            cpio="rootfs.cpio",
            root=".kphelper/checksec-root",
            no_color=True,
            live=True,
            all=False,
            boot_timeout=30,
            command_timeout=8,
        )

        handle_checksec(args)

        create_analysis.assert_called_once_with(
            cpio_path="rootfs.cpio",
            run_path="run.sh",
        )
        self.assertEqual(args.run, ".kphelper/run-analysis.sh")
        self.assertTrue(args.analysis)
        print_output.assert_any_call("live report\n[*] Analysis address scope: current boot only")

    def test_checksec_all_uses_generated_analysis_run_and_cpio(self):
        environment = SimpleNamespace(
            cpio_path=Path(".kphelper/analysis-rootfs.cpio.gz"),
            run_path=Path(".kphelper/run-analysis.sh"),
        )
        args = SimpleNamespace(
            run="run.sh",
            cpio="rootfs.cpio",
            root=".kphelper/checksec-root",
            no_color=True,
            live=False,
            all=True,
            boot_timeout=30,
            command_timeout=8,
        )
        with ExitStack() as stack:
            create_analysis = stack.enter_context(
                patch(
                    "kphelper.commands.kp_checksec.create_analysis_environment",
                    return_value=environment,
                )
            )
            collect = stack.enter_context(
                patch("kphelper.commands.kp_checksec.collect_checksec", return_value=({}, None))
            )
            stack.enter_context(
                patch("kphelper.commands.kp_checksec.render_report", return_value="static report")
            )
            stack.enter_context(
                patch("kphelper.commands.kp_checksec._run_live", side_effect=KphelperError("offline"))
            )
            stack.enter_context(
                patch("kphelper.commands.kp_checksec.render_live_report", return_value="live report")
            )
            stack.enter_context(
                patch("kphelper.commands.kp_checksec.analysis_address_scope", return_value="current boot only")
            )
            stack.enter_context(patch("builtins.print"))

            handle_checksec(args)

        create_analysis.assert_called_once_with(
            cpio_path="rootfs.cpio",
            run_path="run.sh",
        )
        collect.assert_called_once_with(
            ".kphelper/run-analysis.sh",
            ".kphelper/analysis-rootfs.cpio.gz",
            ".kphelper/checksec-root",
        )
        self.assertTrue(args.analysis)

    @patch("kphelper.core.session.process")
    def test_local_target_rejects_missing_run_script(self, process):
        with self.assertRaisesRegex(KphelperError, "startup script not found"):
            local_target("/definitely/missing/run.sh")

        process.assert_not_called()

    @patch("kphelper.core.session.remote", side_effect=RuntimeError("connection refused"))
    def test_remote_connection_errors_are_user_facing(self, _remote):
        with self.assertRaisesRegex(KphelperError, "failed to connect to 127.0.0.1:1"):
            remote_target("127.0.0.1", 1)

    def test_debugger_starts_before_upload_waits_for_paused_guest(self):
        events = []
        io = object()
        with ExitStack() as stack:
            stack.enter_context(patch("kphelper.commands.kp_debug.build_only"))
            stack.enter_context(
                patch("kphelper.commands.kp_debug.create_debug_run_copy", return_value=Path("debug.sh"))
            )
            session = stack.enter_context(patch("kphelper.commands.kp_debug.managed_session"))
            stack.enter_context(
                patch("kphelper.commands.kp_debug.kgdb", side_effect=lambda _symbol: events.append("gdb"))
            )
            stack.enter_context(
                patch("kphelper.commands.kp_debug.upload_and_cd", side_effect=lambda _io: events.append("upload"))
            )
            stack.enter_context(patch("kphelper.commands.kp_debug.interact"))
            session.return_value.__enter__.return_value = io
            handle_debug(SimpleNamespace(symbol="vmlinux", nokaslr=False))

        self.assertEqual(events, ["gdb", "upload"])

    @patch("kphelper.commands.kp_symbols._runtime_symbols")
    @patch("kphelper.commands.kp_symbols._cached_symbols", return_value="cached symbols")
    @patch("builtins.print")
    def test_symbols_uses_cache_unless_refresh_is_requested(self, print_output, cached, runtime):
        args = SimpleNamespace(
            symbols=None,
            analysis=False,
            remote=None,
            file=None,
            refresh=False,
            run="run.sh",
            json=False,
            format="macro",
        )

        handle_symbols(args)

        cached.assert_called_once()
        runtime.assert_not_called()
        print_output.assert_called_once_with("cached symbols")


if __name__ == "__main__":
    unittest.main()
