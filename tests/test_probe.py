import unittest
from unittest.mock import patch

from kpcli.core.findings import Finding, RuntimeProbeReport
from kpcli.core.probe import HIDDEN, READABLE, _probe_kallsyms, probe_runtime


class ProbeTests(unittest.TestCase):
    def test_kallsyms_is_hidden_when_kptr_restrict_blocks_addresses(self):
        finding, symbols = _probe_kallsyms(
            None,
            (),
            Finding(READABLE, value=1),
        )

        self.assertEqual(finding.status, HIDDEN)
        self.assertEqual(finding.detail, "kptr_restrict=1")
        self.assertEqual(symbols, {})

    @patch("kpcli.core.probe.GuestShell")
    def test_probe_runtime_returns_structured_report(self, guest_shell):
        shell = guest_shell.return_value
        shell.run.side_effect = [
            ("1000", 0),
            ("1", 0),
            ("1", 0),
            ("", 1),
        ]

        report = probe_runtime(object(), names=())

        self.assertIsInstance(report, RuntimeProbeReport)
        self.assertEqual(report.findings["User ID"].value, "1000")
        self.assertEqual(report.findings["kallsyms"].status, HIDDEN)
        self.assertEqual(report.symbols, {})


if __name__ == "__main__":
    unittest.main()
