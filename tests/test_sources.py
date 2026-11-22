"""Tests for bounded local event-source behavior."""
from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sentinel.sources.journald import JournaldSource
from sentinel.sources.syslog import SyslogSource


class JournaldSourceTests(unittest.TestCase):
    def test_reads_json_with_fixed_arguments_and_timeout(self):
        record = {
            "__REALTIME_TIMESTAMP": "0",
            "PRIORITY": "4",
            "MESSAGE": "journal warning",
            "SYSLOG_IDENTIFIER": "test-service",
        }
        result = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=json.dumps(record) + "\n", stderr=""
        )
        source = JournaldSource()
        with (
            patch.object(source, "available", return_value=True),
            patch("sentinel.sources.journald.subprocess.run", return_value=result) as run,
        ):
            events = source.read(25)

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].message, "journal warning")
        args = run.call_args.args[0]
        self.assertEqual(args[0], "journalctl")
        self.assertIn("--output=json", args)
        self.assertIn("-n25", args)
        self.assertEqual(run.call_args.kwargs["timeout"], 15)
        self.assertNotIn("shell", run.call_args.kwargs)

    def test_ignores_malformed_journal_lines(self):
        result = subprocess.CompletedProcess(
            args=[], returncode=0, stdout='{"MESSAGE":"ok"}\nnot-json\n', stderr=""
        )
        source = JournaldSource()
        with (
            patch.object(source, "available", return_value=True),
            patch("sentinel.sources.journald.subprocess.run", return_value=result),
        ):
            events = source.read(10)
        self.assertEqual([event.message for event in events], ["ok"])

    def test_nonzero_journal_exit_returns_empty_batch(self):
        result = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="permission denied"
        )
        source = JournaldSource()
        with (
            patch.object(source, "available", return_value=True),
            patch("sentinel.sources.journald.subprocess.run", return_value=result),
        ):
            self.assertEqual(source.read(10), [])


class SyslogSourceTests(unittest.TestCase):
    def test_parses_supported_syslog_line(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "messages"
            path.write_text(
                "Jan  1 00:00:00 host-a sshd[123]: Failed password for root\n",
                encoding="utf-8",
            )
            source = SyslogSource()
            with patch.object(source, "available_paths", return_value=[path]):
                events = source.read(10)

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].hostname, "host-a")
        self.assertEqual(events[0].identifier, "sshd[123]")
        self.assertIn("Failed password", events[0].message)


if __name__ == "__main__":
    unittest.main()
