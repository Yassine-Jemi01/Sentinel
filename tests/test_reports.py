"""Report export tests for untrusted event text."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sentinel.core.models import Event, Finding
from sentinel.core.report import export_html, export_json


class ReportExportTests(unittest.TestCase):
    def setUp(self):
        self.finding = Finding(
            event=Event(
                "2026-01-01T00:00:00+00:00",
                '<script>alert("log")</script>',
            ),
            title="<img src=x onerror=alert(1)>",
            category="Test",
            severity="high",
            summary="Test summary",
            why_it_matters="Test explanation",
            recommendation="Inspect the original event",
        )

    def test_html_report_escapes_untrusted_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "report.html"
            with (
                patch("sentinel.core.report.system_info", return_value={}),
                patch("sentinel.core.report.snapshot", return_value={}),
            ):
                export_html([self.finding], destination)

            content = destination.read_text(encoding="utf-8")
            self.assertNotIn("<script>", content)
            self.assertNotIn("<img src=x", content)
            self.assertIn("&lt;script&gt;", content)
            self.assertIn("&lt;img", content)

    def test_json_report_preserves_event_text_as_data(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "report.json"
            with (
                patch("sentinel.core.report.system_info", return_value={}),
                patch("sentinel.core.report.snapshot", return_value={}),
            ):
                export_json([self.finding], destination)

            data = json.loads(destination.read_text(encoding="utf-8"))
            self.assertEqual(
                data["findings"][0]["event"]["message"],
                '<script>alert("log")</script>',
            )


if __name__ == "__main__":
    unittest.main()
