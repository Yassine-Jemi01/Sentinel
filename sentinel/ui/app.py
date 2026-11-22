"""Terminal dashboard for findings and system health."""
from __future__ import annotations

import hashlib
from pathlib import Path

from textual.app import App, ComposeResult
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    Static,
    TabbedContent,
    TabPane,
)

from sentinel.config import load_config
from sentinel.core.engine import analyze
from sentinel.core.report import export_json
from sentinel.system.distro import system_info
from sentinel.system.health import snapshot


class SentinelApp(App):
    TITLE = "Sentinel"
    SUB_TITLE = "Linux Security & System Monitor"

    CSS = """
    #overview, #health, #sources, #detail {
        height: auto;
        padding: 1 2;
        border: round $primary;
        margin: 1;
    }

    #event_table {
        height: 1fr;
        margin: 0 1;
    }

    #detail {
        min-height: 10;
    }

    #about_text {
        padding: 2 3;
    }

    #export_panel {
        padding: 2 3;
        height: auto;
    }

    #export_panel Input {
        margin-bottom: 1;
    }

    #export_status {
        margin-top: 1;
    }
    """

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("r", "refresh", "Refresh"),
        ("d", "dashboard", "Dashboard"),
        ("e", "events", "Events"),
        ("x", "export", "Export JSON"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()

        with TabbedContent(initial="dashboard"):
            with TabPane("Dashboard", id="dashboard"):
                yield Static("Loading...", id="overview")
                yield Static("", id="health")
                yield Static("", id="sources")

            with TabPane("Events", id="events"):
                yield DataTable(
                    id="event_table",
                    cursor_type="row",
                )
                yield Static(
                    "Select an event to inspect its explanation.",
                    id="detail",
                    markup=False,
                )

            with TabPane("Export JSON", id="export"):
                with Static(id="export_panel"):
                    yield Static("JSON REPORT EXPORT")
                    yield Static("Save directory")
                    yield Input(
                        value=str(Path.home() / "Documents"),
                        placeholder="/home/user/Documents",
                        id="export_dir",
                    )
                    yield Static("File name")
                    yield Input(
                        value="sentinel-report.json",
                        placeholder="sentinel-report.json",
                        id="export_filename",
                    )
                    yield Button(
                        "Export JSON",
                        id="export_json",
                        variant="primary",
                    )
                    yield Static(
                        "Choose where to save your local report.",
                        id="export_status",
                    )

            with TabPane("About", id="about"):
                yield Static(
                    "Sentinel 0.1.0\n\n"
                    "Local-first Linux event visibility and system health monitor.\n\n"
                    "Sentinel does not require systemd, root access, or a cloud "
                    "service. It does not modify security policies, delete source "
                    "logs, upload data, block processes, or execute commands "
                    "found in logs.\n\n"
                    "Findings are heuristic; an alert is not proof of compromise.",
                    id="about_text",
                    markup=False,
                )

        yield Footer()

    def on_mount(self) -> None:
        self._findings = []
        self._findings_by_key = {}

        table = self.query_one("#event_table", DataTable)
        table.add_columns(
            "Time",
            "Severity",
            "Category",
            "Finding",
            "Source",
        )

        self.refresh_data()

        try:
            seconds = max(5, int(load_config()["refresh_seconds"]))
        except (KeyError, TypeError, ValueError):
            seconds = 30

        self.set_interval(seconds, self.refresh_data)

    @staticmethod
    def _finding_key(finding) -> str:
        event = finding.event
        raw = "\0".join((
            event.timestamp,
            event.message,
            event.unit,
            event.identifier,
            event.source,
            finding.rule_id,
        ))
        return hashlib.sha256(
            raw.encode("utf-8", errors="replace")
        ).hexdigest()

    def refresh_data(self) -> None:
        try:
            findings, sources, new_events, new_findings = analyze()

            self._findings = list(reversed(findings))
            self._findings_by_key = {
                self._finding_key(finding): finding
                for finding in self._findings
            }

            info = system_info()

            self.query_one("#overview", Static).update(
                f"SYSTEM\n"
                f"{info['distro_name']} · {info['kernel']} · "
                f"{info['architecture']} · init: {info['init']}\n"
                f"EVENTS  {len(findings)} analyzed · "
                f"{sum(f.severity in ('critical', 'high') for f in findings)} "
                f"high/critical · "
                f"{sum(f.severity == 'medium' for f in findings)} medium\n"
                f"Newly stored: {new_events} events / "
                f"{new_findings} findings"
            )

            health = snapshot()
            loads = ", ".join(
                f"{value:.2f}" for value in health["cpu_load"]
            ) or "unavailable"

            mem = (
                f"{health['memory_percent']}%"
                if health["memory_percent"] is not None
                else "unavailable"
            )
            disk = (
                f"{health['disk_percent']}%"
                if health["disk_percent"] is not None
                else "unavailable"
            )
            temps = ", ".join(
                f"{value:.1f}°C"
                for value in health["temperatures_c"][:4]
            ) or "unavailable"

            self.query_one("#health", Static).update(
                f"SYSTEM HEALTH\n"
                f"CPU load (1/5/15m): {loads}   "
                f"Memory: {mem}   Disk (/): {disk}   "
                f"Temperatures: {temps}"
            )

            self.query_one("#sources", Static).update(
                "EVENT SOURCES\n"
                + (
                    "\n".join(
                        f"{name}: {status}"
                        for name, status in sources.items()
                    )
                    or "No configured source found."
                )
            )

            table = self.query_one("#event_table", DataTable)
            table.clear()

            for finding in self._findings:
                key = self._finding_key(finding)
                table.add_row(
                    finding.event.timestamp.replace("T", " ")[:19],
                    finding.severity.upper(),
                    finding.category,
                    finding.title[:80],
                    finding.event.source[:28],
                    key=key,
                )

        except Exception as exc:
            self.notify(
                f"Refresh failed: {type(exc).__name__}: {exc}",
                severity="error",
            )

    def _show_finding(self, row_key) -> None:
        if row_key is None:
            return

        key = str(row_key.value)
        finding = self._findings_by_key.get(key)

        if finding is None:
            return

        self.query_one("#detail", Static).update(
            f"{finding.title} [{finding.severity.upper()}]\n"
            f"Category: {finding.category} · "
            f"Rule: {finding.rule_id} · "
            f"Confidence: {finding.confidence} · "
            f"Similar events: {finding.correlated_count}\n\n"
            f"WHAT HAPPENED\n{finding.summary}\n\n"
            f"WHY IT MATTERS\n{finding.why_it_matters}\n\n"
            f"SUGGESTED NEXT STEP\n{finding.recommendation}\n\n"
            f"ORIGINAL LOG\n{finding.event.message[:3000]}"
        )

    def on_data_table_row_highlighted(
        self,
        event: DataTable.RowHighlighted,
    ) -> None:
        self._show_finding(event.row_key)

    def on_data_table_row_selected(
        self,
        event: DataTable.RowSelected,
    ) -> None:
        self._show_finding(event.row_key)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "export_json":
            self.export_report()

    def export_report(self) -> None:
        directory_text = self.query_one("#export_dir", Input).value.strip()
        filename = self.query_one("#export_filename", Input).value.strip()

        status = self.query_one("#export_status", Static)

        if not directory_text:
            status.update("Error: Choose a save directory.")
            self.notify("Save directory is required.", severity="error")
            return

        if not filename:
            status.update("Error: Enter a file name.")
            self.notify("File name is required.", severity="error")
            return

        # Accept a file name, not a path, to keep directory selection explicit.
        if filename in (".", "..") or Path(filename).name != filename:
            status.update("Error: Enter a file name without directory paths.")
            self.notify("Invalid file name.", severity="error")
            return

        if not filename.lower().endswith(".json"):
            filename += ".json"

        try:
            directory = Path(directory_text).expanduser()
            destination = directory / filename

            result = export_json(
                getattr(self, "_findings", []),
                destination,
            )

            status.update(f"Report saved successfully:\n{result}")
            self.notify(f"JSON exported: {result}")

        except (OSError, ValueError) as exc:
            status.update(f"Export failed: {exc}")
            self.notify(
                f"Export failed: {exc}",
                severity="error",
            )

    def action_refresh(self) -> None:
        self.refresh_data()
        self.notify("Sentinel data refreshed")

    def action_dashboard(self) -> None:
        self.query_one(TabbedContent).active = "dashboard"

    def action_events(self) -> None:
        self.query_one(TabbedContent).active = "events"

    def action_export(self) -> None:
        self.query_one(TabbedContent).active = "export"
