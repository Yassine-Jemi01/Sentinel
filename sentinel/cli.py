"""Sentinel command-line interface."""
from __future__ import annotations
import argparse
import json
import subprocess
import sys
from pathlib import Path
from urllib.request import Request, urlopen
from sentinel import __version__
from sentinel.requirements import check_requirements

def update_from_github() -> int:
    """Download and run the official Sentinel updater."""
    url = "https://raw.githubusercontent.com/Yassine-Jemi01/Sentinel/main/install.sh"

    print("Checking for Sentinel updates...")

    try:
        request = Request(
            url,
            headers={"User-Agent": "Sentinel-Updater"},
        )
        with urlopen(request, timeout=30) as response:
            script = response.read()

        if not script.startswith(b"#!/usr/bin/env bash"):
            raise RuntimeError("The downloaded installer is invalid.")

        print("Starting update...")
        result = subprocess.run(
            ["bash", "-s", "--", "--update"],
            input=script,
            check=False,
        )
        return result.returncode

    except Exception as exc:
        print(f"Update failed: {exc}", file=sys.stderr)
        return 1


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="sentinel", description="Local-first Linux Security & System Monitor")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("check", help="show detected system and source capabilities")
    events = sub.add_parser("events", help="analyze recent events")
    events.add_argument("-n", "--limit", type=int, default=100)
    export = sub.add_parser("export", help="export JSON or HTML report")
    export.add_argument("format", choices=("json", "html"))
    export.add_argument("output", nargs="?")
    sub.add_parser("version", help="show version")
    sub.add_parser("update", help="update Sentinel from GitHub")
    args = parser.parse_args(argv)
    if args.command == "version":
        print(f"Sentinel {__version__}")
        return 0
    if args.command == "update":
        return update_from_github()
    if args.command == "check":
        print(json.dumps(check_requirements(), indent=2, ensure_ascii=False))
        return 0
    if args.command in {"events", "export"}:
        from sentinel.core.engine import analyze
        findings, sources, _, _ = analyze(max(1, min(getattr(args, "limit", 100), 2000)))
        if args.command == "events":
            for item in findings:
                print(f"[{item.severity.upper():8}] {item.event.timestamp} {item.category}: {item.title}\n  {item.summary}\n")
            if not findings:
                print("No events found or no readable source is available.")
            print("Sources: " + json.dumps(sources, ensure_ascii=False))
            return 0
        from sentinel.core.report import export_html, export_json
        output = Path(args.output or (Path.home() / f"sentinel-report.{args.format}"))
        result = export_json(findings, output) if args.format == "json" else export_html(findings, output)
        print(f"Report written to: {result}")
        return 0
    if sys.platform != "linux":
        print("Sentinel requires Linux.", file=sys.stderr)
        return 1
    if sys.version_info < (3, 12):
        print("Python 3.12+ is required.", file=sys.stderr)
        return 1
    try:
        from sentinel.ui.app import SentinelApp
        SentinelApp().run()
    except ImportError as exc:
        print(f"Textual is not installed. Run ./build.sh first. ({exc})", file=sys.stderr)
        return 1
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
