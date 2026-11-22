"""Sentinel command-line interface."""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from urllib.request import Request, urlopen

from sentinel import __version__
from sentinel.requirements import check_requirements


REPO = "Yassine-Jemi01/Sentinel"
RAW_BASE = f"https://raw.githubusercontent.com/{REPO}/main"


def _version_key(value: str) -> tuple[int, ...]:
    """Parse a numeric release version for update comparison."""
    if not re.fullmatch(r"\d+(?:\.\d+)*", value.strip()):
        raise RuntimeError(f"Unsupported version format: {value!r}")
    parts = [int(part) for part in value.strip().split(".")]
    while len(parts) > 1 and parts[-1] == 0:
        parts.pop()
    return tuple(parts)


def _get_remote_version() -> str:
    """Read the version declared by the latest source on the main branch."""
    request = Request(
        f"{RAW_BASE}/pyproject.toml",
        headers={"User-Agent": "Sentinel-Updater"},
    )
    with urlopen(request, timeout=30) as response:
        metadata = tomllib.loads(response.read().decode("utf-8"))

    version = metadata.get("project", {}).get("version")
    if not isinstance(version, str) or not version:
        raise RuntimeError("The remote project version could not be read.")
    _version_key(version)
    return version


def update_from_github() -> int:
    """Install Sentinel only when a newer version is available."""
    print("Checking for Sentinel updates...")

    try:
        remote_version = _get_remote_version()
        current_key = _version_key(__version__)
        remote_key = _version_key(remote_version)

        if remote_key <= current_key:
            if remote_key == current_key:
                print(f"Sentinel is already up to date ({__version__}).")
            else:
                print(
                    "No newer version is available. "
                    f"Installed: {__version__}; repository: {remote_version}."
                )
            return 0

        print(f"Update available: {__version__} -> {remote_version}")

        request = Request(
            f"{RAW_BASE}/install.sh",
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
        print(f"Update check failed: {exc}", file=sys.stderr)
        return 1


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="Local-first Linux Security & System Monitor",
    )
    parser.add_argument(
        "-update",
        dest="update_flag",
        action="store_true",
        help="check for and install updates",
    )
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("check", help="show detected system and source capabilities")
    events = sub.add_parser("events", help="analyze recent events")
    events.add_argument("-n", "--limit", type=int, default=100)
    export = sub.add_parser("export", help="export JSON or HTML report")
    export.add_argument("format", choices=("json", "html"))
    export.add_argument("output", nargs="?")
    sub.add_parser("version", help="show version")
    sub.add_parser("update", help="check for and install updates")
    args = parser.parse_args(argv)

    if args.update_flag and args.command is not None:
        parser.error("-update cannot be combined with another command")

    if args.update_flag or args.command == "update":
        return update_from_github()
    if args.command == "version":
        print(f"Sentinel {__version__}")
        return 0
    if args.command == "check":
        print(json.dumps(check_requirements(), indent=2, ensure_ascii=False))
        return 0
    if args.command in {"events", "export"}:
        from sentinel.core.engine import analyze

        findings, sources, _, _ = analyze(
            max(1, min(getattr(args, "limit", 100), 2000))
        )
        if args.command == "events":
            for item in findings:
                print(
                    f"[{item.severity.upper():8}] {item.event.timestamp} "
                    f"{item.category}: {item.title}\n  {item.summary}\n"
                )
            if not findings:
                print("No events found or no readable source is available.")
            print("Sources: " + json.dumps(sources, ensure_ascii=False))
            return 0

        from sentinel.core.report import export_html, export_json

        output = Path(args.output or (Path.home() / f"sentinel-report.{args.format}"))
        result = (
            export_json(findings, output)
            if args.format == "json"
            else export_html(findings, output)
        )
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
        print(
            f"Textual is not installed. Run ./build.sh first. ({exc})",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
