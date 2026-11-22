"""Collect events from whichever supported local sources are present."""
from __future__ import annotations
from sentinel.config import load_config
from sentinel.sources.journald import JournaldSource
from sentinel.sources.syslog import SyslogSource

def collect_events(limit: int | None = None):
    config = load_config()
    maximum = max(1, min(int(limit or config["event_limit"]), 2000))
    events, status = [], {}
    if config["monitor_journal"]:
        source = JournaldSource()
        if source.available():
            batch = source.read(maximum)
            events.extend(batch)
            status["journald"] = f"readable ({len(batch)} events)" if batch else "available; no readable events"
        else:
            status["journald"] = "not installed"
    if config["monitor_syslog"]:
        source = SyslogSource()
        paths = source.available_paths()
        if paths:
            batch = source.read(maximum)
            events.extend(batch)
            status["syslog"] = f"readable ({len(batch)} events)" if batch else "files found; no readable entries"
        else:
            status["syslog"] = "no supported log files found"
    unique = {}
    for event in events:
        key = (event.timestamp, event.message, event.identifier or event.unit)
        unique.setdefault(key, event)
    ordered = sorted(unique.values(), key=lambda event: event.timestamp)
    return ordered[-maximum:], status
