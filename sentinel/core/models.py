"""Normalized event and human-readable finding models."""
from __future__ import annotations
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

PRIORITIES = {0: "EMERG", 1: "ALERT", 2: "CRIT", 3: "ERROR", 4: "WARNING", 5: "NOTICE", 6: "INFO", 7: "DEBUG"}

@dataclass(slots=True)
class Event:
    timestamp: str
    message: str
    priority: int = 6
    hostname: str = ""
    unit: str = ""
    identifier: str = ""
    source: str = "unknown"
    event_id: str = ""

    @property
    def priority_name(self) -> str:
        return PRIORITIES.get(self.priority, "UNKNOWN")

    @classmethod
    def from_journal(cls, item: dict[str, Any]) -> "Event":
        try:
            micros = int(item.get("__REALTIME_TIMESTAMP", "0"))
            stamp = datetime.fromtimestamp(micros / 1_000_000, tz=timezone.utc).astimezone().isoformat(timespec="seconds")
        except (ValueError, TypeError, OSError, OverflowError):
            stamp = datetime.now().astimezone().isoformat(timespec="seconds")
        try:
            priority = max(0, min(7, int(item.get("PRIORITY", 6))))
        except (ValueError, TypeError):
            priority = 6
        message = item.get("MESSAGE", "")
        if isinstance(message, list):
            try:
                message = bytes(message).decode("utf-8", errors="replace")
            except (ValueError, TypeError):
                message = ""
        return cls(
            timestamp=stamp,
            message=str(message).replace("\x00", "�"),
            priority=priority,
            hostname=str(item.get("_HOSTNAME", "")),
            unit=str(item.get("_SYSTEMD_UNIT", "")),
            identifier=str(item.get("SYSLOG_IDENTIFIER", "")),
            source="journald",
            event_id=f"{item.get('_BOOT_ID', '')}:{item.get('__MONOTONIC_TIMESTAMP', '')}",
        )

    def to_dict(self) -> dict:
        return asdict(self)

@dataclass(slots=True)
class Finding:
    event: Event
    title: str
    category: str
    severity: str
    summary: str
    why_it_matters: str
    recommendation: str
    confidence: str = "medium"
    rule_id: str = "generic"
    correlated_count: int = 1

    def to_dict(self) -> dict:
        result = asdict(self)
        result["event"] = self.event.to_dict()
        return result
