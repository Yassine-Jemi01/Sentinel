"""Optional systemd journal reader. Uses journalctl only when present."""
from __future__ import annotations
import json
import shutil
import subprocess
from sentinel.core.models import Event

class JournaldSource:
    name = "journald"
    def available(self) -> bool:
        return shutil.which("journalctl") is not None
    def read(self, limit: int = 100) -> list[Event]:
        if not self.available():
            return []
        limit = max(1, min(int(limit), 2000))
        try:
            result = subprocess.run(
                ["journalctl", "--no-pager", "--quiet", "--output=json", f"-n{limit}"],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=15, check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return []
        if result.returncode != 0:
            return []
        events = []
        for line in result.stdout.splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict):
                events.append(Event.from_journal(item))
        return events
