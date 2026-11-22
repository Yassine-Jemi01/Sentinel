"""Best-effort reader for common text syslog locations."""
from __future__ import annotations
import re
from datetime import datetime
from pathlib import Path
from sentinel.core.models import Event

PATHS = (Path("/var/log/syslog"), Path("/var/log/messages"), Path("/var/log/secure"), Path("/var/log/auth.log"))
MONTHS = {name: i for i, name in enumerate(("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1)}
PATTERN = re.compile(r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<ident>[^:]+):\s?(?P<message>.*)$")

class SyslogSource:
    name = "syslog"
    def available_paths(self) -> list[Path]:
        return [p for p in PATHS if p.is_file()]
    @staticmethod
    def _tail(path: Path, limit: int) -> list[str]:
        try:
            with path.open("rb") as stream:
                stream.seek(0, 2)
                size = stream.tell()
                stream.seek(max(0, size - 2 * 1024 * 1024))
                content = stream.read().decode("utf-8", errors="replace")
            return content.splitlines()[-limit:]
        except OSError:
            return []
    def read(self, limit: int = 100) -> list[Event]:
        result = []
        year = datetime.now().year
        for path in self.available_paths():
            for line in self._tail(path, max(1, min(limit, 2000))):
                match = PATTERN.match(line)
                if not match:
                    continue
                data = match.groupdict()
                try:
                    stamp = datetime(year, MONTHS[data["mon"]], int(data["day"]), *map(int, data["time"].split(":"))).astimezone().isoformat(timespec="seconds")
                except (ValueError, KeyError):
                    stamp = datetime.now().astimezone().isoformat(timespec="seconds")
                message = data["message"]
                lower = message.casefold()
                priority = 4 if any(word in lower for word in ("warning", "failed", "denied", "error")) else 6
                result.append(Event(stamp, message, priority, hostname=data["host"], identifier=data["ident"], source=f"syslog:{path}"))
        return result[-limit:]
