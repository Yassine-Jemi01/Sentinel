"""Audit availability probe; audit records may also appear in the journal."""
import shutil
from pathlib import Path

class AuditSource:
    name = "audit"
    def available(self) -> bool:
        return bool(shutil.which("ausearch") or Path("/var/log/audit/audit.log").is_file())
    def status(self) -> str:
        if shutil.which("ausearch"):
            return "ausearch available; event access may require permissions"
        if Path("/var/log/audit/audit.log").is_file():
            return "audit log exists; read permissions may be restricted"
        return "not available"
