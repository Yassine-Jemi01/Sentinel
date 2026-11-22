"""Non-blocking capability checks across Linux distributions."""
from __future__ import annotations
import platform
import shutil
import sqlite3
import sys
from pathlib import Path
from sentinel.sources.journald import JournaldSource
from sentinel.sources.syslog import SyslogSource
from sentinel.sources.audit import AuditSource
from sentinel.system.distro import system_info

def check_requirements() -> dict:
    try:
        import textual
        textual_version = getattr(textual, "__version__", "installed")
        textual_available = True
    except ImportError:
        textual_version, textual_available = None, False
    journal = JournaldSource()
    syslog = SyslogSource()
    audit = AuditSource()
    return {
        "system": {**system_info(), "is_linux": platform.system() == "Linux", "python_version": platform.python_version()},
        "requirements": {"python_supported": sys.version_info >= (3, 12), "sqlite_version": sqlite3.sqlite_version, "textual_available": textual_available, "textual_version": textual_version},
        "sources": {
            "journald": {"available": journal.available(), "note": "Optional; permissions may limit access."},
            "syslog": {"available": bool(syslog.available_paths()), "paths": [str(p) for p in syslog.available_paths()]},
            "audit": {"available": audit.available(), "status": audit.status()},
        },
        "security": {"selinux_detected": Path("/sys/fs/selinux").exists(), "apparmor_detected": Path("/sys/module/apparmor").exists(), "auditctl_available": shutil.which("auditctl") is not None},
    }
