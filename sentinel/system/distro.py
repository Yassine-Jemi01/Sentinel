"""Portable Linux distribution and init-system detection."""
from __future__ import annotations
import platform
import shutil
from pathlib import Path

def read_os_release() -> dict[str, str]:
    values = {}
    try:
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                values[key] = value.strip().strip('"').strip("'")
    except OSError:
        pass
    return values

def detect_init() -> str:
    if Path("/run/systemd/system").exists() or Path("/usr/lib/systemd/systemd").exists():
        return "systemd"
    if Path("/run/openrc").exists() or shutil.which("rc-service"):
        return "openrc"
    if Path("/run/runit").exists() or Path("/etc/runit").exists():
        return "runit"
    if Path("/etc/s6").exists() or shutil.which("s6-svscan"):
        return "s6"
    return "unknown"

def system_info() -> dict[str, str]:
    release = read_os_release()
    return {
        "distro_id": release.get("ID", "unknown"),
        "distro_name": release.get("PRETTY_NAME", "Unknown Linux"),
        "distro_like": release.get("ID_LIKE", ""),
        "version": release.get("VERSION_ID", ""),
        "kernel": platform.release(),
        "architecture": platform.machine(),
        "init": detect_init(),
    }
