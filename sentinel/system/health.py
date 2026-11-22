"""Dependency-free system health snapshot using procfs/sysfs where available."""
from __future__ import annotations
import shutil
from pathlib import Path

def _meminfo() -> dict[str, int]:
    values = {}
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            key, _, rest = line.partition(":")
            parts = rest.split()
            if parts and parts[0].isdigit():
                values[key] = int(parts[0]) * (1024 if len(parts) > 1 and parts[1] == "kB" else 1)
    except OSError:
        pass
    return values

def snapshot() -> dict:
    memory = _meminfo()
    total = memory.get("MemTotal", 0)
    available = memory.get("MemAvailable", memory.get("MemFree", 0))
    try:
        loads = [float(x) for x in Path("/proc/loadavg").read_text().split()[:3]]
    except (OSError, ValueError):
        loads = []
    try:
        disk = shutil.disk_usage("/")
        disk_data = {"total": disk.total, "used": disk.used, "free": disk.free}
        disk_pct = round(disk.used / disk.total * 100, 1) if disk.total else None
    except OSError:
        disk_data, disk_pct = {}, None
    temperatures = []
    for sensor in Path("/sys/class/thermal").glob("thermal_zone*/temp"):
        try:
            temperatures.append(round(int(sensor.read_text().strip()) / 1000, 1))
        except (OSError, ValueError):
            continue
    return {
        "cpu_load": loads,
        "memory": {"total": total, "used": max(0, total - available), "available": available},
        "memory_percent": round((total - available) / total * 100, 1) if total else None,
        "disk": disk_data,
        "disk_percent": disk_pct,
        "temperatures_c": temperatures,
    }
