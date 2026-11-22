"""Local configuration; Sentinel never sends configuration anywhere."""
from __future__ import annotations
import json
import os
from pathlib import Path

DEFAULTS = {
    "language": "en",
    "refresh_seconds": 5,
    "event_limit": 300,
    "monitor_journal": True,
    "monitor_syslog": True,
    "correlation_window_seconds": 300,
}

def config_path() -> Path:
    base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return base / "sentinel" / "config.json"

def load_config() -> dict:
    result = dict(DEFAULTS)
    try:
        loaded = json.loads(config_path().read_text(encoding="utf-8"))
        if isinstance(loaded, dict):
            result.update({k: v for k, v in loaded.items() if k in DEFAULTS})
    except (OSError, json.JSONDecodeError):
        pass
    try:
        result["refresh_seconds"] = max(2, min(60, int(result["refresh_seconds"])))
        result["event_limit"] = max(50, min(2000, int(result["event_limit"])))
        result["correlation_window_seconds"] = max(30, min(3600, int(result["correlation_window_seconds"])))
    except (TypeError, ValueError):
        result = dict(DEFAULTS)
    if result["language"] not in {"en", "ar"}:
        result["language"] = "en"
    return result

def save_config(values: dict) -> Path:
    result = load_config()
    result.update({k: v for k, v in values.items() if k in DEFAULTS})
    path = config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)
    return path
