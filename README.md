# Sentinel

**Local-first Linux Security & System Monitor**

Sentinel reads available local event sources, explains common messages in human language, groups repeated authentication events, and displays a lightweight system-health snapshot.

## Features

- Textual TUI with Dashboard, Events, and About tabs.
- Human-readable deterministic event explanations.
- English and Arabic explanation labels and summaries.
- Optional journald and common syslog file sources.
- Distribution, kernel, architecture, and init-system detection.
- Repeated authentication-event correlation.
- Local SQLite history with event deduplication.
- CPU load, memory, disk, and available thermal sensor snapshots.
- JSON and standalone HTML report export.
- Periodic refresh; raw event text remains available for inspection.
- No telemetry, tracking, cloud requirement, or automatic uploads.

## Linux compatibility

Sentinel targets Linux distributions using systemd, OpenRC, runit, s6, or another init system. Journald is optional. If it is unavailable, Sentinel attempts to read common syslog files when present and readable.

The intended test targets include Debian/Ubuntu, Fedora/RHEL-family, Arch/Manjaro, openSUSE, Alpine, Void, Gentoo, and NixOS. Actual sources depend on each system's logging configuration and permissions. This is broad compatibility intent, not a claim that every distribution/version has been tested.

## Requirements

- Linux
- Python 3.12+
- Python venv support
- Network access for the first installation of Textual

`journalctl`, syslog files, audit tools, and thermal sensors are optional.

## Developer generation

`dev-build.sh` generates or updates the project files, tests, documentation, and separate user-facing `build.sh`. It does not install packages, create a virtual environment, or download dependencies.

```bash
chmod +x dev-build.sh
./dev-build.sh
```

## End-user setup

```bash
chmod +x build.sh
./build.sh
```

## Usage

```bash
.venv/bin/python main.py
.venv/bin/python main.py check
.venv/bin/python main.py events
.venv/bin/python main.py export json
.venv/bin/python main.py export html
```

## TUI keys

- `R`: refresh
- `D`: Dashboard
- `E`: Events
- `X`: export JSON
- `Q`: quit

## Local paths

- Config: `~/.config/sentinel/config.json`
- Database: `~/.local/share/sentinel/events.sqlite3`
- Default reports: home directory

`XDG_CONFIG_HOME` and `XDG_DATA_HOME` are respected.

## Privacy and safety

Sentinel processes data locally. It does not upload logs, change SELinux/AppArmor/firewall policies, delete source logs, block processes, or execute commands found in logs. Run it as an unprivileged user. Logs may contain usernames, hostnames, IP addresses, and paths; redact them before sharing.

## Limitations

Sentinel is an experimental event visibility and system-health tool, not an antivirus, firewall, SIEM, or intrusion-prevention system. Rules are heuristic. An alert is not proof of compromise, and recommendations are informational rather than automatic remediation.

## License

MIT
