# Sentinel

**Sentinel — Local-first Linux Security & System Monitor**

Sentinel is a local Linux event-monitoring and system-health application. It collects events from available local logging sources, applies deterministic explanation rules, groups repeated authentication events, stores event history in SQLite, and presents findings in a Textual terminal interface.

Sentinel is designed for visibility and investigation. It does not claim to detect every attack, and a finding is not proof of compromise.

## Contents

- [Features](#features)
- [How it works](#how-it-works)
- [Supported event sources](#supported-event-sources)
- [Detection and explanation rules](#detection-and-explanation-rules)
- [System information and health](#system-information-and-health)
- [Requirements and compatibility](#requirements-and-compatibility)
- [Install from Fedora RPM](#install-from-fedora-rpm)
- [Install from GitHub](#install-from-github)
- [Build from a source checkout](#build-from-a-source-checkout)
- [Command-line reference](#command-line-reference)
- [Terminal interface](#terminal-interface)
- [Configuration](#configuration)
- [Data locations](#data-locations)
- [Privacy and security](#privacy-and-security)
- [Limitations](#limitations)
- [Troubleshooting](#troubleshooting)
- [Uninstall](#uninstall)
- [Development and tests](#development-and-tests)
- [License](#license)

## Features

- **Event collection:** reads the systemd journal when `journalctl` is available and readable; also checks common text syslog files.
- **Deterministic explanations:** maps known log patterns and component identifiers to English descriptions, severity, context, and suggested next steps.
- **Authentication correlation:** groups repeated SSH authentication and sudo-related findings within a configurable time window.
- **Desktop coverage:** recognizes components from GNOME, KDE Plasma, Xfce, Cinnamon, MATE, LXQt, LXDE, Budgie, COSMIC, common display managers, standalone window managers, Wayland compositors, X11/Xwayland, portals, notifications, and D-Bus.
- **System and hardware findings:** includes rules for SELinux and AppArmor denials, process crashes, service failures, storage errors, hardware/I/O errors, network-link changes, and memory pressure.
- **System overview:** reports distribution, kernel, architecture, and detected init system.
- **Health snapshot:** reports CPU load averages, memory usage, root-filesystem usage, and available thermal-zone readings.
- **Local history:** stores normalized events and findings in SQLite, with event deduplication and schema migration support.
- **Reports:** exports findings as JSON or standalone HTML from the CLI; the TUI provides JSON export.
- **Periodic refresh:** refreshes the dashboard and event table while the TUI is running.
- **Local-first operation:** no account, cloud service, telemetry, tracking, or automatic log upload is required.

## How it works

The application follows this pipeline:

1. **Discover sources.** Sentinel checks which supported local log sources are available.
2. **Collect events.** Available sources return a bounded batch of events. Unavailable or unreadable sources do not prevent the other source from being used.
3. **Normalize events.** Journal and syslog records are converted into a common event model.
4. **Explain events.** Ordered deterministic rules classify known patterns. Security and system rules are evaluated before desktop and graphics rules to reduce misleading classifications.
5. **Correlate repeated authentication events.** Similar SSH and sudo findings are counted within the configured time window. Repeated events can receive a higher severity.
6. **Persist locally.** By default, events and findings are stored in the local SQLite database.
7. **Present results.** Findings are shown in the TUI or exported to a report.

The rules are pattern-based and intentionally conservative. Unknown messages remain generic rather than being labelled as attacks.

## Supported event sources

### systemd journal

- Uses the `journalctl` executable with JSON output.
- Reads up to the requested event limit, capped at 2,000.
- Does not require systemd to be the active init system if `journalctl` is installed, but useful journal data and access permissions depend on the host.
- Journal access may be restricted for unprivileged users. Sentinel does not automatically request root privileges.

### Text syslog files

Sentinel checks these common paths when present:

- `/var/log/syslog`
- `/var/log/messages`
- `/var/log/secure`
- `/var/log/auth.log`

The reader parses conventional RFC 3164-style timestamp and process-prefix lines. It reads a bounded tail from each file and does not modify the source logs. Some distributions use different paths, formats, permissions, or binary journal-only logging; those configurations may not be readable by this source.

### Audit

The `sentinel check` capability report probes for `ausearch` or `/var/log/audit/audit.log`. The current event collection pipeline does **not** independently read audit records. Audit messages may still appear in the journal or syslog and be processed through those sources.

## Detection and explanation rules

The current rule set includes:

| Area | Examples |
|---|---|
| Authentication | Failed SSH password/public-key attempts, unknown SSH users, sudo/PAM authentication events |
| Security policy | SELinux AVC denials and AppArmor denials |
| Desktop environments | GNOME, KDE Plasma, Xfce, Cinnamon, MATE, LXQt, LXDE, Budgie, COSMIC |
| Window managers and compositors | Openbox, i3, Sway, Hyprland, bspwm, Awesome, dwm, River, Wayfire, Labwc |
| Login and display | GDM, SDDM, LightDM, LXDM, greetd, Xorg, Xwayland, Wayland |
| Desktop services | XDG Desktop Portal, notification services, D-Bus |
| Kernel and processes | Segmentation faults and general protection faults |
| Services | Failed service starts, failed main processes, dependency failures |
| Storage and hardware | Filesystem-full/read-only errors, I/O errors, machine-check events |
| Network and memory | Link/carrier loss, unreachable network, out-of-memory events |

A rule match is a clue based on log content and metadata. It is not a verified security incident. The original event is retained in the finding so the operator can inspect the source message.

## System information and health

The `check` command reports:

- Distribution identifiers and display name from `/etc/os-release`.
- Kernel release and machine architecture.
- Detected init system: systemd, OpenRC, runit, s6, or unknown.
- Python, SQLite, and Textual availability/version information.
- Whether journald, common syslog files, audit tooling, SELinux, and AppArmor appear to be present.

The dashboard health snapshot uses Linux procfs/sysfs and standard filesystem information where available:

- CPU load averages for 1, 5, and 15 minutes.
- Total, used, and available memory from `/proc/meminfo`.
- Usage of the root filesystem.
- Readable thermal-zone temperatures under `/sys/class/thermal`.

These are best-effort snapshots. Missing kernel interfaces or permissions may cause a field to be unavailable.

## Requirements and compatibility

- Linux.
- Linux and Python 3.12 or newer.
- Textual 1.x through 8.x. The Fedora RPM uses the distribution-provided Python and Textual packages.
- Python virtual-environment support (`venv`) and network access are needed for the GitHub installer or source-checkout build, not for an RPM-managed installation.
- `curl` or `wget` and `tar` are needed for the GitHub installer.

The application does not require systemd, but journal collection specifically requires `journalctl`. Syslog collection depends on supported files being present and readable.

The code includes init detection for systemd, OpenRC, runit, and s6. Other init systems are reported as `unknown`; that does not necessarily prevent the application from running.

Compatibility depends on the logging configuration and permissions of each host. The project does not claim that every distribution release or desktop environment has been tested.

## Install from Fedora RPM

The Fedora package is being prepared for distribution review and is not yet available from the official Fedora repositories. Do not assume that `dnf install sentinel` is available until Fedora publishes the package.

To install a locally built RPM for testing:

```bash
sudo dnf install ./path/to/sentinel.rpm
```

For an RPM-managed installation, update Sentinel through the system package manager:

```bash
sudo dnf upgrade sentinel
```

Remove the RPM with `sudo dnf remove sentinel`. These package-manager operations do not remove Sentinel's per-user configuration or event history.

## Install from GitHub

Install the latest contents of the `main` branch into a dedicated user environment:

```bash
curl -fsSL https://raw.githubusercontent.com/Yassine-Jemi01/Sentinel/main/install.sh | bash
```

The installer:

1. Checks that the host is Linux and Python 3.12+ is available.
2. Downloads the source archive from GitHub.
3. Creates or reuses `~/.local/share/sentinel/venv` (or the corresponding `XDG_DATA_HOME` location).
4. Installs Sentinel and its Python dependencies.
5. Creates `~/.local/bin/sentinel`.

No root access is requested. Ensure `~/.local/bin` is on your `PATH`. For Fish, run:

```fish
fish_add_path ~/.local/bin
```

For Bash:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

Start the application:

```bash
sentinel
```

## Build from a source checkout

Clone the repository and run the user-facing build script:

```bash
git clone https://github.com/Yassine-Jemi01/Sentinel.git
cd Sentinel
./build.sh
```

The build script creates a project-local `.venv`, installs the package quietly, compiles the Python sources, runs the unit tests, and creates `~/.local/bin/sentinel` as a symlink to the checkout's virtual environment.

This is intended for a source checkout/development installation. The GitHub installer uses a separate dedicated environment under the user's data directory.

## Command-line reference

| Command | Description |
|---|---|
| `sentinel` | Launch the Textual terminal interface. |
| `sentinel check` | Print system, dependency, and source capability information as JSON. |
| `sentinel events` | Analyze and print recent findings. |
| `sentinel events -n 250` | Analyze up to 250 events; the accepted range is capped at 2,000. |
| `sentinel export json` | Write a JSON report to `~/sentinel-report.json`. |
| `sentinel export html` | Write a standalone HTML report to `~/sentinel-report.html`. |
| `sentinel export json /path/report.json` | Write a report to an explicit destination. |
| `sentinel version` | Print the installed version. |
| `sentinel update` | Update a GitHub-installed copy; RPM-managed installs use the system package manager. |
| `sentinel --help` | Show command help. |

The `events` and `export` commands analyze the current available source batch and persist collected events/findings to the local database by default.

### Update

For an installation made with the GitHub installer, run:

```bash
sentinel update
```

The updater downloads the current `install.sh` from the repository's `main` branch and runs it with `--update`. It first checks whether the running executable is owned by an RPM package. RPM-managed installations are never updated by this script; Sentinel prints a package-manager command instead. If RPM ownership cannot be verified, the update is stopped.

A source-checkout installation is not updated by the GitHub installer. Use `git pull` and rerun `./build.sh` for that installation type.

## Terminal interface

The Textual interface contains four tabs:

- **Dashboard:** distribution/kernel/init details, event counts, health snapshot, and source status.
- **Events:** a table of recent findings. Select or highlight a row to inspect its explanation, severity, confidence, correlation count, recommendation, and original log message.
- **Export JSON:** choose a directory and filename for a local JSON report.
- **About:** project purpose and safety notes.

Keyboard bindings:

| Key | Action |
|---|---|
| `Q` | Quit |
| `R` | Refresh data |
| `D` | Switch to Dashboard |
| `E` | Switch to Events |
| `X` | Switch to Export |

The Events table also supports the standard cursor navigation provided by Textual's DataTable widget.

## Configuration

Configuration is read from:

```text
$XDG_CONFIG_HOME/sentinel/config.json
```

If `XDG_CONFIG_HOME` is not set, Sentinel uses:

```text
~/.config/sentinel/config.json
```

Supported keys and defaults:

| Key | Default | Bounds / meaning |
|---|---:|---|
| `refresh_seconds` | `5` | TUI refresh interval, clamped to 2–60 seconds; the UI uses at least 5 seconds. |
| `event_limit` | `300` | Default event batch size, clamped to 50–2,000. |
| `monitor_journal` | `true` | Enable the optional journal source. |
| `monitor_syslog` | `true` | Enable supported text syslog files. |
| `correlation_window_seconds` | `300` | Authentication correlation window, clamped to 30–3,600 seconds. |

Example:

```json
{
  "refresh_seconds": 5,
  "event_limit": 300,
  "monitor_journal": true,
  "monitor_syslog": true,
  "correlation_window_seconds": 300
}
```

Unknown keys are ignored. Invalid values fall back to safe defaults. Configuration is local and is not transmitted.

## Data locations

Sentinel respects XDG base-directory environment variables.

| Data | Default location |
|---|---|
| Configuration | `~/.config/sentinel/config.json` |
| SQLite event history | `~/.local/share/sentinel/events.sqlite3` |
| GitHub-installed application environment | `~/.local/share/sentinel/venv` |
| User command | `~/.local/bin/sentinel` |
| Default CLI reports | `~/sentinel-report.json` or `~/sentinel-report.html` |

The SQLite database uses a local file and WAL journaling. Existing database files are migrated by adding missing columns; Sentinel does not intentionally delete historical records during schema migration.

## Privacy and security

- Event collection and analysis happen locally.
- Sentinel does not send telemetry, tracking data, logs, reports, or configuration to a server.
- No cloud account or remote logging service is required.
- Source logs are read-only from Sentinel's perspective; Sentinel does not edit or delete them.
- Sentinel does not change SELinux, AppArmor, firewall, or service policies.
- Sentinel does not block processes or automatically remediate findings.
- Sentinel invokes fixed system utilities with argument lists where needed (currently `journalctl` and, for RPM ownership checks, `rpm`). It never interprets log messages as shell commands or executable code.
- The optional GitHub self-updater downloads and runs the project's installer only for a confirmed non-RPM user installation. It does not automatically elevate privileges.
- Run Sentinel as an ordinary user. Some logs may be unavailable without additional permissions; Sentinel does not automatically elevate privileges.
- Logs can contain usernames, hostnames, IP addresses, command arguments, and file paths. Review and redact exported reports before sharing them.

The installer contacts GitHub to download the application source and Python package repositories to install dependencies. The running application does not automatically upload local event data.

## Limitations

Sentinel is an experimental local event-visibility and system-health tool. It is **not**:

- An antivirus or malware scanner.
- A firewall or intrusion-prevention system.
- A full SIEM or centralized log-management platform.
- A guarantee that all suspicious activity will be detected.
- A replacement for reviewing original logs, maintaining backups, or applying security updates.

Rules are deterministic pattern matches. Log formats vary, source access may be restricted, and false positives or missed events are possible. A high-severity finding means the matched rule considers the event important; it does not establish that the system is compromised.

## Troubleshooting

**The `sentinel` command is not found**

Ensure `~/.local/bin` is on `PATH`. In Fish, run `fish_add_path ~/.local/bin`; in Bash, add `export PATH="$HOME/.local/bin:$PATH"` to the shell startup file.

**No journal events are shown**

Check whether `journalctl` exists and whether the current user can read the journal. Try `sentinel check` to inspect source availability. Journal permissions are controlled by the host distribution.

**No syslog events are shown**

Sentinel only checks the four paths listed above and expects conventional text syslog lines. Your distribution may use different paths or journal-only logging.

**Some health values are unavailable**

Sentinel reads procfs, sysfs, and filesystem information where available. A missing interface, sensor, or permission can leave a field unavailable.

**Installation fails while creating the virtual environment**

Install your distribution's Python venv support package, then rerun the installer or `./build.sh`.

## Uninstall

For an RPM installation, use the system package manager:

```bash
sudo dnf remove sentinel
```

For a GitHub installation, remove the application environment and command:

```bash
rm -rf "${XDG_DATA_HOME:-$HOME/.local/share}/sentinel/venv"
rm -f "$HOME/.local/bin/sentinel"
```

This intentionally leaves the configuration and event database in place. To remove those local data files as well, delete:

```bash
rm -rf "${XDG_CONFIG_HOME:-$HOME/.config}/sentinel"
rm -rf "${XDG_DATA_HOME:-$HOME/.local/share}/sentinel"
```

For a source-checkout installation, also remove the checkout's `.venv` directory. Review the paths before running removal commands.

## Development and tests

Run the test suite from the repository root:

```bash
python3 -m compileall -q main.py sentinel
python3 -W error::ResourceWarning -m unittest discover -s tests -v
```

Run the end-user setup and validation workflow:

```bash
./build.sh
```

The tests cover event normalization, rule matching and precedence, desktop/window-manager detection, correlation, SQLite deduplication and rollback, read-only database integrity checks, safe HTML report escaping, CLI update safety, and system snapshot structure.

## License

Sentinel is distributed under the MIT License. See [LICENSE](LICENSE).
