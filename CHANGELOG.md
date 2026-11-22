# Changelog

All notable changes to Sentinel are documented here.

## 0.1.0

Initial public release.

- Added a Textual terminal interface with Dashboard, Events, Export JSON, and About tabs.
- Added local event collection from systemd journal and supported text syslog files.
- Added deterministic English explanations for authentication, security policy, desktop, graphics, service, kernel, storage, hardware, network, and memory events.
- Added repeated SSH and sudo authentication-event correlation.
- Added distribution, kernel, architecture, and init-system detection.
- Added CPU load, memory, root-filesystem, and thermal-zone health snapshots.
- Added local SQLite event and finding history with deduplication and schema migration.
- Added JSON and standalone HTML report export through the command line.
- Added the GitHub installer and `sentinel update` command.
- Added a source-checkout build script and automated unit tests.
- Documented local data handling, privacy, security boundaries, compatibility, and known limitations.
