# Privacy

Sentinel processes event data locally. It does not send telemetry, tracking data, logs, reports, or configuration to a server. No cloud account or remote logging service is required.

The application reads supported local event sources and stores normalized event history in a SQLite database under the user's XDG data directory. Configuration is stored under the user's XDG config directory. Reports are written only to the destination selected by the user.

The optional GitHub installer and updater contact GitHub to retrieve application source, version metadata, and installer content. Installation may also contact Python package repositories to install Textual. These operations do not upload local logs, reports, event history, or configuration.

Logs can contain usernames, hostnames, IP addresses, command arguments, and file paths. Review and redact reports before sharing them. Protect the local configuration and event database as you would other system diagnostic data.
