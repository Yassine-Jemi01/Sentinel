# Security Policy

Sentinel is an experimental local event-visibility and system-health tool. Run it as an unprivileged user.

Sentinel reads supported local event sources and does not modify or delete the original logs. It writes its own configuration, SQLite history, and reports to user-selected locations. It does not change security policies or firewall rules, block processes, or automatically remediate findings.

The application invokes fixed system utilities with argument lists where needed. It does not interpret event messages or log contents as shell commands or executable code. The optional GitHub updater downloads and runs the project's installer only for a confirmed non-RPM user installation. RPM-managed installations are directed to their system package manager; uncertain RPM ownership checks stop the update.

Findings are heuristic explanations of log patterns, not proof of compromise. Run Sentinel without elevated privileges; some log sources may consequently be unavailable. Redact logs before including them in public bug reports.

For security reports, open a private security advisory through the repository's GitHub Security tab when available. Do not publish sensitive logs, credentials, or personal data in public issues.
