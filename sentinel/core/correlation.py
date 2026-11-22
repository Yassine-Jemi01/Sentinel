"""Group repeated authentication messages without inferring attacker identity."""
from collections import defaultdict
from datetime import datetime

def correlate(findings, window_seconds: int = 300):
    groups = defaultdict(list)
    for finding in findings:
        if finding.rule_id in {"ssh_failed_password", "ssh_invalid_user", "sudo_auth"}:
            # Group by rule and log identifier. Do not invent an IP/source attribution.
            groups[(finding.rule_id, finding.event.identifier or finding.event.unit)].append(finding)
    for group in groups.values():
        parsed = []
        for item in group:
            try:
                parsed.append((datetime.fromisoformat(item.event.timestamp), item))
            except (TypeError, ValueError):
                continue
        for current_time, item in parsed:
            count = sum(abs((current_time - other_time).total_seconds()) <= window_seconds for other_time, _ in parsed)
            item.correlated_count = count
            if count >= 5:
                item.severity = "high"
                item.title += " (repeated)"
                item.summary += f" Sentinel grouped {count} similar events in the configured time window."
            elif count > 1:
                item.summary += f" Sentinel found {count} similar events in the configured time window."
    return findings
