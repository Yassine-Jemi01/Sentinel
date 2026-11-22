"""Collection, explanation, correlation, and local persistence pipeline."""
from sentinel.config import load_config
from sentinel.core.correlation import correlate
from sentinel.core.explainer import explain
from sentinel.sources.manager import collect_events
from sentinel.storage.database import save_events, save_findings

def analyze(limit: int | None = None, *, persist: bool = True):
    """Analyze system events, optionally persisting results locally."""
    config = load_config()
    events, source_status = collect_events(limit)
    findings = [explain(event, config["language"]) for event in events]
    findings = correlate(findings, int(config["correlation_window_seconds"]))

    if persist:
        stored_events = save_events(events) if events else 0
        stored_findings = save_findings(findings) if findings else 0
    else:
        stored_events = 0
        stored_findings = 0

    return findings, source_status, stored_events, stored_findings
