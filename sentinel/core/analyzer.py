"""Compatibility wrapper for the original analyzer API."""
from sentinel.core.explainer import explain

def classify(event):
    finding = explain(event)
    return finding.severity, finding.why_it_matters
