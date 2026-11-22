"""JSON and HTML report export with HTML escaping for untrusted log text."""
from __future__ import annotations
import html
import json
from datetime import datetime
from pathlib import Path
from sentinel.system.distro import system_info
from sentinel.system.health import snapshot

def report_data(findings):
    return {
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "system": system_info(), "health": snapshot(),
        "findings": [item.to_dict() for item in findings],
        "disclaimer": "Heuristic local analysis; findings are not proof of compromise.",
    }

def export_json(findings, destination: Path) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report_data(findings), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return destination

def export_html(findings, destination: Path) -> Path:
    data = report_data(findings)
    cards = []
    for item in data["findings"]:
        event = item["event"]
        fields = [item["title"], item["severity"].upper(), item["category"], event["timestamp"], item["summary"], item["why_it_matters"], item["recommendation"], event["message"]]
        title, severity, category, timestamp, summary, why, action, raw = map(html.escape, fields)
        cards.append(f"<article><h2>{title}</h2><p><b>{severity}</b> · {category} · {timestamp}</p><p>{summary}</p><p><b>Why it matters:</b> {why}</p><p><b>Suggested next step:</b> {action}</p><details><summary>Original log</summary><pre>{raw}</pre></details></article>")
    page = """<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sentinel report</title><style>body{font:16px system-ui;max-width:960px;margin:2rem auto;padding:0 1rem;background:#10151d;color:#e8edf4}article{border:1px solid #394454;border-radius:10px;padding:1rem;margin:1rem 0}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#080b10;padding:1rem}small{color:#aab5c4}</style><h1>Sentinel report</h1><small>Generated: """ + html.escape(data["generated_at"]) + "</small><p>Heuristic local analysis; findings are not proof of compromise.</p>" + "\n".join(cards) + "</html>"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(page, encoding="utf-8")
    return destination
