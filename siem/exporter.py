import json
import csv
import io
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from siem.alerting import AlertManager, Alert
from siem.incident import IncidentManager


class ReportExporter:
    def __init__(self, alert_manager: AlertManager,
                 incident_manager: Optional[IncidentManager] = None):
        self.alerts = alert_manager
        self.incidents = incident_manager

    def export_alerts_json(self, path: str, min_severity: int = 0) -> None:
        alerts = [a.to_dict() for a in self.alerts.alerts.values()
                  if a.severity >= min_severity]
        self._write_json(path, sorted(alerts, key=lambda x: x["severity"], reverse=True))

    def export_alerts_csv(self, path: str, min_severity: int = 0) -> None:
        alerts = [a for a in self.alerts.alerts.values() if a.severity >= min_severity]
        if not alerts:
            Path(path).write_text("")
            return
        fieldnames = [
            "id", "timestamp", "severity_label", "rule_name", "description",
            "category", "mitre_id", "mitre_tactic", "status", "assigned_to",
            "event_src_ip", "event_user",
        ]
        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for a in sorted(alerts, reverse=True):
                row = a.to_dict()
                writer.writerow({k: row.get(k, "") for k in fieldnames})

    def export_html_report(self, path: str, title: str = "Sentinel SIEM Report") -> None:
        alerts = sorted(self.alerts.get_open_alerts(), reverse=True)[:100]
        total_events = self.alerts.total_alerts

        rows = "".join(
            f"""<tr>
                <td>{a.timestamp.strftime('%Y-%m-%d %H:%M:%S')}</td>
                <td><span class="severity severity-{a.severity}">{severity_label(a.severity)}</span></td>
                <td>{a.rule_name}</td>
                <td>{a.description[:100]}</td>
                <td>{a.category}</td>
                <td>{a.event.get('src_ip', '')}</td>
                <td>{a.event.get('user', '')}</td>
                <td class="status-{a.status}">{a.status}</td>
            </tr>"""
            for a in alerts
        )

        stats = self.alerts.get_stats()
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{title}</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
       background: #0a0a0f; color: #e0e0e0; padding: 2rem; }}
h1 {{ color: #00d4aa; font-size: 2rem; margin-bottom: 0.5rem; }}
.subtitle {{ color: #888; margin-bottom: 2rem; }}
.stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
          gap: 1rem; margin-bottom: 2rem; }}
.stat-card {{ background: #141420; border: 1px solid #2a2a3a; border-radius: 8px;
             padding: 1.2rem; text-align: center; }}
.stat-value {{ font-size: 2rem; font-weight: bold; color: #00d4aa; }}
.stat-label {{ color: #888; font-size: 0.85rem; margin-top: 0.3rem; }}
.critical .stat-value {{ color: #ff4444; }}
.high .stat-value {{ color: #ff8800; }}
.medium .stat-value {{ color: #ffcc00; }}
table {{ width: 100%; border-collapse: collapse; background: #141420;
        border-radius: 8px; overflow: hidden; }}
th {{ background: #1a1a2e; padding: 0.8rem 1rem; text-align: left;
     font-weight: 600; color: #00d4aa; font-size: 0.85rem; text-transform: uppercase; }}
td {{ padding: 0.8rem 1rem; border-bottom: 1px solid #2a2a3a; font-size: 0.9rem; }}
tr:hover {{ background: #1a1a2e; }}
.severity {{ padding: 2px 8px; border-radius: 4px; font-size: 0.8rem; font-weight: bold; }}
.severity-6, .severity-7 {{ background: #ff444422; color: #ff4444; }}
.severity-4, .severity-5 {{ background: #ff880022; color: #ff8800; }}
.severity-2, .severity-3 {{ background: #ffcc0022; color: #ffcc00; }}
.severity-0, .severity-1 {{ background: #00d4aa22; color: #00d4aa; }}
.status-open {{ color: #ff4444; }}
.status-closed {{ color: #00d4aa; }}
.footer {{ margin-top: 2rem; color: #555; font-size: 0.8rem; text-align: center; }}
</style>
</head>
<body>
<h1>{title}</h1>
<p class="subtitle">Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} | Total Events: {total_events}</p>
<div class="stats">
  <div class="stat-card critical"><div class="stat-value">{stats['critical']}</div><div class="stat-label">Critical</div></div>
  <div class="stat-card high"><div class="stat-value">{stats['high']}</div><div class="stat-label">High</div></div>
  <div class="stat-card medium"><div class="stat-value">{stats['medium']}</div><div class="stat-label">Medium</div></div>
  <div class="stat-card"><div class="stat-value">{stats['open']}</div><div class="stat-label">Open Alerts</div></div>
</div>
<table>
<thead><tr>
  <th>Timestamp</th><th>Severity</th><th>Rule</th><th>Description</th>
  <th>Category</th><th>Source IP</th><th>User</th><th>Status</th>
</tr></thead>
<tbody>{rows or '<tr><td colspan="8" style="text-align:center;color:#555;">No alerts found</td></tr>'}</tbody>
</table>
<div class="footer">Sentinel SIEM — Advanced Security Information & Event Management</div>
</body>
</html>"""
        Path(path).write_text(html)

    def _write_json(self, path: str, data: Any) -> None:
        with open(path, "w") as f:
            json.dump(data, f, indent=2, default=str)


def severity_label(sev: int) -> str:
    if sev >= 6:
        return "CRITICAL"
    if sev >= 4:
        return "HIGH"
    if sev >= 2:
        return "MEDIUM"
    return "LOW"
