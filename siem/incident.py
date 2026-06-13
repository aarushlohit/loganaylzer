import json
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Any, Optional, Callable
from collections import defaultdict

from siem.utils import severity_label
from siem.alerting import Alert


class Incident:
    def __init__(self, title: str, severity: int, alert: Optional[Alert] = None):
        ts = datetime.now(timezone.utc)
        self.id = hashlib.md5(f"{title}:{ts.isoformat()}".encode()).hexdigest()[:12]
        self.title = title
        self.severity = severity
        self.timestamp = ts
        self.status = "open"
        self.assigned_to = ""
        self.alerts: list[Alert] = [alert] if alert else []
        self.timeline: list[dict] = []
        self.notes: list[str] = []
        self.tags: set[str] = set()
        self.mitre_tactics: set[str] = set()
        self.artifacts: dict[str, list[str]] = defaultdict(list)
        self.escalated = False
        self.resolution = ""
        self.closed_at: Optional[datetime] = None

        self.add_timeline_entry("incident_created", f"Incident created: {title}")

    def add_alert(self, alert: Alert) -> None:
        self.alerts.append(alert)
        self.tags.update(alert.tags)
        self.severity = max(self.severity, alert.severity)
        if alert.mitre_tactic:
            self.mitre_tactics.add(alert.mitre_tactic)
        if alert.event.get("src_ip"):
            self.artifacts["src_ips"].append(alert.event["src_ip"])
        if alert.event.get("user"):
            self.artifacts["users"].append(alert.event["user"])
        if alert.event.get("path"):
            self.artifacts["paths"].append(alert.event["path"])
        self.add_timeline_entry("alert_added", f"Alert added: {alert.rule_name} ({alert.id})")

    def add_timeline_entry(self, event_type: str, description: str) -> None:
        self.timeline.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "type": event_type,
            "description": description,
        })

    def add_note(self, note: str) -> None:
        ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
        self.notes.append(f"[{ts}] {note}")
        self.add_timeline_entry("note_added", note)

    def assign(self, user: str) -> None:
        self.assigned_to = user
        self.add_timeline_entry("assigned", f"Assigned to {user}")

    def close(self, resolution: str = "") -> None:
        self.status = "closed"
        self.resolution = resolution
        self.closed_at = datetime.now(timezone.utc)
        self.add_timeline_entry("closed", f"Incident closed: {resolution}")

    def escalate(self) -> None:
        self.escalated = True
        self.severity = min(self.severity + 1, 7)
        self.add_timeline_entry("escalated", "Incident escalated")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "severity_label": severity_label(self.severity),
            "timestamp": self.timestamp.isoformat(),
            "status": self.status,
            "assigned_to": self.assigned_to,
            "alert_count": len(self.alerts),
            "mitre_tactics": list(self.mitre_tactics),
            "tags": list(self.tags),
            "artifacts": dict(self.artifacts),
            "escalated": self.escalated,
            "resolution": self.resolution,
            "closed_at": self.closed_at.isoformat() if self.closed_at else "",
        }

    def summary(self) -> str:
        return (
            f"[{self.id}] {self.title} | Severity: {severity_label(self.severity)} | "
            f"Status: {self.status} | Alerts: {len(self.alerts)} | "
            f"Assigned: {self.assigned_to or 'Unassigned'}"
        )


class IncidentManager:
    def __init__(self):
        self.incidents: dict[str, Incident] = {}
        self._callbacks: list[Callable[[Incident], None]] = []

    def on_incident(self, callback: Callable[[Incident], None]) -> None:
        self._callbacks.append(callback)

    def create_incident(self, title: str, severity: int,
                        alert: Optional[Alert] = None) -> Incident:
        incident = Incident(title, severity, alert)
        self.incidents[incident.id] = incident
        for cb in self._callbacks:
            try:
                cb(incident)
            except Exception:
                pass
        return incident

    def add_alert_to_incident(self, incident_id: str, alert: Alert) -> bool:
        inc = self.incidents.get(incident_id)
        if not inc:
            return False
        inc.add_alert(alert)
        return True

    def get_incident(self, incident_id: str) -> Optional[Incident]:
        return self.incidents.get(incident_id)

    def get_open_incidents(self) -> list[Incident]:
        return sorted(
            [i for i in self.incidents.values() if i.status == "open"],
            key=lambda i: i.severity, reverse=True,
        )

    def find_merge_candidates(self, alert: Alert) -> Optional[str]:
        for inc in self.incidents.values():
            if inc.status != "open":
                continue
            for existing in inc.alerts:
                if existing.src_ip == alert.event.get("src_ip", "") and existing.src_ip:
                    return inc.id
                if existing.user == alert.event.get("user", "") and existing.user:
                    return inc.id
        return None

    def get_stats(self) -> dict:
        open_count = sum(1 for i in self.incidents.values() if i.status == "open")
        return {
            "total": len(self.incidents),
            "open": open_count,
            "critical": sum(1 for i in self.incidents.values()
                          if i.severity >= 6 and i.status == "open"),
            "high": sum(1 for i in self.incidents.values()
                      if 4 <= i.severity < 6 and i.status == "open"),
        }

    def export_json(self, path: str) -> None:
        with open(path, "w") as f:
            json.dump(
                [i.to_dict() for i in sorted(self.incidents.values(),
                                              key=lambda x: x.severity, reverse=True)],
                f, indent=2,
            )
