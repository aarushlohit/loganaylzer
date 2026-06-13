import json
import time
import hashlib
import threading
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import Any, Optional, Callable

from siem.utils import LogEvent, severity_label, severity_color


class Alert:
    def __init__(self, rule_id: str, rule_name: str, description: str,
                 severity: int, category: str, event: dict,
                 mitre_id: str = "", mitre_tactic: str = "",
                 mitre_technique: str = "", tags: Optional[list[str]] = None):
        self.id = hashlib.md5(f"{rule_id}:{event.get('timestamp', '')}:{event.get('src_ip', '')}:{time.time()}".encode()).hexdigest()[:12]
        self.rule_id = rule_id
        self.rule_name = rule_name
        self.description = description
        self.severity = severity
        self.category = category
        self.event = event
        self.mitre_id = mitre_id
        self.mitre_tactic = mitre_tactic
        self.mitre_technique = mitre_technique
        self.tags = tags or []
        self.timestamp = datetime.now(timezone.utc)
        self.status = "open"
        self.assigned_to = ""
        self.notes: list[str] = []
        self.escalated = False

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "description": self.description,
            "severity": self.severity,
            "severity_label": severity_label(self.severity),
            "category": self.category,
            "mitre_id": self.mitre_id,
            "mitre_tactic": self.mitre_tactic,
            "mitre_technique": self.mitre_technique,
            "tags": self.tags,
            "timestamp": self.timestamp.isoformat(),
            "status": self.status,
            "assigned_to": self.assigned_to,
            "escalated": self.escalated,
            "notes": self.notes,
            "event_src_ip": self.event.get("src_ip", ""),
            "event_user": self.event.get("user", ""),
            "event_message": self.event.get("message", "")[:200],
        }

    def __lt__(self, other: "Alert") -> bool:
        return self.severity > other.severity

    def __hash__(self) -> int:
        return hash(self.id)


class AlertManager:
    def __init__(self):
        self.alerts: dict[str, Alert] = {}
        self._lock = threading.Lock()
        self._callbacks: list[Callable[[Alert], None]] = []
        self.stats: dict[str, int] = defaultdict(int)
        self.total_alerts = 0

    def on_alert(self, callback: Callable[[Alert], None]) -> None:
        self._callbacks.append(callback)

    def create_alert(self, finding: dict) -> Alert:
        event_data = finding.get("event", {})
        alert = Alert(
            rule_id=finding.get("rule_id", "unknown"),
            rule_name=finding.get("rule_name", "Unknown Rule"),
            description=finding.get("description", ""),
            severity=finding.get("severity", 3),
            category=finding.get("category", "generic"),
            event=event_data,
            mitre_id=finding.get("mitre_id", ""),
            mitre_tactic=finding.get("mitre_tactic", ""),
            mitre_technique=finding.get("mitre_technique", ""),
            tags=finding.get("tags", []),
        )

        with self._lock:
            dedup_key = f"{alert.rule_id}:{event_data.get('src_ip', '')}:{event_data.get('user', '')}"
            if dedup_key in self.stats:
                self.stats[dedup_key] += 1
                if self.stats[dedup_key] > 100:
                    return alert
            else:
                self.stats[dedup_key] = 1

            self.alerts[alert.id] = alert
            self.total_alerts += 1

        for cb in self._callbacks:
            try:
                cb(alert)
            except Exception:
                pass

        return alert

    def get_alert(self, alert_id: str) -> Optional[Alert]:
        return self.alerts.get(alert_id)

    def update_status(self, alert_id: str, status: str, user: str = "") -> bool:
        with self._lock:
            alert = self.alerts.get(alert_id)
            if not alert:
                return False
            alert.status = status
            if user:
                alert.assigned_to = user
            return True

    def add_note(self, alert_id: str, note: str) -> bool:
        with self._lock:
            alert = self.alerts.get(alert_id)
            if not alert:
                return False
            alert.notes.append(f"[{datetime.now(timezone.utc).strftime('%H:%M:%S')}] {note}")
            return True

    def escalate(self, alert_id: str) -> bool:
        with self._lock:
            alert = self.alerts.get(alert_id)
            if not alert:
                return False
            alert.escalated = True
            alert.severity = min(alert.severity + 1, 7)
            return True

    def get_open_alerts(self) -> list[Alert]:
        return sorted(
            [a for a in self.alerts.values() if a.status == "open"],
            reverse=True,
        )

    def get_alerts_by_severity(self, min_severity: int = 3) -> list[Alert]:
        return sorted(
            [a for a in self.alerts.values() if a.severity >= min_severity],
            reverse=True,
        )

    def get_recent_alerts(self, minutes: int = 60) -> list[Alert]:
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes)
        return sorted(
            [a for a in self.alerts.values() if a.timestamp > cutoff],
            reverse=True,
        )

    def get_stats(self) -> dict:
        with self._lock:
            open_count = sum(1 for a in self.alerts.values() if a.status == "open")
            critical = sum(1 for a in self.alerts.values() if a.severity >= 6 and a.status == "open")
            high = sum(1 for a in self.alerts.values() if 4 <= a.severity < 6 and a.status == "open")
            medium = sum(1 for a in self.alerts.values() if 2 <= a.severity < 4 and a.status == "open")
            low = sum(1 for a in self.alerts.values() if a.severity < 2 and a.status == "open")

        return {
            "total": self.total_alerts,
            "open": open_count,
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
        }

    def export_json(self, path: str) -> None:
        with open(path, "w") as f:
            json.dump(
                [a.to_dict() for a in sorted(self.alerts.values(), reverse=True)],
                f, indent=2,
            )
