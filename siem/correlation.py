from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import Any, Optional

from siem.utils import LogEvent


class CorrelationRule:
    def __init__(self, rule_id: str, name: str, data: dict):
        self.id = rule_id
        self.name = name
        self.description = data.get("description", "")
        self.severity = data.get("severity", 5)
        self.time_window = data.get("time_window", 60)
        self.sequence: list[dict] = data.get("sequence", [])
        self.group_by = data.get("group_by", "src_ip")
        self.tags: list[str] = data.get("tags", [])

    def matches_sequence(self, events: list[LogEvent]) -> bool:
        if len(events) < len(self.sequence):
            return False
        idx = 0
        for event in events:
            if idx >= len(self.sequence):
                break
            step = self.sequence[idx]
            if self._matches_step(event, step):
                idx += 1
        return idx >= len(self.sequence)

    def _matches_step(self, event: LogEvent, step: dict) -> bool:
        for field, expected in step.items():
            if field == "event_type":
                if event.event_type != expected:
                    return False
            elif field == "service":
                if event.service != expected:
                    return False
            elif field == "status":
                if event.status != expected:
                    return False
            elif field == "src_ip":
                if event.src_ip != expected:
                    return False
            elif field == "level":
                if event.level != expected:
                    return False
            elif field == "user":
                if event.user != expected:
                    return False
            elif field in ("pattern", "regex"):
                import re
                if not re.search(expected, event.raw, re.IGNORECASE):
                    return False
        return True


class CorrelationEngine:
    def __init__(self):
        self.rules: dict[str, CorrelationRule] = {}
        self._windows: dict[str, list[tuple[datetime, LogEvent]]] = defaultdict(list)
        self._patterns: dict[str, list[tuple[datetime, LogEvent, str]]] = defaultdict(list)
        self._window_seconds = 300

    def add_rule(self, rule: CorrelationRule) -> None:
        self.rules[rule.id] = rule

    def ingest(self, event: LogEvent) -> Optional[dict]:
        now = event.timestamp or datetime.now(timezone.utc)
        cutoff = now - timedelta(seconds=self._window_seconds)
        group_key = event.src_ip or event.user or event.host or "global"

        window = self._windows[group_key]
        window.append((now, event))
        self._windows[group_key] = [(t, e) for t, e in window if t > cutoff]

        alerts: list[dict] = []
        for rule in self.rules.values():
            rule_cutoff = now - timedelta(seconds=rule.time_window)
            recent = [(t, e) for t, e in window if t > rule_cutoff]
            events = [e for _, e in recent]
            if rule.matches_sequence(events):
                key = f"{rule.id}:{group_key}"
                if key not in {p[2] for p in self._patterns.get(group_key, [])}:
                    self._patterns.setdefault(group_key, []).append((now, event, key))
                    alerts.append({
                        "rule_id": rule.id,
                        "rule_name": rule.name,
                        "description": rule.description,
                        "severity": rule.severity,
                        "group_key": group_key,
                        "events": [e.to_dict() for e in events[-5:]],
                        "event_count": len(events),
                        "tags": rule.tags,
                        "timestamp": now.isoformat(),
                    })

        self._patterns[group_key] = [(t, e, k) for t, e, k in self._patterns.get(group_key, [])
                                     if t > cutoff]

        if alerts:
            return {
                "type": "correlation_alert",
                "alerts": alerts,
            }
        return None

    def reset(self) -> None:
        self._windows.clear()
        self._patterns.clear()
