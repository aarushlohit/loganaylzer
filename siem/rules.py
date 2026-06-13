import os
import re
import yaml
from pathlib import Path
from typing import Any, Optional

from siem.utils import LogEvent, RollingCounter


class DetectionRule:
    def __init__(self, rule_id: str, name: str, data: dict):
        self.id = rule_id
        self.name = name
        self.description = data.get("description", "")
        self.severity = data.get("severity", 3)
        self.category = data.get("category", "generic")
        self.mitre_id = data.get("mitre_id", "")
        self.mitre_tactic = data.get("mitre_tactic", "")
        self.mitre_technique = data.get("mitre_technique", "")
        self.condition = data.get("condition", "match")
        self.fields: dict = data.get("fields", {})
        self.patterns: list[dict] = data.get("patterns", [])
        self.threshold = data.get("threshold", 0)
        self.window = data.get("window", 300)
        self.expression: Optional[str] = data.get("expression")
        self.actions: list[str] = data.get("actions", ["alert"])
        self.tags: list[str] = data.get("tags", [])
        self.override_expression: Optional[str] = data.get("override_expression")
        self._compiled_patterns: list[re.Pattern] = []
        self._counters: RollingCounter | None = None
        if self.threshold > 0 or self.expression:
            self._counters = RollingCounter(window_seconds=self.window)

        for p in self.patterns:
            try:
                self._compiled_patterns.append(re.compile(p.get("regex", ""), re.IGNORECASE))
            except re.error:
                pass

        if data.get("compiled_pattern", ""):
            try:
                self._compiled_patterns.append(re.compile(data["compiled_pattern"], re.IGNORECASE))
            except re.error:
                pass

    def _get_field_value(self, event: LogEvent, field_name: str) -> str:
        if "." in field_name:
            parts = field_name.split(".")
            obj = event
            for p in parts:
                if isinstance(obj, dict):
                    obj = obj.get(p, "")
                else:
                    obj = getattr(obj, p, "")
                    if obj is None:
                        obj = event.extra.get(field_name, "")
            return str(obj)
        val = getattr(event, field_name, None)
        if val is None:
            val = event.extra.get(field_name, "")
        return str(val)

    def match(self, event: LogEvent) -> Optional[dict]:
        if self._compiled_patterns and self.condition in ("match", "any", "all"):
            results = []
            for i, p in enumerate(self._compiled_patterns):
                target = event.raw
                if i < len(self.patterns) and self.patterns[i].get("field", "raw") != "raw":
                    fname = self.patterns[i].get("field", "raw")
                    target = self._get_field_value(event, fname)
                results.append(bool(p.search(target)))
            if self.condition == "match" and not all(results):
                return None
            if self.condition == "any" and not any(results):
                return None
            if self.condition == "all" and not all(results):
                return None

        for field, expected in self.fields.items():
            val = getattr(event, field, None)
            if val is None:
                val = event.extra.get(field, "")
            if isinstance(expected, (int, float)):
                if val != expected:
                    return None
            elif isinstance(val, str):
                if val.lower() != expected.lower():
                    return None

        if self.override_expression:
            try:
                result = self._eval_expression(self.override_expression, event)
                if not result:
                    return None
            except Exception:
                return None

        if self.expression:
            try:
                result = self._eval_expression(self.expression, event)
                if not result:
                    return None
            except Exception:
                return None

        if self.threshold > 0 and self._counters:
            key = f"{self.id}:{event.src_ip}"
            count = self._counters.increment(key)
            if count < self.threshold:
                return None

        finding: dict[str, Any] = {
            "rule_id": self.id,
            "rule_name": self.name,
            "description": self.description,
            "severity": self.severity,
            "category": self.category,
            "mitre_id": self.mitre_id,
            "mitre_tactic": self.mitre_tactic,
            "mitre_technique": self.mitre_technique,
            "tags": self.tags,
            "event": event.to_dict(),
            "timestamp": event.timestamp.isoformat() if event.timestamp else "",
        }
        return finding

    def _eval_expression(self, expr: str, event: LogEvent) -> bool:
        event_dict = event.to_dict()
        safe_globals = {"__builtins__": {}}
        safe_locals = {
            "e": event_dict,
            "event": event_dict,
            "raw": event.raw,
            "msg": event.message,
            "src_ip": event.src_ip,
            "dst_ip": event.dst_ip,
            "user": event.user,
            "status": event.status,
            "path": event.path,
            "service": event.service,
            "level": event.level,
            "count": lambda key: self._counters.count(f"{self.id}:{key}") if self._counters else 0,
            "re_search": lambda p, s: bool(re.search(p, s, re.IGNORECASE)),
            "re_match": lambda p, s: bool(re.match(p, s, re.IGNORECASE)),
        }
        try:
            return bool(eval(expr, safe_globals, safe_locals))
        except Exception:
            return False


class RulesEngine:
    def __init__(self):
        self.rules: dict[str, DetectionRule] = {}
        self._rule_counter = 0

    def load_yaml(self, path: str) -> int:
        p = Path(path)
        if not p.exists():
            return 0
        with open(p) as f:
            data = yaml.safe_load(f)
        if not data:
            return 0
        rules_list = data if isinstance(data, list) else data.get("rules", [data])
        count = 0
        for rule_data in rules_list:
            if not isinstance(rule_data, dict):
                continue
            rule_id = rule_data.get("id", f"rule_{self._rule_counter}")
            name = rule_data.get("name", rule_id)
            if rule_id in self.rules:
                rule_id = f"{rule_id}_{self._rule_counter}"
            self.rules[rule_id] = DetectionRule(rule_id, name, rule_data)
            self._rule_counter += 1
            count += 1
        return count

    def load_yaml_directory(self, directory: str) -> int:
        p = Path(directory)
        if not p.is_dir():
            return 0
        total = 0
        for yaml_file in sorted(p.glob("*.yaml")) + sorted(p.glob("*.yml")):
            total += self.load_yaml(str(yaml_file))
        return total

    def add_rule(self, rule_id: str, name: str, data: dict) -> None:
        self.rules[rule_id] = DetectionRule(rule_id, name, data)

    def evaluate(self, event: LogEvent) -> list[dict]:
        findings: list[dict] = []
        for rule in self.rules.values():
            try:
                result = rule.match(event)
                if result:
                    findings.append(result)
            except Exception:
                continue
        return findings

    def stats(self) -> dict:
        return {
            "total_rules": len(self.rules),
            "by_severity": {
                "critical": sum(1 for r in self.rules.values() if r.severity >= 6),
                "high": sum(1 for r in self.rules.values() if 4 <= r.severity < 6),
                "medium": sum(1 for r in self.rules.values() if 2 <= r.severity < 4),
                "low": sum(1 for r in self.rules.values() if r.severity < 2),
            },
        }
