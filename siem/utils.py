import re
import json
import hashlib
import ipaddress
from datetime import datetime, timezone, timedelta
from typing import Any, Optional
from pathlib import Path
from urllib.parse import urlparse


TIMESTAMP_FORMATS = [
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S%z",
    "%b %d %H:%M:%S",
    "%b  %d %H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
    "%d/%b/%Y:%H:%M:%S %z",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%m/%d/%Y %H:%M:%S",
    "%d-%b-%Y %H:%M:%S",
    "%a, %d %b %Y %H:%M:%S %z",
    "%Y-%m-%d %H:%M:%S,%f",
    "%d/%b/%Y %H:%M:%S",
    "%b %d %H:%M:%S.%f",
]


class LogEvent:
    __slots__ = ("timestamp", "raw", "source", "host", "service", "pid",
                 "message", "level", "src_ip", "dst_ip", "src_port", "dst_port",
                 "user", "protocol", "method", "path", "status", "size",
                 "user_agent", "referer", "event_id", "event_type",
                 "tags", "severity", "normalized", "extra")

    def __init__(self, raw: str = "", source: str = "unknown", timestamp: Optional[datetime] = None):
        self.timestamp = timestamp or datetime.now(timezone.utc)
        self.raw = raw
        self.source = source
        self.host = ""
        self.service = ""
        self.pid = ""
        self.message = raw
        self.level = "INFO"
        self.src_ip = ""
        self.dst_ip = ""
        self.src_port = ""
        self.dst_port = ""
        self.user = ""
        self.protocol = ""
        self.method = ""
        self.path = ""
        self.status = 0
        self.size = 0
        self.user_agent = ""
        self.referer = ""
        self.event_id = ""
        self.event_type = ""
        self.tags: list[str] = []
        self.severity = 0
        self.normalized: dict[str, Any] = {}
        self.extra: dict[str, Any] = {}

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat() if self.timestamp else "",
            "source": self.source,
            "host": self.host,
            "service": self.service,
            "pid": self.pid,
            "message": self.message[:500],
            "level": self.level,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "user": self.user,
            "protocol": self.protocol,
            "method": self.method,
            "path": self.path,
            "status": self.status,
            "size": self.size,
            "user_agent": self.user_agent[:200] if self.user_agent else "",
            "referer": self.referer[:200] if self.referer else "",
            "event_id": self.event_id,
            "event_type": self.event_type,
            "tags": self.tags,
            "severity": self.severity,
            "extra": self.extra,
        }

    def fingerprint(self) -> str:
        raw = f"{self.timestamp}|{self.src_ip}|{self.event_type}|{self.message[:200]}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]


IP_PATTERNS = {
    "private": re.compile(r"^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.)"),
    "loopback": re.compile(r"^127\.|^::1$"),
    "link_local": re.compile(r"^169\.254\."),
}


def classify_ip(ip_str: str) -> str:
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        if ip.is_private:
            return "private"
        if ip.is_loopback:
            return "loopback"
        if ip.is_link_local:
            return "link_local"
        return "public"
    except ValueError:
        return "unknown"


IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def extract_ips(text: str) -> list[str]:
    return list(set(IP_RE.findall(text)))


EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")


def extract_emails(text: str) -> list[str]:
    return list(set(EMAIL_RE.findall(text)))


URL_RE = re.compile(r"https?://[^\s'\">,;]+")


def extract_urls(text: str) -> list[str]:
    return list(set(URL_RE.findall(text)))


HASH_RE = re.compile(r"\b([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{128})\b")


def extract_hashes(text: str) -> list[str]:
    return list(set(HASH_RE.findall(text.lower())))


def parse_timestamp(ts_str: str) -> Optional[datetime]:
    ts_str = ts_str.strip()
    for fmt in TIMESTAMP_FORMATS:
        try:
            dt = datetime.strptime(ts_str, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    return None


SEVERITY_MAP = {
    "EMERG": 7, "ALERT": 6, "CRIT": 5, "ERROR": 4, "WARN": 3,
    "NOTICE": 2, "INFO": 1, "DEBUG": 0,
}


def severity_from_str(s: str) -> int:
    return SEVERITY_MAP.get(s.upper(), 1)


SEVERITY_LABELS = {v: k for k, v in SEVERITY_MAP.items()}
SEVERITY_COLORS = {7: "red", 6: "red", 5: "red", 4: "yellow", 3: "yellow",
                   2: "blue", 1: "green", 0: "white"}


def severity_label(sev: int) -> str:
    if sev >= 7:
        return "EMERG"
    if sev >= 6:
        return "ALERT"
    if sev >= 5:
        return "CRITICAL"
    if sev >= 4:
        return "ERROR"
    if sev >= 3:
        return "WARNING"
    if sev >= 2:
        return "NOTICE"
    if sev >= 1:
        return "INFO"
    return "DEBUG"


def severity_color(sev: int) -> str:
    if sev >= 6:
        return "red"
    if sev >= 4:
        return "yellow"
    if sev >= 2:
        return "blue"
    return "green"


def format_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def format_duration(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes = seconds / 60
    if minutes < 60:
        return f"{int(minutes)}m {int(seconds % 60)}s"
    hours = minutes / 60
    return f"{int(hours)}h {int(minutes % 60)}m"


def load_json_file(path: str) -> Optional[list[dict]]:
    try:
        with open(path) as f:
            data = json.load(f)
            return data if isinstance(data, list) else [data]
    except Exception:
        return None


def safe_get(data: dict, *keys: str, default: Any = "") -> Any:
    for key in keys:
        if isinstance(data, dict):
            data = data.get(key, {})
        else:
            return default
    return data if data != {} else default


class RollingCounter:
    def __init__(self, window_seconds: int = 300):
        self.window = window_seconds
        self.buckets: dict[str, list[float]] = {}

    def increment(self, key: str) -> int:
        now = datetime.now(timezone.utc).timestamp()
        cutoff = now - self.window
        if key not in self.buckets:
            self.buckets[key] = []
        self.buckets[key] = [t for t in self.buckets[key] if t > cutoff]
        self.buckets[key].append(now)
        return len(self.buckets[key])

    def count(self, key: str) -> int:
        if key not in self.buckets:
            return 0
        cutoff = datetime.now(timezone.utc).timestamp() - self.window
        self.buckets[key] = [t for t in self.buckets[key] if t > cutoff]
        return len(self.buckets[key])

    def reset(self, key: str) -> None:
        self.buckets.pop(key, None)


class FrequencyTracker:
    def __init__(self, max_samples: int = 1000):
        self.samples: dict[str, list[float]] = {}
        self.max_samples = max_samples

    def record(self, key: str, value: float = 1.0) -> None:
        if key not in self.samples:
            self.samples[key] = []
        self.samples[key].append(value)
        if len(self.samples[key]) > self.max_samples:
            self.samples[key] = self.samples[key][-self.max_samples:]

    def mean(self, key: str) -> float:
        vals = self.samples.get(key, [])
        return sum(vals) / len(vals) if vals else 0.0

    def std(self, key: str) -> float:
        vals = self.samples.get(key, [])
        if len(vals) < 2:
            return 0.0
        m = sum(vals) / len(vals)
        variance = sum((x - m) ** 2 for x in vals) / (len(vals) - 1)
        return variance ** 0.5

    def is_anomalous(self, key: str, value: float, threshold: float = 3.0) -> bool:
        m = self.mean(key)
        s = self.std(key)
        if s == 0:
            return False
        zscore = abs(value - m) / s
        return zscore > threshold
