from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import Optional

from siem.utils import LogEvent, FrequencyTracker


class AnomalyDetector:
    def __init__(self):
        self.login_freq = FrequencyTracker()
        self.event_freq: dict[str, FrequencyTracker] = {}
        self.ip_event_count: dict[str, int] = defaultdict(int)
        self.ip_timestamps: dict[str, list[datetime]] = defaultdict(list)
        self.hourly_rates: dict[str, list[int]] = defaultdict(list)
        self._baseline_days = 7
        self._min_samples = 10

    def analyze(self, event: LogEvent) -> Optional[dict]:
        anomalies: list[str] = []
        severity = 0

        ip_anomaly = self._check_ip_velocity(event)
        if ip_anomaly:
            anomalies.append(ip_anomaly)
            severity = max(severity, 3)

        time_anomaly = self._check_time_pattern(event)
        if time_anomaly:
            anomalies.append(time_anomaly)
            severity = max(severity, 2)

        login_anomaly = self._check_login_anomaly(event)
        if login_anomaly:
            anomalies.append(login_anomaly)
            severity = max(severity, 4)

        if event.src_ip:
            self.ip_event_count[event.src_ip] += 1
            self.ip_timestamps[event.src_ip].append(event.timestamp or datetime.now(timezone.utc))

        if not anomalies:
            return None

        return {
            "type": "anomaly",
            "anomalies": anomalies,
            "severity": severity,
            "src_ip": event.src_ip,
            "user": event.user,
            "event_type": event.event_type,
        }

    def _check_ip_velocity(self, event: LogEvent) -> Optional[str]:
        if not event.src_ip:
            return None
        ip = event.src_ip
        now = event.timestamp or datetime.now(timezone.utc) + timedelta(seconds=1)
        hour_key = f"{ip}:{now.strftime('%Y-%m-%d-%H')}"

        if hour_key not in self.hourly_rates:
            self.hourly_rates[hour_key] = [0]

        rate_idx = len(self.hourly_rates[hour_key]) - 1
        self.hourly_rates[hour_key][rate_idx] += 1
        current_rate = self.hourly_rates[hour_key][rate_idx]

        if current_rate > 1000:
            return f"High velocity from IP {ip}: {current_rate} events this hour"
        if current_rate > 500:
            return f"Elevated velocity from IP {ip}: {current_rate} events this hour"

        cutoff = now - timedelta(minutes=5)
        recent = [t for t in self.ip_timestamps.get(ip, []) if t > cutoff]
        recent_count = len(recent)

        if recent_count > 50:
            return f"Spike detected from IP {ip}: {recent_count} events in 5 minutes"

        return None

    def _check_time_pattern(self, event: LogEvent) -> Optional[str]:
        now = event.timestamp or datetime.now(timezone.utc)
        hour = now.hour
        if 0 <= hour <= 5 and event.event_type in ("successful_login", "privilege_escalation", "service_install"):
            return f"Unusual activity at {hour:02d}:00 — off-hours {event.event_type}"

        if 0 <= hour <= 6 and event.event_type in ("process_creation", "admin_logon"):
            if event.src_ip and not classify_ip(event.src_ip) == "private":
                return f"Suspicious off-hours activity from {event.src_ip}"
        return None

    def _check_login_anomaly(self, event: LogEvent) -> Optional[str]:
        if event.event_type != "failed_login":
            return None
        if not event.src_ip:
            return None

        self.login_freq.record(event.src_ip)
        rate = self.login_freq.mean(event.src_ip)
        if rate > 10:
            return f"Brute-force pattern detected: {rate:.0f} failed logins from {event.src_ip}"
        return None

    def get_stats(self) -> dict:
        return {
            "tracked_ips": len(self.ip_event_count),
            "total_events_tracked": sum(self.ip_event_count.values()),
        }


def classify_ip(ip_str: str) -> str:
    try:
        import ipaddress
        ip = ipaddress.ip_address(ip_str.strip())
        if ip.is_private:
            return "private"
        if ip.is_loopback:
            return "loopback"
        return "public"
    except ValueError:
        return "unknown"
