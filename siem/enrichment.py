import json
import os
import socket
import struct
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import requests

from siem.utils import LogEvent, classify_ip


THREAT_INTEL_SOURCES: list[dict] = [
    {"name": "alienvault", "url": "https://threatintel.cybercitizen.report/feeds/alienvault.json"},
    {"name": "abuseipdb", "url": "https://feeds.abuseipdb.com/threatintel"},
    {"name": "otx", "url": "https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"},
]


IP_REPUTATION_CACHE: dict[str, dict] = {}
_RISKY_COUNTRIES = {"RU", "CN", "KP", "IR", "SY", "VE"}


class ThreatIntelProvider:
    def __init__(self, cache_dir: str = ""):
        self.cache: dict[str, dict] = {}
        self.cache_dir = cache_dir
        self._known_bad_ips: set[str] = set()
        self._known_bad_domains: set[str] = set()
        self._known_bad_hashes: set[str] = set()
        self._lock = threading.Lock()
        self._load_local_feeds()

    def _load_local_feeds(self) -> None:
        if not self.cache_dir:
            return
        p = Path(self.cache_dir)
        if not p.is_dir():
            return
        for f in p.glob("*.json"):
            try:
                data = json.loads(f.read_text())
                for entry in data if isinstance(data, list) else data.get("indicators", []):
                    ioc = entry.get("indicator", "").lower().strip()
                    ioc_type = entry.get("type", "")
                    if ioc_type == "ip":
                        self._known_bad_ips.add(ioc)
                    elif ioc_type == "domain":
                        self._known_bad_domains.add(ioc)
                    elif ioc_type == "hash":
                        self._known_bad_hashes.add(ioc)
                    else:
                        self._known_bad_ips.add(ioc)
            except Exception:
                continue

    def add_iocs(self, iocs: list[dict]) -> None:
        with self._lock:
            for ioc in iocs:
                indicator = ioc.get("indicator", "").lower().strip()
                ioc_type = ioc.get("type", "ip")
                if ioc_type == "ip":
                    self._known_bad_ips.add(indicator)
                elif ioc_type == "domain":
                    self._known_bad_domains.add(indicator)
                elif ioc_type == "hash":
                    self._known_bad_hashes.add(indicator)

    def check_ip(self, ip: str) -> Optional[dict]:
        if not ip:
            return None
        ip_lower = ip.lower()

        if ip_lower in self._known_bad_ips:
            return {"source": "local_feed", "malicious": True, "confidence": "high"}

        cached = IP_REPUTATION_CACHE.get(ip_lower)
        if cached:
            return cached

        try:
            resp = requests.get(
                f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
                timeout=5,
                headers={"User-Agent": "SentinelSIEM/1.0"},
            )
            if resp.status_code == 200:
                data = resp.json()
                pulses = data.get("pulse_info", {}).get("pulses", [])
                if pulses:
                    result = {
                        "source": "otx",
                        "malicious": True,
                        "confidence": "medium",
                        "pulse_count": len(pulses),
                        "pulse_names": [p.get("name", "")[:80] for p in pulses[:5]],
                    }
                    IP_REPUTATION_CACHE[ip_lower] = result
                    return result
        except Exception:
            pass

        IP_REPUTATION_CACHE[ip_lower] = {"source": "unknown", "malicious": False}
        return None

    def check_hash(self, hash_str: str) -> bool:
        return hash_str.lower() in self._known_bad_hashes

    def is_malicious_ip(self, ip: str) -> bool:
        return ip.lower() in self._known_bad_ips


class GeoIPResolver:
    def __init__(self, db_path: str = ""):
        self._db = None
        self._available = False
        if db_path and Path(db_path).exists():
            try:
                import geoip2.database
                self._db = geoip2.database.Reader(db_path)
                self._available = True
            except Exception:
                pass
        self._cache: dict[str, dict] = {}

    def lookup(self, ip: str) -> dict:
        if not ip or ip in self._cache:
            return self._cache.get(ip, {})

        result: dict = {
            "country": "",
            "city": "",
            "asn": "",
            "isp": "",
            "latitude": 0.0,
            "longitude": 0.0,
            "is_risky": False,
        }

        if self._available and self._db:
            try:
                resp = self._db.city(ip)
                result["country"] = resp.country.name or ""
                result["city"] = resp.city.name or ""
                result["latitude"] = resp.location.latitude or 0.0
                result["longitude"] = resp.location.longitude or 0.0
                if resp.country.iso_code:
                    result["is_risky"] = resp.country.iso_code in _RISKY_COUNTRIES
            except Exception:
                pass
            try:
                asn_resp = self._db.asn(ip)
                result["asn"] = str(asn_resp.autonomous_system_number or "")
                result["isp"] = asn_resp.autonomous_system_organization or ""
            except Exception:
                pass
        else:
            result["classification"] = classify_ip(ip)
            if result["classification"] == "public":
                result["country"] = "External"
                result["is_risky"] = False

        self._cache[ip] = result
        return result


class LogEnricher:
    def __init__(self, threat_intel: Optional[ThreatIntelProvider] = None,
                 geoip: Optional[GeoIPResolver] = None):
        self.threat_intel = threat_intel or ThreatIntelProvider()
        self.geoip = geoip or GeoIPResolver()

    def enrich(self, event: LogEvent) -> LogEvent:
        if event.src_ip:
            geo = self.geoip.lookup(event.src_ip)
            if geo:
                event.extra["geo_country"] = geo.get("country", "")
                event.extra["geo_city"] = geo.get("city", "")
                event.extra["geo_lat"] = geo.get("latitude", 0.0)
                event.extra["geo_lon"] = geo.get("longitude", 0.0)
                event.extra["is_risky_geo"] = geo.get("is_risky", False)

            if geo.get("is_risky") or self.threat_intel.is_malicious_ip(event.src_ip):
                event.tags.append("threat_ip")

            threat = self.threat_intel.check_ip(event.src_ip)
            if threat and threat.get("malicious"):
                event.tags.append("malicious_ip")
                event.extra["threat_intel"] = threat
                event.severity = max(event.severity, 5)

        if event.dst_ip:
            geo = self.geoip.lookup(event.dst_ip)
            if geo:
                event.extra["geo_dst_country"] = geo.get("country", "")

        event.extra["ip_classification"] = classify_ip(event.src_ip) if event.src_ip else ""

        return event
