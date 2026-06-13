# Sentinel SIEM

Advanced Security Information & Event Management engine for real-time log analysis, threat detection, and SOC monitoring.

## Features

- **Real-time log ingestion** — stdin, files, directories (with follow mode)
- **Multi-format parsing** — syslog, authlog, Apache combined, JSON, CSV, Windows Event Forwarding, firewall logs
- **YAML-based detection rules** — regex patterns, thresholds, sliding windows, MITRE ATT&CK mapping
- **Correlation engine** — cross-rule event correlation with multi-stage detection
- **Log enrichment** — GeoIP, threat intel lookups, DNS reverse lookups
- **Live SOC dashboard** — real-time terminal UI with alerts, MITRE tactics, incident tracking
- **MITRE ATT&CK integration** — 14 tactics, 190+ techniques, tactic-aware alerting
- **ML anomaly detection** — unsupervised isolation forest on event frequency and entropy
- **Export** — JSON, CSV, HTML reports
- **Incident management** — auto-incident creation from threshold-based alerts

## Requirements

- Python 3.10+
- pip dependencies (see `requirements.txt`)

## Installation

```bash
git clone <repo-url>
cd loganaylzer
pip install -r requirements.txt
```

## Usage

```bash
python -m siem --help
```

### Modes

| Command | Description |
|---------|-------------|
| `analyze` | Analyze logs and detect threats |
| `dashboard` | Interactive live SOC dashboard |
| `export` | Export findings to report |
| `mitre` | MITRE ATT&CK reference |
| `list-rules` | List all loaded detection rules |

### Analyze

```bash
# From stdin
tail -f /var/log/auth.log | python -m siem analyze -i -

# Single file
python -m siem analyze -i /var/log/syslog

# Directory
python -m siem analyze -i /var/log/ --pattern "*.log" --recursive

# Follow a file in real-time
python -m siem analyze -i /var/log/auth.log --follow

# Verbose output
python -m siem analyze -i auth.log -v
```

### Live Dashboard

```bash
tail -f /var/log/auth.log | python -m siem dashboard -i -
```

### Export Report

```bash
python -m siem export -i /var/log/auth.log -o report.html
python -m siem export -i /var/log/auth.log -o report.json
python -m siem export -i /var/log/auth.log -o report.csv
```

### MITRE Reference

```bash
python -m siem mitre                    # List all tactics
python -m siem mitre -t credential_access  # Show techniques for a tactic
```

### List Rules

```bash
python -m siem list-rules
```

## Detection Rules

Rules are YAML files in `siem/rules/`. Each rule defines:

```yaml
- id: SSH_BRUTE_FORCE
  name: SSH Brute Force Attack
  severity: 5              # 1-10
  category: credential_access
  mitre_id: T1110
  mitre_tactic: Credential Access
  condition: match          # match | any
  patterns:
    - field: raw
      regex: 'Failed password for.*from'
  threshold: 5              # alerts after N matches
  window: 300               # sliding window in seconds
  tags: [ssh, brute_force]
```

Built-in rule packs:
- `authentication.yaml` — SSH brute force, sudo escalation, auth bursts
- `web_attacks.yaml` — SQLi, XSS, path traversal, directory busting
- `network.yaml` — Port scanning, DNS tunneling, DDoS patterns
- `malware.yaml` — Known malware indicators, C2 patterns
- `defense_evasion.yaml` — Log clearing, process hiding, persistence

## Architecture

```
Log Source → LogIngestor → Parser → Enricher → RulesEngine → AlertManager → SOCDashboard
                                                    ↓
                                            CorrelationEngine
                                                    ↓
                                              IncidentManager
                                                    ↓
                                              ReportExporter
```

## License

MIT
