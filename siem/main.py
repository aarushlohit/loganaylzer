import argparse
import sys
import os
import signal
import json
from datetime import datetime, timezone
from threading import Event
from typing import Optional

from siem.utils import LogEvent
from siem.ingestion import LogIngestor
from siem.parser import parse_log
from siem.rules import RulesEngine
from siem.correlation import CorrelationEngine
from siem.enrichment import LogEnricher
from siem.alerting import AlertManager
from siem.incident import IncidentManager
from siem.dashboard import SOCDashboard, print_finding, print_finding_verbose
from siem.mitre import MITRE_ATTACK
from siem.exporter import ReportExporter

DEFAULT_RULES_DIR = os.path.join(os.path.dirname(__file__), "rules")


def load_rules(rules_dir: str) -> RulesEngine:
    engine = RulesEngine()
    if not os.path.isdir(rules_dir):
        print(f"[!] Rules directory not found: {rules_dir}", file=sys.stderr)
        return engine

    count = engine.load_yaml_directory(rules_dir)
    print(f"  [*] Loaded {count} rules total")
    return engine


def make_on_log(rules_engine: RulesEngine, enricher: LogEnricher,
                alert_mgr: AlertManager, dashboard: Optional['SOCDashboard'] = None,
                verbose: bool = False):
    def on_log(event: LogEvent) -> None:
        event = parse_log(event)
        if not event or not event.raw:
            return
        enricher.enrich(event)
        findings = rules_engine.evaluate(event)
        for finding in findings:
            alert_mgr.create_alert(finding)
            if dashboard:
                dashboard.mitre_tactics_triggered.add(finding.get("mitre_tactic", ""))
            if verbose:
                print_finding_verbose(finding)
            else:
                print_finding(finding)
    return on_log


def setup_ingestor(args: argparse.Namespace, on_log) -> LogIngestor:
    ingestor = LogIngestor()
    ingestor.on_log(on_log)
    if args.input == "-" or not args.input:
        ingestor.ingest_stdin()
    elif os.path.isfile(args.input):
        ingestor.ingest_file(args.input, follow=args.follow)
    elif os.path.isdir(args.input):
        ingestor.ingest_directory(args.input, pattern=args.pattern, recursive=args.recursive)
    else:
        print(f"[!] Not found: {args.input}", file=sys.stderr)
        sys.exit(1)
    return ingestor


def analyze_mode(args: argparse.Namespace) -> None:
    print("[bold #00d4aa]Sentinel SIEM - Analyze Mode[/]")
    print()

    rules_engine = load_rules(args.rules_dir)
    if not rules_engine.rules:
        print("[!] No rules loaded. Exiting.", file=sys.stderr)
        sys.exit(1)

    enricher = LogEnricher()
    alert_mgr = AlertManager()
    incident_mgr = IncidentManager()
    dashboard = SOCDashboard(alert_mgr, incident_mgr)

    on_log = make_on_log(rules_engine, enricher, alert_mgr, dashboard, verbose=args.verbose)
    ingestor = setup_ingestor(args, on_log)

    def handler(signum, frame):
        ingestor.stop()
    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGTERM, handler)

    ingestor.start()
    ingestor.wait()
    print(f"\n[+] Total events ingested: {ingestor.total_ingested}")
    print(f"[+] Total alerts: {len(alert_mgr.alerts)}")


def dashboard_mode(args: argparse.Namespace) -> None:
    rules_engine = load_rules(args.rules_dir)
    enricher = LogEnricher()
    alert_mgr = AlertManager()
    incident_mgr = IncidentManager()
    dashboard = SOCDashboard(alert_mgr, incident_mgr)

    on_log = make_on_log(rules_engine, enricher, alert_mgr, dashboard)
    ingestor = setup_ingestor(args, on_log)

    def handler(signum, frame):
        ingestor.stop()
    signal.signal(signal.SIGINT, handler)

    dashboard.start_live(refresh_interval=1.0)
    ingestor.start()
    ingestor.wait()
    dashboard.stop()


def mitre_mode(args: argparse.Namespace) -> None:
    from rich.console import Console
    from rich.table import Table
    from rich import box

    console = Console()

    if args.tactic:
        tactic_name = args.tactic.lower()
        tactic_data = MITRE_ATTACK.get(tactic_name)
        if not tactic_data:
            console.print(f"[red]Tactic '{args.tactic}' not found.[/]")
            return
        table = Table(title=f"[bold #00d4aa]MITRE ATT&CK - {tactic_data['name']}[/]",
                       box=box.ROUNDED)
        table.add_column("Technique ID", style="cyan", width=18)
        table.add_column("Technique Name", width=50)

        for tid, tname in tactic_data["techniques"].items():
            table.add_row(tid, tname)
        console.print(table)
    else:
        table = Table(title="[bold #00d4aa]MITRE ATT&CK Tactics[/]", box=box.ROUNDED)
        table.add_column("Tactic", style="cyan", width=30)
        table.add_column("Techniques", justify="right", width=12)

        for tactic_name, tactic_data in sorted(MITRE_ATTACK.items()):
            count = len(tactic_data["techniques"])
            table.add_row(tactic_data["name"], str(count))
        console.print(table)


def export_mode(args: argparse.Namespace) -> None:
    rules_engine = load_rules(args.rules_dir)
    enricher = LogEnricher()
    alert_mgr = AlertManager()

    alert_ids = set()

    def on_log(event: LogEvent) -> None:
        event = parse_log(event)
        if not event or not event.raw:
            return
        enricher.enrich(event)
        findings = rules_engine.evaluate(event)
        for f in findings:
            alert_mgr.create_alert(f)

    ingestor = LogIngestor()
    ingestor.on_log(on_log)
    if args.input and os.path.isfile(args.input):
        ingestor.ingest_file(args.input, follow=False)
    else:
        print("[!] Specify an input file with --input", file=sys.stderr)
        sys.exit(1)

    ingestor.start()
    ingestor.wait()

    exporter = ReportExporter()
    output = args.output or "sentinel_report"
    _, ext = os.path.splitext(output)
    fmt = "html" if ext == ".html" else "csv" if ext == ".csv" else "json"

    exporter.export(alert_mgr.get_open_alerts(), output_path=output, fmt=fmt)
    print(f"[+] Report exported to {output}")


def list_rules_mode(args: argparse.Namespace) -> None:
    from rich.console import Console
    from rich.table import Table
    from rich import box
    from siem.utils import severity_label, severity_color

    console = Console()
    rules_engine = load_rules(args.rules_dir)

    if not rules_engine.rules:
        print("[!] No rules loaded.", file=sys.stderr)
        return

    table = Table(box=box.ROUNDED, header_style="bold #00d4aa")
    table.add_column("Rule ID", width=24, style="cyan")
    table.add_column("Name", width=30)
    table.add_column("Severity", width=10)
    table.add_column("Category", width=20)
    table.add_column("MITRE ID", width=14)

    for rule_id, rule in sorted(rules_engine.rules.items()):
        sev = severity_label(rule.severity)
        sev_c = severity_color(rule.severity)
        table.add_row(
            rule.id if hasattr(rule, 'id') else rule_id,
            rule.name[:30],
            f"[{sev_c}]{sev}[/]",
            rule.category,
            rule.mitre_id or "-",
        )
    console.print(table)


def _add_common_args(subparser) -> None:
    subparser.add_argument("--rules-dir", default=DEFAULT_RULES_DIR,
                           help=f"Detection rules directory (default: {DEFAULT_RULES_DIR})")
    subparser.add_argument("--input", "-i", help="Input source (file, directory, or - for stdin)")
    subparser.add_argument("--follow", "-f", action="store_true",
                           help="Follow file for new lines")
    subparser.add_argument("--pattern", "-P", default="*.log",
                           help="File pattern for directory scan")
    subparser.add_argument("--recursive", "-r", action="store_true",
                           help="Recursively scan directories")
    subparser.add_argument("--output", "-o", help="Output file for export")
    subparser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="Sentinel SIEM - Advanced Log Analysis and Security Monitoring",
    )
    subparsers = parser.add_subparsers(dest="mode", help="Operation mode")

    analyze_parser = subparsers.add_parser("analyze", help="Analyze logs and detect threats")
    _add_common_args(analyze_parser)

    dash_parser = subparsers.add_parser("dashboard", help="Interactive live SOC dashboard")
    _add_common_args(dash_parser)

    export_parser = subparsers.add_parser("export", help="Export findings to report")
    _add_common_args(export_parser)

    mitre_parser = subparsers.add_parser("mitre", help="MITRE ATT&CK reference")
    mitre_parser.add_argument("--tactic", "-t", help="Filter by tactic")

    list_rules_parser = subparsers.add_parser("list-rules", help="List all loaded detection rules")
    list_rules_parser.add_argument("--rules-dir", default=DEFAULT_RULES_DIR, help="Rules directory")

    args = parser.parse_args()

    if not args.mode:
        parser.print_help()
        return

    modes = {
        "analyze": analyze_mode,
        "dashboard": dashboard_mode,
        "mitre": mitre_mode,
        "export": export_mode,
        "list-rules": list_rules_mode,
    }
    modes[args.mode](args)


if __name__ == "__main__":
    main()
