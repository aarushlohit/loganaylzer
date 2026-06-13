import time
import threading
from datetime import datetime, timezone
from typing import Optional

from rich.console import Console
from rich.table import Table
from rich.layout import Layout
from rich.panel import Panel
from rich.live import Live
from rich.text import Text
from rich.progress import BarColumn, Progress, TextColumn
from rich.box import ROUNDED, HEAVY
from rich.align import Align
from rich.columns import Columns

from siem.utils import severity_label, severity_color, format_bytes, format_duration
from siem.alerting import AlertManager, Alert
from siem.incident import IncidentManager
from siem.mitre import assess_compromise


class SOCDashboard:
    def __init__(self, alert_manager: AlertManager,
                 incident_manager: Optional[IncidentManager] = None):
        self.alerts = alert_manager
        self.incidents = incident_manager
        self.console = Console()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self.start_time = datetime.now(timezone.utc)
        self.total_events = 0
        self.total_bytes = 0
        self.mitre_tactics_triggered: set[str] = set()

    def update_event_count(self, count: int, bytes_count: int = 0) -> None:
        self.total_events = count
        self.total_bytes = bytes_count

    def _build_layout(self) -> Layout:
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="body"),
            Layout(name="footer", size=3),
        )
        layout["body"].split_row(
            Layout(name="alerts", ratio=3),
            Layout(name="sidebar", ratio=1),
        )
        layout["sidebar"].split_column(
            Layout(name="stats", size=14),
            Layout(name="mitre", size=10),
            Layout(name="recent", size=8),
        )
        return layout

    def _render_header(self) -> Panel:
        uptime = format_duration((datetime.now(timezone.utc) - self.start_time).total_seconds())
        text = Text()
        text.append(" SENTINEL SIEM ", style="bold black on #00d4aa")
        text.append(f"  Live SOC Dashboard  |  Uptime: {uptime}", style="bold #00d4aa")
        text.append(f"  |  Events: {self.total_events}", style="white")
        text.append(f"  |  Data: {format_bytes(self.total_bytes)}", style="white")
        return Panel(text, style="#00d4aa")

    def _render_alerts_table(self) -> Table:
        table = Table(
            box=ROUNDED,
            title="[bold #ff8800]Active Alerts[/]",
            title_justify="left",
            border_style="#2a2a3a",
            header_style="bold #00d4aa",
        )
        table.add_column("Time", style="dim", width=10)
        table.add_column("Severity", width=10)
        table.add_column("Rule", width=22)
        table.add_column("Description", width=40)
        table.add_column("Source", width=16)
        table.add_column("Status", width=8)

        open_alerts = self.alerts.get_open_alerts()[:15]
        if not open_alerts:
            table.add_row("", "[dim]No alerts[/]", "", "", "", "")
        else:
            for alert in open_alerts:
                ts = alert.timestamp.strftime("%H:%M:%S")
                sev_label = severity_label(alert.severity)
                sev_color = severity_color(alert.severity)
                table.add_row(
                    ts,
                    f"[{sev_color}]{sev_label}[/]",
                    f"[white]{alert.rule_name[:22]}[/]",
                    f"[dim]{alert.description[:40]}[/]",
                    f"[cyan]{alert.event.get('src_ip', '')}[/]",
                    f"[yellow]{alert.status}[/]",
                )
        return table

    def _render_stats(self) -> Panel:
        stats = self.alerts.get_stats()
        content = Text()
        content.append("\n")
        content.append(f"  Total Alerts     [bold white]{stats['total']:>6}[/]\n")
        content.append(f"  Open Alerts      [bold #ff8800]{stats['open']:>6}[/]\n")
        content.append(f"  Critical         [bold red]{stats['critical']:>6}[/]\n")
        content.append(f"  High             [bold #ff8800]{stats['high']:>6}[/]\n")
        content.append(f"  Medium           [bold yellow]{stats['medium']:>6}[/]\n")
        content.append(f"  Low              [bold green]{stats['low']:>6}[/]\n")

        if self.incidents:
            inc_stats = self.incidents.get_stats()
            content.append(f"\n  Incidents        [bold white]{inc_stats['open']:>6}[/]\n")

        event_rate = self.total_events / max(
            (datetime.now(timezone.utc) - self.start_time).total_seconds(), 1
        )
        content.append(f"\n  Event Rate       [bold cyan]{event_rate:.1f}/s[/]")

        return Panel(content, title="[bold #00d4aa]Stats[/]", border_style="#2a2a3a")

    def _render_mitre_panel(self) -> Panel:
        comp = assess_compromise(self.mitre_tactics_triggered)
        content = Text()
        content.append(f"\n  Score: [bold white]{comp['compromise_score']}/{comp['max_score']}[/]\n")
        confidence_color = "red" if comp['confidence_percent'] >= 60 else "yellow"
        content.append(f"  Confidence: [bold {confidence_color}]{comp['confidence_percent']}%[/]\n")
        content.append(f"  Severity: [bold {severity_color(5)}]{comp['severity']}[/]\n")
        content.append(f"\n  [dim]{comp['assessment'][:50]}[/]")
        return Panel(content, title="[bold #00d4aa]Compromise Assessment[/]", border_style="#2a2a3a")

    def _render_footer(self) -> Panel:
        text = Text()
        text.append(" [Q]uit  [R]efresh  [E]xport  [I]ncidents  [C]lear  ", style="bold #00d4aa")
        return Panel(text, style="#2a2a3a")

    def display(self) -> None:
        layout = self._build_layout()
        layout["header"].update(self._render_header())
        layout["alerts"].update(self._render_alerts_table())
        layout["stats"].update(self._render_stats())
        layout["mitre"].update(self._render_mitre_panel())
        layout["footer"].update(self._render_footer())

        try:
            self.console.clear()
            self.console.print(layout)
        except Exception:
            pass

    def start_live(self, refresh_interval: float = 2.0) -> None:
        self._running = True
        self._thread = threading.Thread(target=self._live_loop, args=(refresh_interval,), daemon=True)
        self._thread.start()

    def _live_loop(self, interval: float) -> None:
        layout = self._build_layout()

        with Live(layout, console=self.console, refresh_per_second=1 / interval,
                  screen=True):
            while self._running:
                layout["header"].update(self._render_header())
                layout["alerts"].update(self._render_alerts_table())
                layout["stats"].update(self._render_stats())
                layout["mitre"].update(self._render_mitre_panel())
                layout["footer"].update(self._render_footer())
                time.sleep(interval)

    def stop(self) -> None:
        self._running = False


def print_alert_summary(alert: Alert) -> None:
    console = Console()
    sev_color = severity_color(alert.severity)
    sev_label = severity_label(alert.severity)
    console.print(
        f"[{sev_color}]![/] [{sev_color}]{sev_label:8}[/] "
        f"[white]{alert.rule_name}[/] "
        f"[dim]| {alert.event.get('src_ip', ''):15} | {alert.event.get('user', ''):12} | "
        f"{alert.description[:60]}[/]"
    )


def print_finding(finding: dict) -> None:
    console = Console()
    sev = finding.get("severity", 3)
    sev_color = severity_color(sev)
    sev_label = severity_label(sev)
    event = finding.get("event", {})
    console.print(
        f"[{sev_color}]![/] [{sev_color}]{sev_label:8}[/] "
        f"[white]{finding.get('rule_name', '')}[/] "
        f"[dim]| {event.get('src_ip', ''):15} | {event.get('user', ''):12} | "
        f"[/]{finding.get('description', '')[:80]}"
    )


def print_finding_verbose(finding: dict) -> None:
    console = Console()
    console.print()
    console.print(Panel(
        f"[bold #ff8800]{finding.get('rule_name', '')}[/]\n"
        f"[dim]{finding.get('description', '')}[/]\n\n"
        f"Severity: [{severity_color(finding.get('severity', 3))}]"
        f"{severity_label(finding.get('severity', 3))}[/]\n"
        f"Category: {finding.get('category', '')}\n"
        f"MITRE: [bold]{finding.get('mitre_id', '')}[/] "
        f"{finding.get('mitre_tactic', '')} / {finding.get('mitre_technique', '')}\n"
        f"Source IP: [cyan]{finding.get('event', {}).get('src_ip', '')}[/]\n"
        f"User: [yellow]{finding.get('event', {}).get('user', '')}[/]\n"
        f"Timestamp: {finding.get('timestamp', '')}",
        border_style="#ff8800",
        title="[bold]Finding Detail[/]",
    ))
