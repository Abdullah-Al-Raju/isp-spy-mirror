"""
Live terminal dashboard — full intelligence display with
bandwidth graph, tracker map, fingerprint panel, behavioral
profiling, and VPN/spoof alerts.
"""

import time
from collections import deque
from datetime import datetime

from rich.console import Console, Group
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.live import Live
from rich.align import Align
from rich.progress_bar import ProgressBar
from rich import box

from utils.helpers import bytes_to_human, truncate


class LiveDashboard:
    MAX_DISPLAY_EVENTS = 300
    MAX_ALERTS = 15

    TYPE_STYLES = {
        "DNS": "cyan",
        "HTTP": "yellow",
        "TLS": "green",
        "META": "blue",
        "LEAK": "bold red",
        "WARN": "bold yellow",
        "ERROR": "bold red",
        "TRACKER": "magenta",
        "FINGERPRINT": "bright_cyan",
        "VPN LEAK": "bold red",
        "DNS SPOOF": "bold red",
        "BEHAVIOR": "bright_green",
    }

    def __init__(self, capture_engine, interface):
        self.engine = capture_engine
        self.interface = interface
        self.console = Console()
        self.events = deque(maxlen=self.MAX_DISPLAY_EVENTS)
        self.alerts = deque(maxlen=self.MAX_ALERTS)
        self._refresh_rate = 4
        self._bandwidth_history = deque(maxlen=60)
        self._last_bytes = 0
        self._last_bw_check = time.time()

    def run(self):
        with Live(
            self._build_layout(),
            console=self.console,
            refresh_per_second=self._refresh_rate,
            screen=True,
        ) as live:
            try:
                while self.engine.is_running():
                    drained = 0
                    while drained < 50:
                        event = self.engine.get_event(timeout=0.05)
                        if event is None:
                            break
                        self.events.append(event)
                        if event.get("sensitive"):
                            self.alerts.append(event)
                        drained += 1

                    self._update_bandwidth()
                    live.update(self._build_layout())
                    time.sleep(1 / self._refresh_rate)

            except KeyboardInterrupt:
                pass

    def _update_bandwidth(self):
        """Track bandwidth per second for the graph."""
        now = time.time()
        elapsed = now - self._last_bw_check
        if elapsed >= 1.0:
            stats = self.engine.get_all_stats()
            meta = stats.get("metadata", {})
            current_bytes = meta.get("bytes_sent", 0) + meta.get("bytes_received", 0)
            bps = (current_bytes - self._last_bytes) / max(elapsed, 0.1)
            self._bandwidth_history.append(int(bps))
            self._last_bytes = current_bytes
            self._last_bw_check = now

    def _build_layout(self):
        layout = Layout()

        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="body"),
            Layout(name="footer", size=max(6, min(4 + len(self.alerts), 14))),
        )

        layout["body"].split_row(
            Layout(name="left", ratio=3),
            Layout(name="right", ratio=1, minimum_size=38),
        )

        layout["left"].split_column(
            Layout(name="traffic", ratio=3),
            Layout(name="bandwidth", size=7),
        )

        layout["right"].split_column(
            Layout(name="stats", ratio=2),
            Layout(name="intel", ratio=2),
        )

        layout["header"].update(self._build_header())
        layout["traffic"].update(self._build_traffic_table())
        layout["bandwidth"].update(self._build_bandwidth_graph())
        layout["stats"].update(self._build_stats_panel())
        layout["intel"].update(self._build_intel_panel())
        layout["footer"].update(self._build_alerts_panel())

        return layout

    def _build_header(self):
        elapsed = self.engine.get_elapsed()
        elapsed_str = str(elapsed).split(".")[0] if elapsed else "00:00:00"

        packets = self.engine.packet_count
        events = len(self.events)
        leaks = len(self.alerts)

        stats = self.engine.get_all_stats()
        tracker = stats.get("tracker", {})
        vpn = stats.get("vpn_leak", {})
        spoof = stats.get("dns_spoof", {})

        parts = [
            f"[bold green]● LIVE[/]",
            f"[white]Iface:[/] [cyan]{self.interface}[/]",
            f"[white]Time:[/] [yellow]{elapsed_str}[/]",
            f"[white]Pkts:[/] [cyan]{packets:,}[/]",
            f"[white]Events:[/] [cyan]{events}[/]",
        ]

        tracker_count = tracker.get("unique_trackers", 0)
        if tracker_count > 0:
            parts.append(f"[magenta]Trackers: {tracker_count}[/]")

        if leaks > 0:
            parts.append(f"[bold red]⚠ Leaks: {leaks}[/]")

        vpn_status = vpn.get("vpn_status", "")
        if "Active" in vpn_status:
            parts.append(f"[green][VPN SECURE][/]")
            vpn_leaks = vpn.get("total_leaks", 0)
            if vpn_leaks > 0:
                parts.append(f"[bold red]VPN LEAKS: {vpn_leaks}[/]")
        else:
            parts.append(f"[yellow][NO VPN][/]")

        spoof_count = spoof.get("spoofs_detected", 0)
        if spoof_count > 0:
            parts.append(f"[bold red]☠ Spoofs: {spoof_count}[/]")

        if self.engine.duration:
            remaining = self.engine.duration - (elapsed.total_seconds() if elapsed else 0)
            parts.append(f"[yellow]{int(max(0, remaining))}s left[/]")

        status_line = "  │  ".join(parts)

        return Panel(
            Align.center(Text.from_markup(status_line)),
            title="[bold][ISP SPY MIRROR // FULL INTELLIGENCE][/]",
            border_style="bright_blue",
            box=box.DOUBLE,
        )

    def _build_traffic_table(self):
        table = Table(
            show_header=True,
            header_style="bold white on dark_blue",
            box=box.SIMPLE_HEAD,
            expand=True,
            padding=(0, 1),
            show_edge=False,
        )

        table.add_column("Time", style="dim", width=12, no_wrap=True)
        table.add_column("Type", width=12, no_wrap=True)
        table.add_column("Destination", width=26, no_wrap=True)
        table.add_column("What Your ISP Sees", ratio=1)

        display_events = list(self.events)
        max_rows = max(8, self.console.height - 28)
        visible_events = display_events[-max_rows:]

        for event in visible_events:
            time_str = event.get("timestamp", "")
            event_type = event.get("type", "")
            subtype = event.get("subtype", "")
            destination = event.get("destination", "")
            detail = event.get("detail", "")
            is_sensitive = event.get("sensitive", False)

            type_style = self.TYPE_STYLES.get(event_type, "white")
            type_display = f"[{type_style}]{event_type}[/]"

            dest_parts = [destination]
            hostname = event.get("hostname", "")
            if hostname:
                dest_parts.append(f"[dim]{truncate(hostname, 24)}[/]")
            geo = event.get("geo", "")
            if geo:
                dest_parts.append(f"[dim italic]{truncate(geo, 24)}[/]")
            dest_display = "\n".join(dest_parts) if len(dest_parts) > 1 else destination

            if is_sensitive:
                detail_display = f"[bold red]{detail}[/]"
            elif event_type == "TRACKER":
                detail_display = f"[magenta]{detail}[/]"
            elif event_type == "BEHAVIOR":
                detail_display = f"[bright_green]{detail}[/]"
            elif event_type == "FINGERPRINT":
                detail_display = f"[bright_cyan]{detail}[/]"
            else:
                detail_display = detail

            table.add_row(
                time_str,
                Text.from_markup(type_display),
                Text.from_markup(dest_display),
                Text.from_markup(detail_display),
            )

        if not visible_events:
            table.add_row(
                "", "", "",
                "[dim italic]Waiting for traffic... "
                "Browse some websites to see what your ISP observes.[/]"
            )

        return Panel(
            table,
            title="[bold][LIVE TRAFFIC][/]",
            border_style="blue",
            box=box.ROUNDED,
        )

    def _build_bandwidth_graph(self):
        """Build ASCII bandwidth graph."""
        history = list(self._bandwidth_history)
        if not history:
            history = [0]

        max_bw = max(history) if max(history) > 0 else 1
        current_bw = history[-1] if history else 0

        # Build sparkline-style graph
        width = min(60, self.console.width - 45)
        graph_chars = "▁▂▃▄▅▆▇█"

        # Normalize and build graph
        display_history = history[-width:]
        line = ""
        for val in display_history:
            idx = min(int((val / max_bw) * (len(graph_chars) - 1)), len(graph_chars) - 1)
            line += graph_chars[idx]

        # Color based on intensity
        graph_text = f"[green]{line}[/]"

        # Stats line
        avg_bw = sum(history) / len(history) if history else 0
        stats_line = (
            f"[white]Current:[/] [cyan]{bytes_to_human(current_bw)}/s[/]  "
            f"[white]Peak:[/] [yellow]{bytes_to_human(max_bw)}/s[/]  "
            f"[white]Avg:[/] [green]{bytes_to_human(avg_bw)}/s[/]"
        )

        content = Text.from_markup(f"{graph_text}\n{stats_line}")

        return Panel(
            content,
            title="[bold][BANDWIDTH (LAST 60s)][/]",
            border_style="green",
            box=box.ROUNDED,
        )

    def _build_stats_panel(self):
        """Build statistics panel with all analyzer data."""
        stats = self.engine.get_all_stats()
        sections = []

        # Overview
        overview = Table(show_header=False, box=None, padding=(0, 1), expand=True)
        overview.add_column("L", style="bold", width=10)
        overview.add_column("V", justify="right", style="cyan", width=12)

        meta = stats.get("metadata", {})
        overview.add_row("Packets", f"{stats.get('packets_captured', 0):,}")
        overview.add_row("Sent", bytes_to_human(meta.get("bytes_sent", 0)))
        overview.add_row("Received", bytes_to_human(meta.get("bytes_received", 0)))
        overview.add_row("Dest IPs", str(meta.get("unique_destinations", 0)))
        sections.append(Panel(overview, title="[bold]Overview[/]", box=box.SIMPLE))

        # DNS
        dns = stats.get("dns", {})
        dns_table = Table(show_header=False, box=None, padding=(0, 1), expand=True)
        dns_table.add_column("L", style="bold", width=10)
        dns_table.add_column("V", justify="right", style="cyan", width=12)
        dns_table.add_row("Queries", str(dns.get("total_queries", 0)))
        dns_table.add_row("Domains", str(dns.get("unique_domains", 0)))

        top_domains = dns.get("top_domains", [])
        if top_domains:
            domain_lines = ""
            for domain, count in top_domains[:4]:
                domain_lines += f"[dim]{count}x[/] {truncate(domain, 18)}\n"
            dns_content = Table(show_header=False, box=None, expand=True)
            dns_content.add_column(ratio=1)
            dns_content.add_row(dns_table)
            dns_content.add_row(Text.from_markup(domain_lines.strip()))
            sections.append(Panel(dns_content, title="[bold cyan]DNS[/]", box=box.SIMPLE))
        else:
            sections.append(Panel(dns_table, title="[bold cyan]DNS[/]", box=box.SIMPLE))

        # TLS
        tls = stats.get("tls", {})
        tls_table = Table(show_header=False, box=None, padding=(0, 1), expand=True)
        tls_table.add_column("L", style="bold", width=10)
        tls_table.add_column("V", justify="right", style="green", width=12)
        tls_table.add_row("SNI Seen", str(tls.get("total_handshakes", 0)))
        tls_table.add_row("Domains", str(tls.get("unique_domains", 0)))
        sections.append(Panel(tls_table, title="[bold green]TLS/SNI[/]", box=box.SIMPLE))

        # HTTP
        http = stats.get("http", {})
        if http.get("total_requests", 0) > 0:
            http_table = Table(show_header=False, box=None, padding=(0, 1), expand=True)
            http_table.add_column("L", style="bold", width=10)
            http_table.add_column("V", justify="right", style="yellow", width=12)
            http_table.add_row("Requests", str(http.get("total_requests", 0)))
            http_table.add_row("URLs", str(http.get("unique_urls", 0)))
            sections.append(Panel(http_table, title="[bold yellow]HTTP ⚠[/]", box=box.SIMPLE))

        panel_content = Group(*sections)
        return Panel(
            panel_content,
            title="[bold][STATISTICS][/]",
            border_style="blue",
            box=box.ROUNDED,
        )

    def _build_intel_panel(self):
        """Build intelligence panel: fingerprint, trackers, behavior."""
        stats = self.engine.get_all_stats()
        sections = []

        # Device fingerprint
        fp = stats.get("fingerprint", {})
        best = fp.get("best_guess", {})
        if best.get("os", "Unknown") != "Unknown" or best.get("browser", "Unknown") != "Unknown":
            fp_table = Table(show_header=False, box=None, padding=(0, 1), expand=True)
            fp_table.add_column("L", style="bold", width=10)
            fp_table.add_column("V", style="bright_cyan", width=16)
            fp_table.add_row("OS", best.get("os", "?"))
            fp_table.add_row("Browser", best.get("browser", "?"))
            fp_table.add_row("Device", best.get("device", "?"))
            fp_table.add_row("JA3s", str(best.get("ja3_count", 0)))
            sections.append(Panel(fp_table, title="[bold bright_cyan][DEVICE][/]", box=box.SIMPLE))

        # Trackers
        tracker = stats.get("tracker", {})
        if tracker.get("unique_trackers", 0) > 0:
            tr_table = Table(show_header=False, box=None, padding=(0, 1), expand=True)
            tr_table.add_column("L", style="bold", width=10)
            tr_table.add_column("V", style="magenta", width=16)
            tr_table.add_row("Trackers", str(tracker.get("unique_trackers", 0)))
            tr_table.add_row("Companies", str(tracker.get("unique_companies", 0)))
            tr_table.add_row("Hits", str(tracker.get("total_tracker_hits", 0)))

            categories = tracker.get("categories", {})
            if categories:
                cat_str = ""
                for cat, count in sorted(categories.items(), key=lambda x: x[1], reverse=True)[:3]:
                    cat_str += f"[dim]{count}x[/] {cat}\n"
                tr_content = Table(show_header=False, box=None, expand=True)
                tr_content.add_column(ratio=1)
                tr_content.add_row(tr_table)
                tr_content.add_row(Text.from_markup(cat_str.strip()))
                sections.append(Panel(tr_content, title="[bold magenta][TRACKERS][/]", box=box.SIMPLE))
            else:
                sections.append(Panel(tr_table, title="[bold magenta][TRACKERS][/]", box=box.SIMPLE))

        # Behavior
        behavior = stats.get("behavior", {})
        if behavior.get("total_events", 0) > 0:
            bh_table = Table(show_header=False, box=None, padding=(0, 1), expand=True)
            bh_table.add_column("L", style="bold", width=10)
            bh_table.add_column("V", style="bright_green", width=16)
            bh_table.add_row("Activity", behavior.get("dominant_activity", "?").replace("_", " ").title())
            bh_table.add_row("Period", behavior.get("time_period", "?"))
            bh_table.add_row("Active", f"{behavior.get('active_minutes', 0)} min")

            inferences = behavior.get("inferences", [])
            if inferences:
                inf_text = ""
                for inf in inferences[-3:]:
                    inf_text += f"[dim]• {truncate(inf, 28)}[/]\n"
                bh_content = Table(show_header=False, box=None, expand=True)
                bh_content.add_column(ratio=1)
                bh_content.add_row(bh_table)
                bh_content.add_row(Text.from_markup(inf_text.strip()))
                sections.append(Panel(bh_content, title="[bold bright_green][BEHAVIOR][/]", box=box.SIMPLE))
            else:
                sections.append(Panel(bh_table, title="[bold bright_green][BEHAVIOR][/]", box=box.SIMPLE))

        # Leaks summary
        leaks = stats.get("leaks", {})
        vpn = stats.get("vpn_leak", {})
        spoof = stats.get("dns_spoof", {})
        total_issues = (leaks.get("total_leaks", 0) +
                       vpn.get("total_leaks", 0) +
                       spoof.get("spoofs_detected", 0))

        if total_issues > 0:
            sec_table = Table(show_header=False, box=None, padding=(0, 1), expand=True)
            sec_table.add_column("L", style="bold", width=10)
            sec_table.add_column("V", style="red", width=16)
            sec_table.add_row("Data Leaks", str(leaks.get("total_leaks", 0)))
            sec_table.add_row("VPN Leaks", str(vpn.get("total_leaks", 0)))
            sec_table.add_row("DNS Spoof", str(spoof.get("spoofs_detected", 0)))
            sections.append(Panel(sec_table, title="[bold red][SECURITY][/]", box=box.SIMPLE))

        if not sections:
            sections.append(Panel(
                Align.center(Text.from_markup("[dim]Collecting intelligence...[/]")),
                box=box.SIMPLE,
            ))

        panel_content = Group(*sections)
        return Panel(
            panel_content,
            title="[bold][INTELLIGENCE][/]",
            border_style="bright_blue",
            box=box.ROUNDED,
        )

    def _build_alerts_panel(self):
        if not self.alerts:
            return Panel(
                Align.center(
                    Text.from_markup(
                        "[dim]No alerts yet. Plaintext passwords, "
                        "VPN leaks, DNS spoofing, and tracker "
                        "activity will appear here.[/]"
                    )
                ),
                title="[bold][SECURITY ALERTS][/]",
                border_style="dim",
                box=box.ROUNDED,
            )

        alert_table = Table(
            show_header=True,
            header_style="bold white on red",
            box=box.SIMPLE_HEAD,
            expand=True,
            padding=(0, 1),
        )
        alert_table.add_column("Time", width=12, no_wrap=True)
        alert_table.add_column("Alert", width=22)
        alert_table.add_column("Destination", width=20)
        alert_table.add_column("Detail", ratio=1)

        for alert in list(self.alerts)[-self.MAX_ALERTS:]:
            severity = alert.get("severity", "")
            alert_type = alert.get("type", "")

            if severity == "CRITICAL" or "LEAK" in alert_type:
                style = "bold red"
            elif severity == "HIGH":
                style = "red"
            elif "SPOOF" in alert_type:
                style = "bold red"
            elif "TRACKER" in alert_type:
                style = "magenta"
            else:
                style = "bold yellow"

            alert_table.add_row(
                alert.get("timestamp", ""),
                f"[{style}]{truncate(alert.get('subtype', alert_type), 20)}[/]",
                truncate(alert.get("destination", ""), 18),
                f"[{style}]{truncate(alert.get('detail', ''), 70)}[/]",
            )

        return Panel(
            alert_table,
            title=f"[bold red][SECURITY] Alerts ({len(self.alerts)} found)[/]",
            border_style="red",
            box=box.ROUNDED,
        )


class SummaryReport:
    def __init__(self, console=None):
        self.console = console or Console()

    def display(self, stats):
        self.console.clear()
        self.console.print()

        # Header
        self.console.print(Panel(
            Align.center(Text("[ISP SPY MIRROR // FULL INTELLIGENCE REPORT]",
                             style="bold white")),
            border_style="bright_blue",
            box=box.DOUBLE,
        ))
        self.console.print()

        # Overview
        overview = Table(show_header=False, box=box.SIMPLE, expand=False)
        overview.add_column("Metric", style="bold", width=25)
        overview.add_column("Value", style="cyan", width=20)

        overview.add_row("Packets Captured", f"{stats.get('packets_captured', 0):,}")
        overview.add_row("Events Logged", f"{stats.get('events_logged', 0):,}")

        meta = stats.get("metadata", {})
        overview.add_row("Data Sent", bytes_to_human(meta.get("bytes_sent", 0)))
        overview.add_row("Data Received", bytes_to_human(meta.get("bytes_received", 0)))
        overview.add_row("Unique Destinations", str(meta.get("unique_destinations", 0)))

        self.console.print(Panel(overview, title="[bold][OVERVIEW][/]"))
        self.console.print()

        # DNS
        dns = stats.get("dns", {})
        self.console.print(
            f"[bold cyan]DNS Queries:[/] {dns.get('total_queries', 0)} "
            f"({dns.get('unique_domains', 0)} unique domains)"
        )
        top_domains = dns.get("top_domains", [])
        if top_domains:
            dt = Table(box=box.SIMPLE, show_edge=False)
            dt.add_column("Count", justify="right", style="cyan", width=8)
            dt.add_column("Domain", style="white")
            for domain, count in top_domains[:10]:
                dt.add_row(str(count), domain)
            self.console.print(dt)
        self.console.print()

        # TLS/HTTPS
        tls = stats.get("tls", {})
        self.console.print(
            f"[bold green]HTTPS (SNI):[/] "
            f"{tls.get('total_handshakes', 0)} "
            f"({tls.get('unique_domains', 0)} unique)"
        )
        domains = sorted(tls.get("domains", []))
        if domains:
            domain_list = ", ".join(domains[:20])
            if len(domains) > 20:
                domain_list += f" (+{len(domains) - 20} more)"
            self.console.print(f"  [dim]{domain_list}[/]")
        self.console.print()

        # HTTP
        http = stats.get("http", {})
        if http.get("total_requests", 0) > 0:
            self.console.print(
                f"[bold yellow]⚠ Plaintext HTTP:[/] "
                f"{http.get('total_requests', 0)} requests "
                f"({http.get('unique_urls', 0)} unique URLs)"
            )
            self.console.print()

        # Device Fingerprint
        fp = stats.get("fingerprint", {})
        best = fp.get("best_guess", {})
        if best:
            self.console.print(Panel(
                f"[bold]OS:[/] [cyan]{best.get('os', '?')}[/]  |  "
                f"[bold]Browser:[/] [cyan]{best.get('browser', '?')}[/]  |  "
                f"[bold]Device:[/] [cyan]{best.get('device', '?')}[/]  |  "
                f"[bold]JA3 Hashes:[/] [cyan]{best.get('ja3_count', 0)}[/]",
                title="[bold bright_cyan][DEVICE] Fingerprint[/]",
                border_style="bright_cyan",
            ))
            self.console.print()

        # Trackers
        tracker = stats.get("tracker", {})
        if tracker.get("unique_trackers", 0) > 0:
            tr_table = Table(box=box.SIMPLE, show_edge=False)
            tr_table.add_column("Hits", justify="right", style="magenta", width=6)
            tr_table.add_column("Company", style="bold", width=25)
            tr_table.add_column("Category", style="dim", width=15)
            tr_table.add_column("Domain", style="dim")
            for domain, company, category, count in tracker.get("top_trackers", []):
                tr_table.add_row(str(count), company, category, domain)
            self.console.print(Panel(
                tr_table,
                title=f"[bold magenta][TRACKERS] Found "
                      f"({tracker.get('unique_companies', 0)} companies)[/]",
                border_style="magenta",
            ))
            self.console.print()

        # Behavioral Profile
        behavior = stats.get("behavior", {})
        profile = behavior.get("isp_profile", {})
        if profile:
            interests = profile.get("interests", [])
            inferences = profile.get("inferences", [])

            profile_text = (
                f"[bold]Dominant Activity:[/] [cyan]"
                f"{profile.get('dominant_activity', '?').replace('_', ' ').title()}"
                f"[/]\n"
                f"[bold]Time Period:[/] [cyan]{profile.get('time_period', '?')}[/]\n"
                f"[bold]Active Duration:[/] [cyan]"
                f"{profile.get('active_minutes', 0)} minutes[/]\n"
                f"[bold]Sleep Pattern:[/] [cyan]"
                f"{profile.get('sleep_pattern', '?')}[/]\n"
            )

            if interests:
                profile_text += f"\n[bold]Derived Interests:[/]\n"
                for interest in interests:
                    profile_text += f"  [green]•[/] {interest}\n"

            if inferences:
                profile_text += f"\n[bold]ISP Inferences:[/]\n"
                for inf in inferences[-5:]:
                    profile_text += f"  [yellow]→[/] {inf}\n"

            self.console.print(Panel(
                Text.from_markup(profile_text),
                title="[bold bright_green][BEHAVIOR]al Profile "
                      "(what ISP could sell)[/]",
                border_style="bright_green",
            ))
            self.console.print()

        # Security Summary
        leaks = stats.get("leaks", {})
        vpn = stats.get("vpn_leak", {})
        spoof = stats.get("dns_spoof", {})
        total_leaks = leaks.get("total_leaks", 0)
        total_vpn = vpn.get("total_leaks", 0)
        total_spoof = spoof.get("spoofs_detected", 0)
        total_issues = total_leaks + total_vpn + total_spoof

        if total_issues > 0:
            sec_text = (
                f"[bold red]Data Leaks:[/] {total_leaks} "
                f"(Critical: {leaks.get('critical_count', 0)}, "
                f"Warnings: {leaks.get('warning_count', 0)})\n"
                f"[bold red]VPN Leaks:[/] {total_vpn}\n"
                f"[bold red]DNS Spoof Alerts:[/] {total_spoof} "
                f"(Critical: {spoof.get('critical_count', 0)}, "
                f"High: {spoof.get('high_count', 0)})\n"
            )
            self.console.print(Panel(
                Text.from_markup(sec_text),
                title=f"[bold red]ALERT: {total_issues} Security Issues[/]",
                border_style="red",
            ))
        else:
            self.console.print(Panel(
                "[bold green]No security issues detected.[/]",
                title="[bold green]✅ Clean Session[/]",
                border_style="green",
            ))
        self.console.print()

        # ISP Knowledge Summary
        self.console.print(Panel(
            Text.from_markup(
                f"[bold]Based on this session, your ISP knows:[/]\n\n"
                f"  • [cyan]Every website you visited[/] "
                f"({dns.get('unique_domains', 0)} DNS + "
                f"{tls.get('unique_domains', 0)} TLS SNI)\n"
                f"  • [cyan]When you visited them[/] (timestamps)\n"
                f"  • [cyan]Data transferred[/] "
                f"({bytes_to_human(meta.get('bytes_sent', 0))} up, "
                f"{bytes_to_human(meta.get('bytes_received', 0))} down)\n"
                f"  • [cyan]Your device[/] "
                f"({best.get('os', '?')} / {best.get('browser', '?')})\n"
                f"  • [magenta]{tracker.get('unique_companies', 0)} "
                f"tracking companies[/] following you\n"
                + (f"  • [red]{total_leaks} pieces of sensitive "
                   f"data in plaintext[/]\n"
                   if total_leaks > 0 else "")
                + (f"  • [yellow]Your behavioral profile[/] "
                   f"({', '.join(profile.get('interests', ['browsing'])[:3])})\n"
                   if profile.get("interests") else "")
                + f"\n[dim]All of this is visible even with HTTPS. "
                  f"Only a VPN hides the destination metadata.[/]"
            ),
            title="[bold][WHAT YOUR ISP KNOWS ABOUT YOU][/]",
            border_style="bright_blue",
        ))
        self.console.print()
