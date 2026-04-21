#!/usr/bin/env python3
"""
ISP Spy Mirror — Full Intelligence Edition
"""

import argparse
import signal
import sys
import os
import time

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich import box

from utils.helpers import check_root, get_default_interface
from capture import CaptureEngine
from dashboard.live_display import LiveDashboard, SummaryReport
from reports.dossier import ISPDossier
from reports.html_report import HTMLReport


def parse_args():
    parser = argparse.ArgumentParser(
        description="ISP Spy Mirror — See what your ISP sees about your traffic.",
    )
    parser.add_argument(
        "-i", "--interface", default=None,
        help="Network interface (default: auto-detect)",
    )
    parser.add_argument(
        "-d", "--duration", type=int, default=None,
        help="Capture duration in seconds (default: until Ctrl+C)",
    )
    parser.add_argument(
        "--show-all", action="store_true", default=False,
        help="Show all traffic including noisy/internal",
    )
    parser.add_argument(
        "--no-geo", action="store_true", default=False,
        help="Disable IP geolocation lookups",
    )
    parser.add_argument(
        "-o", "--output", default=None,
        help="Output log file path (default: auto-generated)",
    )
    parser.add_argument(
        "--no-pcap", action="store_true", default=False,
        help="Disable PCAP capture (saves memory)",
    )
    return parser.parse_args()


def print_banner(console, interface, duration, geo_enabled):
    duration_str = f"{duration} seconds" if duration else "until Ctrl+C"
    banner_text = Text.from_markup(
        f"[bold white]🪞 ISP SPY MIRROR — FULL INTELLIGENCE[/]\n"
        f"[dim]See exactly what your ISP can observe about your traffic[/]\n\n"
        f"[white]Interface:[/]    [cyan]{interface}[/]\n"
        f"[white]Duration:[/]     [cyan]{duration_str}[/]\n"
        f"[white]Geo lookup:[/]   [cyan]{'enabled' if geo_enabled else 'disabled'}[/]\n"
        f"[white]Intelligence:[/] [cyan]Fingerprint + Trackers + Behavior + VPN/Spoof[/]\n\n"
        f"[dim]Press Ctrl+C to stop and see the full intelligence report.[/]"
    )
    console.print(Panel(
        banner_text,
        border_style="bright_blue",
        box=box.DOUBLE,
        padding=(1, 3),
    ))
    console.print()


def main():
    console = Console()

    check_root()
    args = parse_args()

    interface = args.interface or get_default_interface()
    geo_enabled = not args.no_geo

    print_banner(console, interface, args.duration, geo_enabled)

    if not os.path.exists(f"/sys/class/net/{interface}"):
        console.print(f"[bold red]Error:[/] Interface '{interface}' not found.")
        console.print("[dim]Available interfaces:[/]")
        for iface in os.listdir("/sys/class/net/"):
            console.print(f"  - {iface}")
        sys.exit(1)

    engine = CaptureEngine(
        interface=interface,
        duration=args.duration,
        show_all=args.show_all,
        geo_enabled=geo_enabled,
        output_path=args.output,
    )

    dashboard = LiveDashboard(engine, interface)

    def signal_handler(sig, frame):
        engine._stop_event.set()

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    console.print("[bold green]Starting capture...[/]\n")

    pcap_path = None
    dossier_path = None
    html_path = None

    try:
        engine.start()
        time.sleep(0.5)
        dashboard.run()

    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")

    finally:
        console.print("\n[bold yellow]Stopping capture and generating reports...[/]")

        # Stop engine and get stats + pcap
        stats, pcap_path = engine.stop()

        # Generate ISP Dossier
        try:
            dossier = ISPDossier(stats)
            dossier_path = dossier.save()
        except Exception as e:
            console.print(f"[dim red]Dossier generation failed: {e}[/]")

        # Generate HTML Report
        try:
            html_report = HTMLReport()
            html_path = html_report.generate(stats)
        except Exception as e:
            console.print(f"[dim red]HTML report generation failed: {e}[/]")

        # Display terminal summary
        summary = SummaryReport(console)
        summary.display(stats)

        # List all generated files
        console.print(Panel(
            Text.from_markup(
                f"[bold white]Generated Files:[/]\n\n"
                f"  📄 Session log:  [cyan]{engine.session_logger.log_path}[/]\n"
                f"  📊 JSON data:    [cyan]{engine.session_logger.json_path}[/]\n"
                f"  🗄  Database:     [cyan]isp_spy.db[/]\n"
                + (f"  📦 PCAP file:    [cyan]{pcap_path}[/]\n" if pcap_path else "")
                + (f"  🕵  ISP Dossier:  [cyan]{dossier_path}[/]\n" if dossier_path else "")
                + (f"  🌐 HTML Report:  [cyan]{html_path}[/]\n" if html_path else "")
            ),
            title="[bold]📁 Output Files[/]",
            border_style="green",
        ))
        console.print()


if __name__ == "__main__":
    main()
