#!/usr/bin/env python3
"""
ISP Spy Mirror — Full Intelligence Edition v2.0
See what your ISP, network snoopers, and data brokers can observe about your traffic.
Author: Abduallah Al Raju
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

from utils.helpers import check_root, check_capture_privileges, get_default_interface
from capture import CaptureEngine
from dashboard.live_display import LiveDashboard, SummaryReport
from reports.dossier import ISPDossier
from reports.html_report import HTMLReport


def build_parser():
    parser = argparse.ArgumentParser(
        description="ISP Spy Mirror — Defensive Network Privacy & Telemetry Radar.",
    )
    subparsers = parser.add_subparsers(dest="command", help="Operational mode")

    # WEB MODE
    web_parser = subparsers.add_parser("web", help="Launch interactive tactical web dashboard & control center")
    web_parser.add_argument("--host", default="127.0.0.1", help="Binding host (default: 127.0.0.1)")
    web_parser.add_argument("--port", type=int, default=8080, help="Binding port (default: 8080)")
    web_parser.add_argument("--live", action="store_true", default=False, help="Force authentic live network monitoring mode")
    web_parser.add_argument("--demo", action="store_true", default=False, help="Run in synthetic simulation mode (rootless)")
    web_parser.add_argument("-i", "--interface", default=None, help="Network interface for live sniffing")

    # LIVE MODE
    live_parser = subparsers.add_parser("live", help="Launch terminal live dashboard on network interface (requires root)")
    live_parser.add_argument("-i", "--interface", default=None, help="Network interface (default: auto-detect)")
    live_parser.add_argument("-d", "--duration", type=int, default=None, help="Capture duration in seconds")
    live_parser.add_argument("--show-all", action="store_true", default=False, help="Show all traffic including noisy")
    live_parser.add_argument("--no-geo", action="store_true", default=False, help="Disable IP geolocation lookups")
    live_parser.add_argument("-o", "--output", default=None, help="Output log file path")

    # DEMO MODE (Rootless terminal)
    demo_parser = subparsers.add_parser("demo", help="Run rootless terminal live dashboard with synthetic traffic")
    demo_parser.add_argument("-d", "--duration", type=int, default=None, help="Duration in seconds")

    # REPLAY MODE
    replay_parser = subparsers.add_parser("replay", help="Replay and analyze recorded PCAP file offline")
    replay_parser.add_argument("-p", "--pcap", required=True, help="Path to PCAP file")
    replay_parser.add_argument("-o", "--output", default=None, help="Output log file path")

    # DOSSIER MODE
    dossier_parser = subparsers.add_parser("dossier", help="Generate ISP Intelligence Dossier from past sessions")
    dossier_parser.add_argument("--db", default="isp_spy.db", help="Path to SQLite database")

    # Global flags if no subcommand given
    parser.add_argument("-i", "--interface", default=None, help="Network interface (default: auto-detect)")
    parser.add_argument("-d", "--duration", type=int, default=None, help="Capture duration in seconds")
    parser.add_argument("--web", action="store_true", default=False, help="Launch web dashboard")
    parser.add_argument("--demo", action="store_true", default=False, help="Run synthetic simulation")
    parser.add_argument("-p", "--pcap", default=None, help="Replay PCAP file")
    parser.add_argument("--no-geo", action="store_true", default=False, help="Disable geolocation")
    parser.add_argument("--show-all", action="store_true", default=False, help="Show noisy traffic")
    parser.add_argument("-o", "--output", default=None, help="Output path")

    return parser


def print_banner(console, interface, duration, geo_enabled, mode="Live"):
    duration_str = f"{duration} seconds" if duration else "until Ctrl+C"
    banner_text = Text.from_markup(
        f"[bold white][ISP SPY MIRROR // FULL INTELLIGENCE v2.0][/]\n"
        f"[dim]Defensive Network Privacy Radar & Telemetry Inspector[/]\n\n"
        f"[white]Author:[/]        [cyan]Abduallah Al Raju[/]\n"
        f"[white]Mode:[/]          [cyan]{mode}[/]\n"
        f"[white]Interface:[/]     [cyan]{interface}[/]\n"
        f"[white]Duration:[/]      [cyan]{duration_str}[/]\n"
        f"[white]Geo Lookup:[/]    [cyan]{'enabled' if geo_enabled else 'disabled'}[/]\n"
        f"[white]Analyzers:[/]     [cyan]DNS + TLS/ECH + HTTP + Leaks + Trackers + Fingerprint + VPN[/]\n\n"
        f"[dim]Press Ctrl+C to stop capture and generate full audit reports.[/]"
    )
    console.print(Panel(
        banner_text,
        border_style="bright_blue",
        box=box.DOUBLE,
        padding=(1, 3),
    ))
    console.print()


def run_live_or_demo(interface, duration=None, show_all=False, geo_enabled=True,
                      output_path=None, simulate=False, pcap_file=None):
    console = Console()
    mode_name = "Synthetic Simulation (Rootless)" if simulate else ("PCAP Replay" if pcap_file else "Live Interface")

    if not simulate and not pcap_file:
        check_root(required=True)
        if not os.path.exists(f"/sys/class/net/{interface}"):
            console.print(f"[bold red]Error:[/] Interface '{interface}' not found.")
            console.print("[dim]Available interfaces:[/]")
            for iface in os.listdir("/sys/class/net/"):
                console.print(f"  - {iface}")
            sys.exit(1)

    print_banner(console, interface, duration, geo_enabled, mode=mode_name)

    engine = CaptureEngine(
        interface=interface,
        duration=duration,
        show_all=show_all,
        geo_enabled=geo_enabled,
        output_path=output_path,
        simulate=simulate,
        pcap_file=pcap_file,
    )

    dashboard = LiveDashboard(engine, interface)

    def signal_handler(sig, frame):
        engine._stop_event.set()

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    console.print("[bold green]Starting packet analysis engine...[/]\n")

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
        console.print("\n[bold yellow]Stopping engine and finalizing reports...[/]")
        stats, pcap_path = engine.stop()

        try:
            dossier = ISPDossier(stats)
            dossier_path = dossier.save()
        except Exception as e:
            console.print(f"[dim red]Dossier generation failed: {e}[/]")

        try:
            html_report = HTMLReport()
            html_path = html_report.generate(stats)
        except Exception as e:
            console.print(f"[dim red]HTML report generation failed: {e}[/]")

        summary = SummaryReport(console)
        summary.display(stats)

        console.print(Panel(
            Text.from_markup(
                f"[bold white]Generated Artifacts & Reports:[/]\n\n"
                f"  Log File:       [cyan]{engine.session_logger.log_path}[/]\n"
                f"  JSON Telemetry: [cyan]{engine.session_logger.json_path}[/]\n"
                f"  Database:       [cyan]isp_spy.db[/]\n"
                + (f"  PCAP Capture:   [cyan]{pcap_path}[/]\n" if pcap_path else "")
                + (f"  ISP Dossier:    [cyan]{dossier_path}[/]\n" if dossier_path else "")
                + (f"  HTML Audit:     [cyan]{html_path}[/]\n" if html_path else "")
            ),
            title="[bold]Report Artifacts[/]",
            border_style="green",
        ))
        console.print()


def main():
    parser = build_parser()
    args = parser.parse_args()

    command = args.command

    # Handle explicit subcommands
    if command == "web" or args.web:
        from web_app import run_web_server
        host = getattr(args, "host", "127.0.0.1")
        port = getattr(args, "port", 8080)
        demo = getattr(args, "demo", False)
        live = getattr(args, "live", False)
        iface = getattr(args, "interface", None)

        engine = None
        if iface or live:
            check_root(required=True)
            active_iface = iface or get_default_interface()
            engine = CaptureEngine(interface=active_iface, simulate=False, geo_enabled=True)
            engine.start()
            demo = False
        elif not demo:
            if check_capture_privileges(required=False):
                active_iface = iface or get_default_interface()
                engine = CaptureEngine(interface=active_iface, simulate=False, geo_enabled=True)
                engine.start()
                demo = False
            else:
                demo = True

        run_web_server(host=host, port=port, engine=engine, demo=demo, interface=iface)
        return

    if command == "live":
        iface = args.interface or get_default_interface()
        check_root(required=True)
        run_live_or_demo(
            interface=iface,
            duration=args.duration,
            show_all=args.show_all,
            geo_enabled=not args.no_geo,
            output_path=args.output,
            simulate=False,
        )
        return

    if command == "demo" or args.demo:
        run_live_or_demo(
            interface="sim0",
            duration=args.duration,
            simulate=True,
            geo_enabled=False,
        )
        return

    if command == "replay" or args.pcap:
        pcap_file = getattr(args, "pcap", None)
        if not pcap_file or not os.path.exists(pcap_file):
            print(f"[!] Error: PCAP file not found: {pcap_file}")
            sys.exit(1)
        run_live_or_demo(
            interface="pcap",
            duration=None,
            pcap_file=pcap_file,
            geo_enabled=False,
            output_path=getattr(args, "output", None),
        )
        return

    if command == "dossier":
        from data.database import Database
        db_path = getattr(args, "db", "isp_spy.db")
        db = Database(db_path=db_path)
        stats = db.get_aggregate_stats()
        dossier = ISPDossier(stats)
        path = dossier.save()
        print(f"[+] Consolidated ISP Dossier saved to: {path}")
        return

    # Default fallback: live mode
    iface = args.interface or get_default_interface()
    has_caps = check_capture_privileges(required=False)
    if not has_caps:
        print("[!] Notice: No live capture privileges detected.")
        print("[+] Starting Web Dashboard with Synthetic Simulation instead...")
        print("[+] To run live sniffing, ensure wireshark/dumpcap access or run with sudo.\n")
        from web_app import run_web_server
        run_web_server(host="127.0.0.1", port=8080, demo=True)
        return

    run_live_or_demo(
        interface=iface,
        duration=args.duration,
        show_all=args.show_all,
        geo_enabled=not args.no_geo,
        output_path=args.output,
        simulate=False,
    )


if __name__ == "__main__":
    main()
