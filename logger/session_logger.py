"""
Session logger — writes all captured events to a log file.
"""

import json
import os
from datetime import datetime
from threading import Lock


class SessionLogger:

    def __init__(self, output_path=None):
        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = f"isp_spy_session_{timestamp}.log"

        self.log_path = output_path
        self.json_path = output_path.replace(".log", ".json")
        self._lock = Lock()
        self._events = []
        self._session_start = datetime.now()

        with open(self.log_path, "w") as f:
            f.write("=" * 100 + "\n")
            f.write("ISP SPY MIRROR — Session Log\n")
            f.write(f"Started: {self._session_start.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 100 + "\n")
            f.write(f"{'Time':<14} {'Type':<12} {'Subtype':<20} {'Destination':<30} {'Detail'}\n")
            f.write("-" * 100 + "\n")

    def log_event(self, event):
        with self._lock:
            self._events.append(event.copy())
            line = (
                f"{event.get('timestamp', ''):<14} "
                f"{event.get('type', ''):<12} "
                f"{event.get('subtype', ''):<20} "
                f"{event.get('destination', ''):<30} "
                f"{event.get('detail', '')}\n"
            )
            if event.get("sensitive"):
                line = f"*** {line.strip()} ***\n"
            try:
                with open(self.log_path, "a") as f:
                    f.write(line)
            except IOError:
                pass

    def write_summary(self, stats):
        duration = datetime.now() - self._session_start

        with self._lock:
            try:
                with open(self.log_path, "a") as f:
                    f.write("\n" + "=" * 100 + "\n")
                    f.write("SESSION SUMMARY\n")
                    f.write("=" * 100 + "\n")
                    f.write(f"Duration: {str(duration).split('.')[0]}\n")
                    f.write(f"Total events logged: {len(self._events)}\n\n")

                    dns = stats.get("dns", {})
                    f.write(f"DNS Queries: {dns.get('total_queries', 0)}\n")
                    f.write(f"Unique Domains: {dns.get('unique_domains', 0)}\n")
                    top_domains = dns.get("top_domains", [])
                    if top_domains:
                        f.write("Top Domains:\n")
                        for domain, count in top_domains:
                            f.write(f"  {count:>5}x  {domain}\n")
                    f.write("\n")

                    http = stats.get("http", {})
                    f.write(f"HTTP Requests (plaintext): {http.get('total_requests', 0)}\n")
                    f.write(f"Unique URLs: {http.get('unique_urls', 0)}\n")
                    user_agents = http.get("user_agents", [])
                    if user_agents:
                        f.write("User Agents:\n")
                        for ua in user_agents:
                            f.write(f"  - {ua}\n")
                    f.write("\n")

                    tls = stats.get("tls", {})
                    f.write(f"TLS Handshakes (SNI): {tls.get('total_handshakes', 0)}\n")
                    f.write(f"Unique HTTPS Domains: {tls.get('unique_domains', 0)}\n")
                    tls_domains = tls.get("domains", [])
                    if tls_domains:
                        f.write("HTTPS Domains:\n")
                        for d in sorted(tls_domains)[:50]:
                            f.write(f"  - {d}\n")
                    f.write("\n")

                    meta = stats.get("metadata", {})
                    f.write(f"Unique Destinations: {meta.get('unique_destinations', 0)}\n")
                    f.write(f"Bytes Sent: {meta.get('bytes_sent', 0):,}\n")
                    f.write(f"Bytes Received: {meta.get('bytes_received', 0):,}\n")

                    top_dests = meta.get("top_destinations", [])
                    if top_dests:
                        f.write("\nTop Destinations:\n")
                        for ip, count in top_dests[:20]:
                            f.write(f"  {count:>6}x  {ip}\n")

                    top_ports = meta.get("top_ports", [])
                    if top_ports:
                        f.write("\nTop Ports:\n")
                        for port, count, service in top_ports:
                            svc = f" ({service})" if service else ""
                            f.write(f"  {count:>6}x  port {port}{svc}\n")
                    f.write("\n")

                    leaks = stats.get("leaks", {})
                    f.write(f"Sensitive Leaks Detected: {leaks.get('total_leaks', 0)}\n")
                    f.write(f"  Critical: {leaks.get('critical_count', 0)}\n")
                    f.write(f"  Warnings: {leaks.get('warning_count', 0)}\n")
                    leak_types = leaks.get("leak_types", {})
                    if leak_types:
                        f.write("Leak Types:\n")
                        for ltype, count in leak_types.items():
                            f.write(f"  {count:>5}x  {ltype}\n")

                    f.write("\n" + "=" * 100 + "\n")
                    f.write("END OF SESSION\n")
                    f.write("=" * 100 + "\n")

                self._write_json(stats, duration)

            except IOError:
                pass

    def _write_json(self, stats, duration):
        try:
            output = {
                "session": {
                    "start": self._session_start.isoformat(),
                    "end": datetime.now().isoformat(),
                    "duration_seconds": duration.total_seconds(),
                },
                "statistics": stats,
                "events": self._events,
            }
            with open(self.json_path, "w") as f:
                json.dump(output, f, indent=2, default=str)
        except (IOError, TypeError):
            pass

    def get_event_count(self):
        with self._lock:
            return len(self._events)
