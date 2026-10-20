"""
Packet capture engine — full intelligence edition.
"""

from scapy.all import sniff, conf, IP, IPv6, TCP, UDP, Raw
from threading import Thread, Event
from queue import Queue, Empty
from datetime import datetime

from analyzers import (
    DNSAnalyzer,
    HTTPAnalyzer,
    TLSAnalyzer,
    MetadataAnalyzer,
    SensitiveDetector,
    FingerprintAnalyzer,
    TrackerAnalyzer,
    VPNLeakDetector,
    DNSSpoofDetector,
    BehaviorAnalyzer,
)
from resolvers import HostnameResolver, GeoResolver
from logger.session_logger import SessionLogger
from data.database import Database
from reports.pcap_export import PCAPExport
from utils.helpers import get_local_ips, format_timestamp, is_private_ip
from simulation.traffic_generator import SyntheticTrafficGenerator
import time


class CaptureEngine:

    def __init__(self, interface="eth0", duration=None, show_all=False,
                 geo_enabled=True, output_path=None, db_path="isp_spy.db",
                 simulate=False, pcap_file=None):
        self.interface = interface or "eth0"
        self.duration = duration
        self.show_all = show_all
        self.simulate = simulate
        self.pcap_file = pcap_file

        self.local_ips = get_local_ips()
        self.local_ips.add(SyntheticTrafficGenerator.LOCAL_IP)
        self.local_ips.add("127.0.0.1")

        # Analyzers
        self.dns_analyzer = DNSAnalyzer()
        self.http_analyzer = HTTPAnalyzer()
        self.tls_analyzer = TLSAnalyzer()
        self.metadata_analyzer = MetadataAnalyzer(
            local_ips=self.local_ips, show_all=show_all
        )
        self.sensitive_detector = SensitiveDetector()
        self.fingerprint_analyzer = FingerprintAnalyzer()
        self.tracker_analyzer = TrackerAnalyzer()
        self.vpn_leak_detector = VPNLeakDetector(interface=self.interface)
        self.dns_spoof_detector = DNSSpoofDetector()
        self.behavior_analyzer = BehaviorAnalyzer()

        # Resolvers
        self.hostname_resolver = HostnameResolver()
        self.geo_resolver = GeoResolver(enabled=geo_enabled and not simulate)

        # Storage
        self.session_logger = SessionLogger(output_path=output_path)
        self.db = Database(db_path=db_path)
        session_label = f"sim-{self.interface}" if simulate else (f"pcap-{pcap_file}" if pcap_file else self.interface)
        self.session_id = self.db.create_session(interface=session_label)
        self.pcap_exporter = PCAPExport()

        # Event queue
        self.event_queue = Queue(maxsize=10000)

        # Control
        self._stop_event = Event()
        self._paused = False
        self._capture_thread = None
        self._start_time = None
        self.packet_count = 0
        self.simulation_generator = None

        if self.simulate:
            self.simulation_generator = SyntheticTrafficGenerator(
                packet_callback=self._process_packet, rate=2.0
            )

        # Noise filter
        self._noisy_domains = {
            "connectivity-check", "detectportal", "captive.apple",
            "msftconnecttest", "nmcheck", "pool.ntp.org",
        }

    def start(self):
        self._start_time = datetime.now()
        self.geo_resolver.start()
        self.dns_spoof_detector.start()
        self._capture_thread = Thread(target=self._capture_loop, daemon=True)
        self._capture_thread.start()

    def stop(self):
        self._stop_event.set()
        if self.simulation_generator:
            self.simulation_generator.stop()
        self.geo_resolver.stop()
        self.dns_spoof_detector.stop()
        if self._capture_thread:
            self._capture_thread.join(timeout=5)

        stats = self.get_all_stats()
        self.session_logger.write_summary(stats)
        self.db.close_session(self.session_id, stats)
        self.db.close()

        # Export PCAP
        pcap_path = self.pcap_exporter.export(session_id=self.session_id)

        return stats, pcap_path

    def pause(self):
        self._paused = True
        if self.simulation_generator:
            self.simulation_generator.pause()

    def resume(self):
        self._paused = False
        if self.simulation_generator:
            self.simulation_generator.resume()

    def is_paused(self):
        return self._paused

    def inject_scenario(self, scenario_name):
        if not self.simulation_generator:
            self.simulation_generator = SyntheticTrafficGenerator(
                packet_callback=self._process_packet
            )
        if scenario_name in ("credential_leak", "auth_leak"):
            return self.simulation_generator.inject_credential_leak()
        elif scenario_name == "jwt_leak":
            return self.simulation_generator.inject_jwt_leak()
        elif scenario_name == "aws_leak":
            return self.simulation_generator.inject_aws_leak()
        elif scenario_name == "vpn_leak":
            return self.simulation_generator.inject_vpn_dns_leak()
        elif scenario_name == "tracker_storm":
            return self.simulation_generator.inject_tracker_storm()
        elif scenario_name == "ech_handshake":
            return self.simulation_generator.inject_ech_handshake()
        return None

    def is_running(self):
        if self._stop_event.is_set():
            return False
        if self.duration and self._start_time:
            elapsed = (datetime.now() - self._start_time).total_seconds()
            if elapsed >= self.duration:
                return False
        return True

    def get_event(self, timeout=0.1):
        try:
            return self.event_queue.get(timeout=timeout)
        except Empty:
            return None

    def _capture_loop(self):
        try:
            conf.verb = 0
            if self.simulate:
                self.simulation_generator.start()
                while not self._stop_event.is_set():
                    time.sleep(0.1)
                self.simulation_generator.stop()
            elif self.pcap_file:
                sniff(
                    offline=self.pcap_file,
                    prn=self._process_packet,
                    store=False,
                    stop_filter=lambda _: self._stop_event.is_set(),
                )
            else:
                sniff(
                    iface=self.interface,
                    prn=self._process_packet,
                    store=False,
                    stop_filter=lambda _: self._stop_event.is_set(),
                    filter="ip or ip6",
                )
        except PermissionError:
            self._emit_error("Permission denied. Run with sudo or use --demo mode.")
        except OSError as e:
            self._emit_error(f"Capture error: {e}")
        except Exception as e:
            self._emit_error(f"Unexpected error: {e}")

    def _process_packet(self, packet):
        if self._paused:
            return
        self.packet_count += 1

        if not self._is_our_traffic(packet):
            return

        # Save to PCAP buffer
        try:
            self.pcap_exporter.add_packet(packet)
        except Exception:
            pass

        events = []

        # Run all analyzers
        for analyzer in [
            self.dns_analyzer,
            self.http_analyzer,
            self.tls_analyzer,
            self.metadata_analyzer,
            self.vpn_leak_detector,
            self.dns_spoof_detector,
            self.fingerprint_analyzer,
        ]:
            try:
                events.extend(analyzer.analyze(packet))
            except Exception:
                pass

        # Sensitive data scan on raw payload
        if packet.haslayer(Raw) and packet.haslayer(TCP):
            try:
                payload = bytes(packet[Raw].load)
                dst_ip = ""
                dst_port = packet[TCP].dport
                if packet.haslayer(IP):
                    dst_ip = packet[IP].dst

                if dst_port not in (443, 8443, 993, 995, 465):
                    leaks = self.sensitive_detector.scan_raw_payload(
                        payload, dst_ip=dst_ip, dst_port=dst_port
                    )
                    for leak in leaks:
                        leak["timestamp"] = format_timestamp()
                    events.extend(leaks)
            except Exception:
                pass

        # HTTP event deep scan
        for event in list(events):
            if event.get("type") == "HTTP" and event.get("subtype") == "Request":
                try:
                    leaks = self.sensitive_detector.scan_http_event(event)
                    events.extend(leaks)
                except Exception:
                    pass

        # Tracker detection on DNS and TLS events
        for event in list(events):
            domain = event.get("domain", "")
            if domain and event.get("type") in ("DNS", "TLS"):
                try:
                    tracker_event = self.tracker_analyzer.analyze_domain(domain, event)
                    if tracker_event:
                        events.append(tracker_event)
                except Exception:
                    pass

        # User-Agent fingerprinting from HTTP
        for event in list(events):
            if event.get("type") == "HTTP":
                headers = event.get("headers", {})
                ua = headers.get("user-agent", "")
                if ua:
                    try:
                        ua_fp = self.fingerprint_analyzer.analyze_user_agent(ua)
                        if ua_fp:
                            events.append(ua_fp)
                    except Exception:
                        pass

        # Behavioral analysis
        for event in list(events):
            try:
                behavior_event = self.behavior_analyzer.analyze_event(event)
                if behavior_event:
                    events.append(behavior_event)
            except Exception:
                pass

        # Record bandwidth
        pkt_len = 0
        if packet.haslayer(IP):
            pkt_len = packet[IP].len or len(packet)
            is_outbound = packet[IP].src in self.local_ips
        elif packet.haslayer(IPv6):
            pkt_len = packet[IPv6].plen or len(packet)
            is_outbound = packet[IPv6].src in self.local_ips
        else:
            is_outbound = False

        if pkt_len and pkt_len > 0:
            self.behavior_analyzer.record_bytes(
                pkt_len, "sent" if is_outbound else "received"
            )

        # Filter noisy traffic
        if not self.show_all:
            events = [e for e in events if not self._is_noisy(e)]

        # Enrich and emit
        for event in events:
            self._enrich_event(event)
            self.session_logger.log_event(event)
            self.db.insert_event(self.session_id, event)

            if "LEAK" in event.get("type", ""):
                self.db.insert_leak(self.session_id, event)
            if event.get("type") == "FINGERPRINT":
                self.db.insert_fingerprint(self.session_id, event)

            try:
                self.event_queue.put_nowait(event)
            except Exception:
                try:
                    self.event_queue.get_nowait()
                    self.event_queue.put_nowait(event)
                except Exception:
                    pass

    def _is_our_traffic(self, packet):
        if self.simulate or self.pcap_file:
            return True
        if packet.haslayer(IP):
            return (packet[IP].src in self.local_ips or
                    packet[IP].dst in self.local_ips)
        if packet.haslayer(IPv6):
            return (packet[IPv6].src in self.local_ips or
                    packet[IPv6].dst in self.local_ips)
        return False

    def _is_noisy(self, event):
        domain = event.get("raw_domain", "").lower()
        if domain:
            for noisy in self._noisy_domains:
                if noisy in domain:
                    return True
        return False

    def _enrich_event(self, event):
        dest = event.get("destination", "")
        ip = dest.split(":")[0] if ":" in dest else dest

        if ip and not is_private_ip(ip):
            self.geo_resolver.request_lookup(ip)
            geo_str = self.geo_resolver.get_location_string(ip)
            if geo_str:
                event["geo"] = geo_str
            hostname = self.hostname_resolver.resolve(ip)
            if hostname:
                event["hostname"] = hostname

        domain = event.get("domain", "")
        if domain:
            category = ""
            is_tracker = False
            if event.get("type") == "TRACKER":
                category = event.get("category", "Unknown")
                is_tracker = True
            self.db.update_domain(
                self.session_id, domain, category, is_tracker, False
            )

    def _emit_error(self, message):
        event = {
            "timestamp": format_timestamp(),
            "type": "ERROR",
            "subtype": "System",
            "destination": "",
            "detail": message,
            "sensitive": False,
        }
        try:
            self.event_queue.put_nowait(event)
        except Exception:
            pass

    def get_privacy_score(self):
        """Calculate dynamic privacy health score (0-100) and letter grade."""
        score = 100
        deductions = []

        # 1. Plaintext Sensitive Credential Leaks (-20 each, max -50)
        leak_stats = self.sensitive_detector.get_stats()
        total_leaks = leak_stats.get("total_leaks", 0)
        critical_leaks = leak_stats.get("critical_count", 0)
        if critical_leaks > 0:
            penalty = min(50, critical_leaks * 20)
            score -= penalty
            deductions.append(f"Critical credential / secret leaks ({critical_leaks} detected: -{penalty})")
        elif total_leaks > 0:
            penalty = min(20, total_leaks * 5)
            score -= penalty
            deductions.append(f"Plaintext sensitive warnings ({total_leaks} detected: -{penalty})")

        # 2. VPN DNS Leaks & Spoofing (-30)
        vpn_stats = self.vpn_leak_detector.get_stats()
        vpn_leaks = vpn_stats.get("total_leaks", 0)
        if vpn_leaks > 0:
            penalty = min(30, vpn_leaks * 15)
            score -= penalty
            deductions.append(f"DNS queries bypassing VPN tunnel ({vpn_leaks} leaks: -{penalty})")

        dns_spoof_stats = self.dns_spoof_detector.get_stats()
        spoofs = dns_spoof_stats.get("spoofs_detected", 0)
        if spoofs > 0:
            score -= 25
            deductions.append("DNS spoofing / tampering detected: -25")

        # 3. Trackers & Ad Network Profiling (-2 per unique tracker domain, max -20)
        tracker_stats = self.tracker_analyzer.get_stats()
        unique_trackers = tracker_stats.get("unique_trackers", 0)
        if unique_trackers > 0:
            penalty = min(20, unique_trackers * 2)
            score -= penalty
            deductions.append(f"Ad networks & profiling trackers ({unique_trackers} domains: -{penalty})")

        # 4. Plaintext HTTP Traffic (-2 per request, max -15)
        http_stats = self.http_analyzer.get_stats()
        http_requests = http_stats.get("total_requests", 0)
        if http_requests > 0:
            penalty = min(15, http_requests * 2)
            score -= penalty
            deductions.append(f"Unencrypted HTTP requests visible to ISP ({http_requests} reqs: -{penalty})")

        # 5. TLS SNI vs ECH (-10 if SNI leaked without ECH, +5 bonus if ECH active)
        tls_stats = self.tls_analyzer.get_stats()
        total_tls = tls_stats.get("total_handshakes", 0)
        ech_tls = tls_stats.get("ech_protected_handshakes", 0)
        if total_tls > 0 and ech_tls == 0:
            score -= 10
            deductions.append("TLS SNI exposed in cleartext without ECH: -10")
        elif ech_tls > 0:
            score = min(100, score + 5)

        score = max(0, min(100, score))

        if score >= 90:
            grade = "A+"
            status = "EXCELLENT"
            color = "#00ff88"
        elif score >= 80:
            grade = "A"
            status = "GOOD"
            color = "#00e5ff"
        elif score >= 70:
            grade = "B"
            status = "MODERATE"
            color = "#ffea00"
        elif score >= 55:
            grade = "C"
            status = "POOR"
            color = "#ff9100"
        elif score >= 40:
            grade = "D"
            status = "CRITICAL"
            color = "#ff3d00"
        else:
            grade = "F"
            status = "COMPROMISED"
            color = "#ff1744"

        return {
            "score": score,
            "grade": grade,
            "status": status,
            "color": color,
            "deductions": deductions,
            "critical_leaks": critical_leaks,
            "vpn_leaks": vpn_leaks,
            "trackers_detected": unique_trackers,
            "ech_protected": ech_tls,
            "plaintext_http": http_requests,
        }

    def get_all_stats(self):
        return {
            "dns": self.dns_analyzer.get_stats(),
            "http": self.http_analyzer.get_stats(),
            "tls": self.tls_analyzer.get_stats(),
            "metadata": self.metadata_analyzer.get_stats(),
            "leaks": self.sensitive_detector.get_stats(),
            "fingerprint": self.fingerprint_analyzer.get_stats(),
            "tracker": self.tracker_analyzer.get_stats(),
            "vpn_leak": self.vpn_leak_detector.get_stats(),
            "dns_spoof": self.dns_spoof_detector.get_stats(),
            "behavior": self.behavior_analyzer.get_stats(),
            "resolver": self.hostname_resolver.get_cache_stats(),
            "geo": self.geo_resolver.get_stats(),
            "privacy_score": self.get_privacy_score(),
            "packets_captured": self.packet_count,
            "events_logged": self.session_logger.get_event_count(),
        }

    def get_elapsed(self):
        if self._start_time:
            return datetime.now() - self._start_time
        return None
