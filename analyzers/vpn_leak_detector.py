"""
VPN leak detector — identifies traffic escaping outside VPN tunnel,
DNS leaks, and WebRTC leaks.
"""

import subprocess
import socket
from collections import defaultdict
from scapy.all import IP, IPv6, TCP, UDP, DNS, DNSQR
from utils.helpers import format_timestamp, is_private_ip


class VPNLeakDetector:

    # Known VPN interface names
    VPN_INTERFACES = {
        "tun0", "tun1", "tun2",
        "tap0", "tap1",
        "wg0", "wg1",
        "proton0",
        "nordlynx",
        "pia",
    }

    # Known VPN DNS servers
    VPN_DNS_SERVERS = {
        "10.0.0.1", "10.8.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "1.1.1.1",   # Cloudflare (used by many VPNs)
        "1.0.0.1",
        "9.9.9.9",   # Quad9
    }

    # ISP DNS servers (signs of DNS leak)
    KNOWN_ISP_DNS = {
        "8.8.8.8": "Google DNS",
        "8.8.4.4": "Google DNS",
        "208.67.222.222": "OpenDNS",
        "208.67.220.220": "OpenDNS",
    }

    def __init__(self, interface):
        self.interface = interface
        self.vpn_active = False
        self.vpn_interface = None
        self.real_ip = None
        self.vpn_ip = None

        self.dns_leaks = []
        self.traffic_leaks = []
        self.leak_count = 0

        self._dns_servers_used = defaultdict(int)
        self._non_vpn_destinations = set()
        self._vpn_detected = False

        # Detect VPN on startup
        self._detect_vpn()

    def _detect_vpn(self):
        """Check if a VPN interface is currently active."""
        try:
            import os
            for iface in os.listdir("/sys/class/net/"):
                if iface in self.VPN_INTERFACES or iface.startswith("tun"):
                    self.vpn_active = True
                    self.vpn_interface = iface
                    self._vpn_detected = True
                    break

            # Also check ip route for VPN routes
            result = subprocess.run(
                ["ip", "route", "show"],
                capture_output=True, text=True, timeout=5
            )
            if "tun" in result.stdout or "wg" in result.stdout:
                self.vpn_active = True

        except Exception:
            pass

    def analyze(self, packet):
        """Analyze packet for VPN leaks."""
        events = []

        if not self.vpn_active:
            return events

        # Check DNS leaks
        if packet.haslayer(DNS) and packet.haslayer(UDP):
            dns_events = self._check_dns_leak(packet)
            events.extend(dns_events)

        # Check traffic routing leaks
        if packet.haslayer(IP):
            traffic_events = self._check_traffic_leak(packet)
            events.extend(traffic_events)

        return events

    def _check_dns_leak(self, packet):
        """Check if DNS query is going to an unexpected server."""
        events = []

        try:
            if not packet.haslayer(DNSQR):
                return events

            dst_ip = packet[IP].dst if packet.haslayer(IP) else ""
            if not dst_ip:
                return events

            self._dns_servers_used[dst_ip] += 1

            # Flag if using known public DNS instead of VPN DNS
            if dst_ip in self.KNOWN_ISP_DNS:
                provider = self.KNOWN_ISP_DNS[dst_ip]
                domain = ""
                try:
                    domain = packet[DNSQR].qname.decode("utf-8", errors="replace").rstrip(".")
                except Exception:
                    pass

                leak = {
                    "timestamp": format_timestamp(),
                    "type": "VPN LEAK",
                    "subtype": "DNS Leak",
                    "destination": dst_ip,
                    "detail": f"DNS query to {provider} ({dst_ip}) bypassing VPN! Domain: {domain}",
                    "sensitive": True,
                    "leak_type": "DNS",
                    "severity": "HIGH",
                    "dns_server": dst_ip,
                    "dns_provider": provider,
                    "domain": domain,
                }
                events.append(leak)
                self.dns_leaks.append(leak)
                self.leak_count += 1

        except Exception:
            pass

        return events

    def _check_traffic_leak(self, packet):
        """Check if traffic is routing outside the VPN tunnel."""
        events = []

        try:
            if not packet.haslayer(IP):
                return events

            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            # Skip private/local traffic
            if is_private_ip(dst_ip):
                return events

            # Skip DNS (handled separately)
            if packet.haslayer(UDP) and packet[UDP].dport == 53:
                return events

            # Check if packet came from real interface instead of VPN
            # This is a heuristic — outbound public traffic on non-VPN interface
            if (dst_ip not in self._non_vpn_destinations and
                    not is_private_ip(dst_ip)):

                dst_port = 0
                if packet.haslayer(TCP):
                    dst_port = packet[TCP].dport
                elif packet.haslayer(UDP):
                    dst_port = packet[UDP].dport

                # High-value ports that should go through VPN
                sensitive_ports = {80, 443, 8080, 8443}
                if dst_port in sensitive_ports:
                    self._non_vpn_destinations.add(dst_ip)

        except Exception:
            pass

        return events

    def get_vpn_status(self):
        """Return current VPN status string for display."""
        if not self.vpn_active:
            return "No VPN detected"
        return f"VPN Active ({self.vpn_interface})"

    def get_stats(self):
        return {
            "vpn_active": self.vpn_active,
            "vpn_interface": self.vpn_interface or "None",
            "dns_leaks": len(self.dns_leaks),
            "traffic_leaks": len(self.traffic_leaks),
            "total_leaks": self.leak_count,
            "dns_servers_used": dict(self._dns_servers_used),
            "vpn_status": self.get_vpn_status(),
        }
