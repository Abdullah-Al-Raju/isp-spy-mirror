"""
Connection metadata analyzer.
"""

from scapy.all import IP, IPv6, TCP, UDP, ICMP
from datetime import datetime
from collections import defaultdict
from utils.helpers import format_timestamp, is_private_ip


class MetadataAnalyzer:

    PORT_SERVICES = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
        443: "HTTPS", 465: "SMTPS", 587: "Submission",
        993: "IMAPS", 995: "POP3S", 853: "DNS-over-TLS",
        8080: "HTTP-Alt", 8443: "HTTPS-Alt",
        3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis",
        1194: "OpenVPN", 51820: "WireGuard",
        5222: "XMPP", 6667: "IRC", 9050: "Tor SOCKS",
        1723: "PPTP", 500: "IKE/IPsec",
    }

    UNENCRYPTED_PORTS = {21, 23, 25, 80, 110, 143, 8080}

    def __init__(self, local_ips=None, show_all=False):
        self.local_ips = local_ips or set()
        self.show_all = show_all
        self.connection_count = 0
        self.bytes_sent = 0
        self.bytes_received = 0
        self.destination_ips = defaultdict(int)
        self.destination_ports = defaultdict(int)
        self.protocols = defaultdict(int)
        self._seen_connections = set()
        self._last_metadata_time = {}

    def analyze(self, packet):
        events = []

        if not (packet.haslayer(IP) or packet.haslayer(IPv6)):
            return events

        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            proto_num = packet[IP].proto
            pkt_len = packet[IP].len
        else:
            src_ip = packet[IPv6].src
            dst_ip = packet[IPv6].dst
            proto_num = packet[IPv6].nh
            pkt_len = packet[IPv6].plen

        is_outbound = src_ip in self.local_ips
        is_inbound = dst_ip in self.local_ips

        if is_outbound:
            self.bytes_sent += pkt_len
        elif is_inbound:
            self.bytes_received += pkt_len

        protocol = self._get_protocol_name(proto_num)
        src_port = dst_port = 0

        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            protocol = "TCP"
        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            protocol = "UDP"
        elif packet.haslayer(ICMP):
            protocol = "ICMP"

        if not is_outbound:
            return events

        if dst_ip.startswith("224.") or dst_ip.startswith("255.") or dst_ip == "0.0.0.0":
            return events

        if not is_private_ip(dst_ip):
            self.destination_ips[dst_ip] += 1
        self.destination_ports[dst_port] += 1
        self.protocols[protocol] += 1

        conn_key = (dst_ip, dst_port, protocol)
        is_new = conn_key not in self._seen_connections
        is_syn = (packet.haslayer(TCP) and
                  packet[TCP].flags & 0x02 and
                  not packet[TCP].flags & 0x10)

        if not is_new and not is_syn and not self.show_all:
            return events

        self._seen_connections.add(conn_key)

        now = datetime.now()
        if conn_key in self._last_metadata_time:
            elapsed = (now - self._last_metadata_time[conn_key]).total_seconds()
            if elapsed < 2 and not is_syn:
                return events
        self._last_metadata_time[conn_key] = now

        if is_private_ip(dst_ip) and not self.show_all:
            return events

        if dst_port == 53:
            return events

        self.connection_count += 1

        service = self.PORT_SERVICES.get(dst_port, "")
        service_str = f" ({service})" if service else ""
        is_unencrypted = dst_port in self.UNENCRYPTED_PORTS
        connection_type = "NEW" if is_syn else "→"
        detail = f"{connection_type} {protocol}/{dst_port}{service_str}"
        if is_syn:
            detail += " [SYN]"

        if dst_port in (80, 443, 8080, 8443) and not self.show_all:
            return events

        events.append({
            "timestamp": format_timestamp(),
            "type": "META",
            "subtype": protocol,
            "destination": f"{dst_ip}:{dst_port}",
            "detail": detail,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "protocol": protocol,
            "sensitive": is_unencrypted and dst_port != 53,
        })

        return events

    def _get_protocol_name(self, proto_num):
        protos = {1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP"}
        return protos.get(proto_num, f"Proto-{proto_num}")

    def get_stats(self):
        top_dests = sorted(
            self.destination_ips.items(),
            key=lambda x: x[1], reverse=True
        )[:15]

        top_ports = sorted(
            self.destination_ports.items(),
            key=lambda x: x[1], reverse=True
        )[:10]

        return {
            "total_connections": self.connection_count,
            "unique_destinations": len(self.destination_ips),
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "top_destinations": top_dests,
            "top_ports": [(p, c, self.PORT_SERVICES.get(p, "")) for p, c in top_ports],
            "protocols": dict(self.protocols),
        }
