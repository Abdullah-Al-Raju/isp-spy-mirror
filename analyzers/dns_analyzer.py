"""
DNS query analyzer — extracts every domain name lookup.
"""

from scapy.all import DNS, DNSQR, DNSRR, IP, IPv6
from datetime import datetime
from utils.helpers import format_timestamp


class DNSAnalyzer:
    """Parses DNS packets to extract domain lookups and responses."""

    RECORD_TYPES = {
        1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
        15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV",
        43: "DS", 46: "RRSIG", 47: "NSEC", 48: "DNSKEY",
        65: "HTTPS", 257: "CAA",
    }

    def __init__(self):
        self.query_count = 0
        self.domains_seen = set()
        self.query_log = []

    def analyze(self, packet):
        events = []

        if not packet.haslayer(DNS):
            return events

        dns_layer = packet[DNS]

        if dns_layer.qr == 0 and dns_layer.haslayer(DNSQR):
            event = self._parse_query(packet, dns_layer)
            if event:
                events.append(event)

        if dns_layer.qr == 1 and dns_layer.ancount > 0:
            response_event = self._parse_response(packet, dns_layer)
            if response_event:
                events.append(response_event)

        return events

    def _parse_query(self, packet, dns_layer):
        try:
            qname = dns_layer[DNSQR].qname.decode("utf-8", errors="replace").rstrip(".")
            qtype_num = dns_layer[DNSQR].qtype
            qtype = self.RECORD_TYPES.get(qtype_num, str(qtype_num))
        except (AttributeError, UnicodeDecodeError):
            return None

        if not qname or qname == ".":
            return None

        self.query_count += 1
        self.domains_seen.add(qname.lower())

        dst_ip = ""
        if packet.haslayer(IP):
            dst_ip = packet[IP].dst
        elif packet.haslayer(IPv6):
            dst_ip = packet[IPv6].dst

        event = {
            "timestamp": format_timestamp(),
            "type": "DNS",
            "subtype": "Query",
            "destination": dst_ip,
            "detail": f"{qname} ({qtype})",
            "domain": qname,
            "query_type": qtype,
            "sensitive": False,
            "raw_domain": qname.lower(),
        }

        self.query_log.append({
            "time": datetime.now(),
            "domain": qname,
            "type": qtype,
            "server": dst_ip,
        })

        return event

    def _parse_response(self, packet, dns_layer):
        try:
            qname = dns_layer[DNSQR].qname.decode("utf-8", errors="replace").rstrip(".")
        except (AttributeError, UnicodeDecodeError):
            return None

        resolved = []
        for i in range(dns_layer.ancount):
            try:
                rr = dns_layer.an[i]
                if hasattr(rr, "rdata"):
                    rdata = rr.rdata
                    if isinstance(rdata, bytes):
                        rdata = rdata.decode("utf-8", errors="replace")
                    resolved.append(str(rdata).rstrip("."))
            except (IndexError, AttributeError):
                continue

        if not resolved:
            return None

        src_ip = ""
        if packet.haslayer(IP):
            src_ip = packet[IP].src
        elif packet.haslayer(IPv6):
            src_ip = packet[IPv6].src

        resolved_str = ", ".join(resolved[:4])
        if len(resolved) > 4:
            resolved_str += f" (+{len(resolved) - 4} more)"

        return {
            "timestamp": format_timestamp(),
            "type": "DNS",
            "subtype": "Response",
            "destination": src_ip,
            "detail": f"{qname} → {resolved_str}",
            "domain": qname,
            "resolved_ips": resolved,
            "sensitive": False,
            "raw_domain": qname.lower(),
        }

    def get_stats(self):
        return {
            "total_queries": self.query_count,
            "unique_domains": len(self.domains_seen),
            "top_domains": self._get_top_domains(10),
        }

    def _get_top_domains(self, n=10):
        from collections import Counter
        base_domains = []
        for entry in self.query_log:
            domain = entry["domain"].lower()
            parts = domain.split(".")
            base = ".".join(parts[-2:]) if len(parts) >= 2 else domain
            base_domains.append(base)
        return Counter(base_domains).most_common(n)
