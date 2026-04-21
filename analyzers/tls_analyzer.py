"""
TLS/SSL analyzer — extracts Server Name Indication (SNI) from HTTPS handshakes.
"""

from scapy.all import TCP, IP, IPv6, Raw
from utils.helpers import format_timestamp
import struct


class TLSAnalyzer:

    TLS_HANDSHAKE = 22
    CLIENT_HELLO = 1

    def __init__(self):
        self.sni_count = 0
        self.domains_seen = set()
        self.connections = []

    def analyze(self, packet):
        events = []

        if not packet.haslayer(TCP) or not packet.haslayer(Raw):
            return events

        tcp = packet[TCP]
        payload = bytes(packet[Raw].load)

        if tcp.dport not in (443, 8443, 993, 995, 465, 587):
            return events

        sni = self._extract_sni(payload)
        if sni:
            dst_ip = ""
            if packet.haslayer(IP):
                dst_ip = packet[IP].dst
            elif packet.haslayer(IPv6):
                dst_ip = packet[IPv6].dst

            self.sni_count += 1
            self.domains_seen.add(sni.lower())
            self.connections.append({
                "domain": sni,
                "ip": dst_ip,
                "port": tcp.dport,
            })

            tls_version = self._extract_tls_version(payload)
            version_str = f" [{tls_version}]" if tls_version else ""

            events.append({
                "timestamp": format_timestamp(),
                "type": "TLS",
                "subtype": "SNI",
                "destination": f"{dst_ip}:{tcp.dport}",
                "detail": f"Connecting to: {sni}{version_str}",
                "domain": sni,
                "sensitive": False,
                "raw_domain": sni.lower(),
            })

        return events

    def _extract_sni(self, payload):
        try:
            if len(payload) < 6:
                return None

            if payload[0] != self.TLS_HANDSHAKE:
                return None

            if payload[5] != self.CLIENT_HELLO:
                return None

            pos = 5 + 1 + 3 + 2 + 32  # = 43

            if pos >= len(payload):
                return None

            session_id_length = payload[pos]
            pos += 1 + session_id_length

            if pos + 2 > len(payload):
                return None

            cipher_suites_length = struct.unpack("!H", payload[pos:pos + 2])[0]
            pos += 2 + cipher_suites_length

            if pos + 1 > len(payload):
                return None

            compression_length = payload[pos]
            pos += 1 + compression_length

            if pos + 2 > len(payload):
                return None

            extensions_length = struct.unpack("!H", payload[pos:pos + 2])[0]
            pos += 2
            extensions_end = pos + extensions_length

            while pos + 4 < extensions_end and pos + 4 < len(payload):
                ext_type = struct.unpack("!H", payload[pos:pos + 2])[0]
                ext_length = struct.unpack("!H", payload[pos + 2:pos + 4])[0]
                pos += 4

                if ext_type == 0:
                    if pos + 5 <= len(payload):
                        sni_type = payload[pos + 2]
                        sni_length = struct.unpack("!H", payload[pos + 3:pos + 5])[0]
                        if sni_type == 0 and pos + 5 + sni_length <= len(payload):
                            sni = payload[pos + 5:pos + 5 + sni_length]
                            return sni.decode("ascii", errors="replace")

                pos += ext_length

        except (struct.error, IndexError, ValueError):
            pass

        return None

    def _extract_tls_version(self, payload):
        try:
            if len(payload) >= 5:
                major = payload[1]
                minor = payload[2]
                versions = {
                    (3, 0): "SSL 3.0",
                    (3, 1): "TLS 1.0",
                    (3, 2): "TLS 1.1",
                    (3, 3): "TLS 1.2/1.3",
                }
                return versions.get((major, minor), f"Unknown ({major}.{minor})")
        except IndexError:
            pass
        return None

    def get_stats(self):
        return {
            "total_handshakes": self.sni_count,
            "unique_domains": len(self.domains_seen),
            "domains": list(self.domains_seen),
        }
