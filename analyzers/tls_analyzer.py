"""
TLS/SSL analyzer — extracts Server Name Indication (SNI) from HTTPS handshakes.
"""

from scapy.all import TCP, IP, IPv6, Raw
from utils.helpers import format_timestamp
import struct


class TLSAnalyzer:

    TLS_HANDSHAKE = 22
    CLIENT_HELLO = 1
    ECH_EXTENSION_TYPES = {0xFE0D, 0xFE08, 0xFE09, 0xFE07}

    def __init__(self):
        self.sni_count = 0
        self.ech_count = 0
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

        parsed_tls = self._parse_client_hello(payload)
        if parsed_tls and parsed_tls.get("sni"):
            sni = parsed_tls["sni"]
            ech_present = parsed_tls.get("ech", False)
            alpn = parsed_tls.get("alpn", "")
            tls_version = parsed_tls.get("version") or self._extract_tls_version(payload)

            dst_ip = ""
            if packet.haslayer(IP):
                dst_ip = packet[IP].dst
            elif packet.haslayer(IPv6):
                dst_ip = packet[IPv6].dst

            self.sni_count += 1
            if ech_present:
                self.ech_count += 1
            self.domains_seen.add(sni.lower())
            self.connections.append({
                "domain": sni,
                "ip": dst_ip,
                "port": tcp.dport,
                "ech": ech_present,
                "alpn": alpn,
            })

            version_str = f" [{tls_version}]" if tls_version else ""
            ech_tag = " [ECH Protected]" if ech_present else " [Plaintext SNI Exposed]"
            alpn_tag = f" ({alpn})" if alpn else ""

            events.append({
                "timestamp": format_timestamp(),
                "type": "TLS",
                "subtype": "SNI (ECH Protected)" if ech_present else "SNI (Exposed)",
                "destination": f"{dst_ip}:{tcp.dport}",
                "detail": f"Target: {sni}{version_str}{alpn_tag}{ech_tag}",
                "domain": sni,
                "sensitive": False,
                "raw_domain": sni.lower(),
                "ech": ech_present,
                "alpn": alpn,
            })

        return events

    def _parse_client_hello(self, payload):
        """Parse ClientHello to extract SNI, ECH presence, ALPN, and extensions."""
        result = {"sni": None, "ech": False, "alpn": None, "version": None}
        try:
            if len(payload) < 6:
                return None
            if payload[0] != self.TLS_HANDSHAKE or payload[5] != self.CLIENT_HELLO:
                return None

            pos = 43  # 5 (record) + 1 (type) + 3 (len) + 2 (ver) + 32 (random)
            if pos >= len(payload):
                return None

            session_id_len = payload[pos]
            pos += 1 + session_id_len

            if pos + 2 > len(payload):
                return None
            ciphers_len = struct.unpack("!H", payload[pos:pos + 2])[0]
            pos += 2 + ciphers_len

            if pos + 1 > len(payload):
                return None
            comp_len = payload[pos]
            pos += 1 + comp_len

            if pos + 2 > len(payload):
                return None
            ext_len = struct.unpack("!H", payload[pos:pos + 2])[0]
            pos += 2
            ext_end = pos + ext_len

            while pos + 4 <= ext_end and pos + 4 <= len(payload):
                ext_type = struct.unpack("!H", payload[pos:pos + 2])[0]
                ext_l = struct.unpack("!H", payload[pos + 2:pos + 4])[0]
                pos += 4

                if ext_type == 0:  # Server Name Indication
                    if pos + 5 <= len(payload):
                        sni_type = payload[pos + 2]
                        s_len = struct.unpack("!H", payload[pos + 3:pos + 5])[0]
                        if sni_type == 0 and pos + 5 + s_len <= len(payload):
                            result["sni"] = payload[pos + 5:pos + 5 + s_len].decode("ascii", errors="replace")

                elif ext_type in self.ECH_EXTENSION_TYPES:
                    result["ech"] = True

                elif ext_type == 16:  # ALPN
                    try:
                        alpn_list_len = struct.unpack("!H", payload[pos:pos + 2])[0]
                        cur = pos + 2
                        protocols = []
                        while cur < pos + 2 + alpn_list_len and cur < len(payload):
                            p_len = payload[cur]
                            cur += 1
                            proto = payload[cur:cur + p_len].decode("ascii", errors="replace")
                            cur += p_len
                            protocols.append(proto)
                        if protocols:
                            result["alpn"] = ",".join(protocols)
                    except Exception:
                        pass

                pos += ext_l

            return result

        except Exception:
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
            "ech_protected_handshakes": self.ech_count,
            "plaintext_sni_handshakes": max(0, self.sni_count - self.ech_count),
            "ech_protection_rate": f"{(self.ech_count / self.sni_count * 100):.1f}%" if self.sni_count > 0 else "0.0%",
            "unique_domains": len(self.domains_seen),
            "domains": list(self.domains_seen),
        }
