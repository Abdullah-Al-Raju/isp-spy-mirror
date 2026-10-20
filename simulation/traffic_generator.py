"""
Synthetic privacy traffic generator for ISP Spy Mirror.
Enables full-fidelity simulation of network traffic, privacy leaks,
trackers, TLS handshakes, and VPN bypasses without root privileges.
"""

import time
import random
import struct
from threading import Thread, Event
from scapy.all import IP, TCP, UDP, DNS, DNSQR, DNSRR, Raw


class SyntheticTrafficGenerator:
    """Generates authentic Scapy network packets for simulation, testing, and demonstration."""

    LOCAL_IP = "192.168.1.105"
    GATEWAY_IP = "192.168.1.1"

    SAMPLE_DOMAINS = [
        "github.com",
        "google.com",
        "wikipedia.org",
        "duckduckgo.com",
        "reddit.com",
        "news.ycombinator.com",
        "stackoverflow.com",
        "archlinux.org",
    ]

    SAMPLE_TRACKERS = [
        ("google-analytics.com", "Google Analytics", "Tracking"),
        ("facebook.net", "Meta Pixel", "Advertising"),
        ("doubleclick.net", "Google DoubleClick", "Advertising"),
        ("criteo.com", "Criteo", "Retargeting"),
        ("scorecardresearch.com", "Full Circle Studies", "Market Research"),
        ("hotjar.com", "Hotjar", "Session Recording"),
        ("appsflyer.com", "AppsFlyer", "Mobile Analytics"),
    ]

    SAMPLE_LEAKS = [
        ("auth", b"POST /api/v1/auth/login HTTP/1.1\r\nHost: legacy-portal.local\r\nContent-Type: application/x-www-form-urlencoded\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64)\r\nAuthorization: Basic YWRtaW46U3VwZXJTZWNyZXQxMjM=\r\n\r\nusername=admin&password=SuperSecretPassword2026!"),
        ("jwt", b"GET /v2/user/profile HTTP/1.1\r\nHost: api.legacy-shop.org\r\nAuthorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFsaWNlIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n\r\n"),
        ("aws", b"POST /upload HTTP/1.1\r\nHost: unencrypted-s3-proxy.net\r\nUser-Agent: curl/8.2.1\r\nX-Amz-Security-Token: AKIAIOSFODNN7EXAMPLE\r\n\r\naccess_key=AKIAIOSFODNN7EXAMPLE&secret_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
        ("cookie", b"GET /dashboard HTTP/1.1\r\nHost: forum.insecure-community.org\r\nCookie: session=sess_993847291048572; user=john_doe; auth_token=9fa87cb1a\r\nUser-Agent: Mozilla/5.0\r\n\r\n"),
    ]

    def __init__(self, packet_callback, rate=1.5):
        self.packet_callback = packet_callback
        self.rate = rate
        self._stop_event = Event()
        self._thread = None
        self._paused = False

    def start(self):
        self._stop_event.clear()
        self._paused = False
        self._thread = Thread(target=self._run_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=2)

    def pause(self):
        self._paused = True

    def resume(self):
        self._paused = False

    def is_running(self):
        return self._thread is not None and self._thread.is_alive() and not self._stop_event.is_set()

    def _run_loop(self):
        while not self._stop_event.is_set():
            if not self._paused:
                try:
                    pkt = self._generate_random_packet()
                    if pkt and self.packet_callback:
                        self.packet_callback(pkt)
                except Exception:
                    pass

            interval = (1.0 / self.rate) if self.rate > 0 else 0.5
            time.sleep(interval * random.uniform(0.6, 1.4))

    def _generate_random_packet(self):
        choice = random.choices(
            ["dns", "tls_sni", "tls_ech", "tracker", "plaintext_http", "vpn_leak"],
            weights=[30, 25, 15, 15, 10, 5],
            k=1
        )[0]

        if choice == "dns":
            domain = random.choice(self.SAMPLE_DOMAINS)
            return self.build_dns_query_packet(domain)
        elif choice == "tls_sni":
            domain = random.choice(self.SAMPLE_DOMAINS)
            return self.build_tls_client_hello_packet(domain, ech=False)
        elif choice == "tls_ech":
            domain = random.choice(["cloudflare.com", "crypto.cloudflare.com", "defcon.org"])
            return self.build_tls_client_hello_packet(domain, ech=True)
        elif choice == "tracker":
            tracker_domain, _, _ = random.choice(self.SAMPLE_TRACKERS)
            return self.build_dns_query_packet(tracker_domain)
        elif choice == "plaintext_http":
            _, payload = random.choice(self.SAMPLE_LEAKS)
            return self.build_http_packet(payload)
        elif choice == "vpn_leak":
            return self.build_dns_query_packet("confidential-research.corp", server_ip="8.8.8.8")
        return None

    def build_dns_query_packet(self, domain, server_ip="1.1.1.1", client_ip=None):
        src_ip = client_ip or self.LOCAL_IP
        sport = random.randint(40000, 65000)
        pkt = (
            IP(src=src_ip, dst=server_ip)
            / UDP(sport=sport, dport=53)
            / DNS(rd=1, qd=DNSQR(qname=domain, qtype="A"))
        )
        return pkt

    def build_http_packet(self, payload_bytes, client_ip=None, dst_ip="93.184.216.34", dst_port=80):
        src_ip = client_ip or self.LOCAL_IP
        sport = random.randint(40000, 65000)
        pkt = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=sport, dport=dst_port, flags="PA", seq=1000, ack=1)
            / Raw(load=payload_bytes)
        )
        return pkt

    def build_tls_client_hello_packet(self, domain, ech=False, client_ip=None, dst_ip="104.21.5.12", dst_port=443):
        src_ip = client_ip or self.LOCAL_IP
        sport = random.randint(40000, 65000)
        raw_hello = self._craft_tls_client_hello_bytes(domain, ech=ech)
        pkt = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=sport, dport=dst_port, flags="PA", seq=5000, ack=1)
            / Raw(load=raw_hello)
        )
        return pkt

    def _craft_tls_client_hello_bytes(self, domain, ech=False):
        """Build synthetic TLS ClientHello with SNI and optional ECH."""
        sni_bytes = domain.encode("ascii")
        sni_entry = b"\x00" + struct.pack("!H", len(sni_bytes)) + sni_bytes
        sni_list = struct.pack("!H", len(sni_entry)) + sni_entry
        ext_sni = b"\x00\x00" + struct.pack("!H", len(sni_list)) + sni_list

        extensions = ext_sni
        if ech:
            ech_payload = b"\x00\x20" + (b"\xaa" * 32)
            ext_ech = b"\xfe\x0d" + struct.pack("!H", len(ech_payload)) + ech_payload
            extensions += ext_ech

        # Add ALPN: h2, http/1.1
        alpn_data = b"\x02h2\x08http/1.1"
        ext_alpn = b"\x00\x10" + struct.pack("!H", len(alpn_data) + 2) + struct.pack("!H", len(alpn_data)) + alpn_data
        extensions += ext_alpn

        # ClientHello body
        version = b"\x03\x03"  # TLS 1.2/1.3
        random_bytes = b"\x55" * 32
        session_id = b"\x20" + (b"\x11" * 32)
        cipher_suites = b"\x00\x04\x13\x01\x13\x02"  # TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384
        compression = b"\x01\x00"
        ext_block = struct.pack("!H", len(extensions)) + extensions

        ch_body = version + random_bytes + session_id + cipher_suites + compression + ext_block
        ch_len = len(ch_body)

        handshake_header = b"\x01" + struct.pack("!I", ch_len)[1:]
        handshake_payload = handshake_header + ch_body

        record_header = b"\x16\x03\x01" + struct.pack("!H", len(handshake_payload))
        return record_header + handshake_payload

    def inject_credential_leak(self, username="admin@corporate-network.com", password="MasterPassword99#"):
        payload = (
            f"POST /v1/login HTTP/1.1\r\n"
            f"Host: dev-internal.portal.net\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64)\r\n\r\n"
            f"user={username}&password={password}&login=1"
        ).encode("utf-8")
        pkt = self.build_http_packet(payload)
        if self.packet_callback:
            self.packet_callback(pkt)
        return pkt

    def inject_jwt_leak(self, token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsImlzcCI6ImRhdGEtYnJva2VyIn0.wU-Hh-EXAMPLE-SIGNATURE"):
        payload = (
            f"GET /api/financial/records HTTP/1.1\r\n"
            f"Host: unencrypted-finance.net\r\n"
            f"Authorization: Bearer {token}\r\n"
            f"User-Agent: Mozilla/5.0\r\n\r\n"
        ).encode("utf-8")
        pkt = self.build_http_packet(payload)
        if self.packet_callback:
            self.packet_callback(pkt)
        return pkt

    def inject_aws_leak(self, access_key="AKIAIOSFODNN7EXAMPLE"):
        payload = (
            f"POST /s3/sync HTTP/1.1\r\n"
            f"Host: s3-backup-mirror.org\r\n"
            f"User-Agent: aws-cli/2.15.0\r\n\r\n"
            f"token={access_key}&bucket=customer-private-data"
        ).encode("utf-8")
        pkt = self.build_http_packet(payload)
        if self.packet_callback:
            self.packet_callback(pkt)
        return pkt

    def inject_vpn_dns_leak(self, domain="whistleblower-leak.org", dns_ip="8.8.8.8"):
        pkt = self.build_dns_query_packet(domain, server_ip=dns_ip)
        if self.packet_callback:
            self.packet_callback(pkt)
        return pkt

    def inject_tracker_storm(self):
        packets = []
        for domain, _, _ in self.SAMPLE_TRACKERS:
            pkt = self.build_dns_query_packet(domain)
            if self.packet_callback:
                self.packet_callback(pkt)
            packets.append(pkt)
        return packets

    def inject_ech_handshake(self, domain="cloudflare-ech.com"):
        pkt = self.build_tls_client_hello_packet(domain, ech=True)
        if self.packet_callback:
            self.packet_callback(pkt)
        return pkt
