"""
DNS spoofing/poisoning detector — multi-layer detection:
1. Known good IP verification
2. Private IP in public response
3. Response inconsistency tracking
4. Real-time cross-verification against trusted resolver
5. TTL anomaly detection
"""

import socket
import struct
import threading
import time
from collections import defaultdict
from scapy.all import DNS, DNSQR, DNSRR, IP, sr1, UDP
from utils.helpers import format_timestamp, is_private_ip


class DNSSpoofDetector:

    # Known good IPs for major domains
    KNOWN_GOOD = {
        "google.com": {"142.250.", "172.217.", "216.58."},
        "www.google.com": {"142.250.", "172.217.", "216.58."},
        "facebook.com": {"157.240.", "31.13.", "179.60."},
        "www.facebook.com": {"157.240.", "31.13.", "179.60."},
        "twitter.com": {"104.244.", "192.133."},
        "github.com": {"140.82.", "192.30."},
        "youtube.com": {"142.250.", "172.217.", "216.58."},
        "cloudflare.com": {"104.16.", "104.17.", "104.18."},
        "amazon.com": {"54.", "52.", "205.251."},
        "microsoft.com": {"20.", "40.", "13."},
        "apple.com": {"17."},
        "netflix.com": {"54.", "52.", "3."},
        "reddit.com": {"151.101."},
        "wikipedia.org": {"91.198.", "103.102."},
        "instagram.com": {"157.240.", "31.13."},
        "linkedin.com": {"13.", "108."},
        "paypal.com": {"64.4.", "173.0."},
    }

    # Suspicious IP ranges (private IPs in DNS response)
    SUSPICIOUS_RANGES = [
        "10.", "192.168.", "127.", "0.0.0.",
        "172.16.", "172.17.", "172.18.", "172.19.",
        "172.20.", "172.21.", "172.22.", "172.23.",
        "172.24.", "172.25.", "172.26.", "172.27.",
        "172.28.", "172.29.", "172.30.", "172.31.",
    ]

    # Trusted DNS resolvers for cross-verification
    TRUSTED_RESOLVERS = [
        "9.9.9.9",       # Quad9
        "1.1.1.1",       # Cloudflare
        "8.8.8.8",       # Google
    ]

    # Minimum suspicious TTL (seconds)
    SUSPICIOUS_TTL_THRESHOLD = 5
    # Maximum normal TTL
    SUSPICIOUS_HIGH_TTL = 86400 * 7  # 7 days is abnormal

    def __init__(self):
        self.spoofs_detected = []
        self.spoof_count = 0
        self._domain_responses = defaultdict(list)
        self._domain_ttls = defaultdict(list)
        self._response_counts = defaultdict(int)
        self._lock = threading.Lock()
        self._verified_cache = {}  # domain -> (trusted_ips, timestamp)
        self._verify_queue = []
        self._verify_lock = threading.Lock()
        self._verify_thread = None
        self._running = False
        self._verification_results = {}  # domain -> {match: bool, trusted_ips: []}
        self._rate_limit_interval = 2  # seconds between verifications

    def start(self):
        """Start background cross-verification thread."""
        self._running = True
        self._verify_thread = threading.Thread(
            target=self._verification_worker, daemon=True
        )
        self._verify_thread.start()

    def stop(self):
        """Stop background thread."""
        self._running = False
        if self._verify_thread:
            self._verify_thread.join(timeout=3)

    def analyze(self, packet):
        """Run all detection layers on a DNS response packet."""
        events = []

        if not packet.haslayer(DNS):
            return events

        dns = packet[DNS]

        # Only analyze responses
        if dns.qr != 1 or dns.ancount == 0:
            return events

        try:
            domain = ""
            if packet.haslayer(DNSQR):
                domain = dns[DNSQR].qname.decode(
                    "utf-8", errors="replace"
                ).rstrip(".").lower()

            if not domain:
                return events

            # Extract resolved IPs and TTLs
            resolved_ips = []
            ttls = []
            for i in range(dns.ancount):
                try:
                    rr = dns.an[i]
                    if hasattr(rr, "rdata"):
                        rdata = str(rr.rdata)
                        if rdata and "." in rdata:
                            resolved_ips.append(rdata)
                    if hasattr(rr, "ttl"):
                        ttls.append(rr.ttl)
                except (IndexError, AttributeError):
                    continue

            if not resolved_ips:
                return events

            src_ip = packet[IP].src if packet.haslayer(IP) else ""

            # ===== Layer 1: Private IP in public domain response =====
            if not is_private_ip(domain):
                for ip in resolved_ips:
                    for suspicious in self.SUSPICIOUS_RANGES:
                        if ip.startswith(suspicious):
                            events.append(self._make_spoof_event(
                                domain, ip, src_ip,
                                "Private IP returned for public domain — "
                                "STRONG spoofing indicator",
                                "CRITICAL"
                            ))
                            break

            # ===== Layer 2: Known good IP mismatch =====
            base_domain = self._get_base_domain(domain)
            if base_domain in self.KNOWN_GOOD:
                expected_prefixes = self.KNOWN_GOOD[base_domain]
                for ip in resolved_ips:
                    if not any(ip.startswith(p) for p in expected_prefixes):
                        if not self._is_likely_cdn(ip):
                            events.append(self._make_spoof_event(
                                domain, ip, src_ip,
                                f"IP mismatch for known domain "
                                f"(expected prefix: "
                                f"{', '.join(list(expected_prefixes)[:3])})",
                                "HIGH"
                            ))

            # ===== Layer 3: TTL anomaly detection =====
            ttl_events = self._check_ttl_anomalies(
                domain, ttls, resolved_ips, src_ip
            )
            events.extend(ttl_events)

            # ===== Layer 4: Response inconsistency =====
            consistency_events = self._check_consistency(
                domain, resolved_ips, src_ip
            )
            events.extend(consistency_events)

            # ===== Layer 5: Queue for cross-verification =====
            self._queue_verification(domain, resolved_ips, src_ip)

            # Check if any past verifications have results
            verify_events = self._check_verification_results(domain, src_ip)
            events.extend(verify_events)

        except Exception:
            pass

        return events

    def _check_ttl_anomalies(self, domain, ttls, resolved_ips, src_ip):
        """Layer 5: Detect suspicious TTL values."""
        events = []

        if not ttls:
            return events

        for ttl in ttls:
            # Suspiciously low TTL (0-5 seconds)
            # Attackers use low TTLs so poison expires fast
            if ttl <= self.SUSPICIOUS_TTL_THRESHOLD:
                events.append(self._make_spoof_event(
                    domain,
                    ", ".join(resolved_ips),
                    src_ip,
                    f"Suspiciously low TTL ({ttl}s) — "
                    f"common in DNS poisoning attacks",
                    "WARNING"
                ))
                break

            # Absurdly high TTL (over 7 days)
            if ttl > self.SUSPICIOUS_HIGH_TTL:
                events.append(self._make_spoof_event(
                    domain,
                    ", ".join(resolved_ips),
                    src_ip,
                    f"Abnormally high TTL ({ttl}s / "
                    f"{ttl // 86400} days) — may indicate cache poisoning",
                    "WARNING"
                ))
                break

        # Track TTL history for sudden changes
        with self._lock:
            prev_ttls = self._domain_ttls.get(domain, [])
            if prev_ttls and ttls:
                avg_prev = sum(prev_ttls[-5:]) / len(prev_ttls[-5:])
                current_ttl = ttls[0]

                # TTL dropped by more than 90% suddenly
                if avg_prev > 60 and current_ttl < avg_prev * 0.1:
                    events.append(self._make_spoof_event(
                        domain,
                        ", ".join(resolved_ips),
                        src_ip,
                        f"TTL dropped sharply: {int(avg_prev)}s → "
                        f"{current_ttl}s — possible active attack",
                        "HIGH"
                    ))

            self._domain_ttls[domain].extend(ttls)
            # Keep last 20 TTLs per domain
            if len(self._domain_ttls[domain]) > 20:
                self._domain_ttls[domain] = self._domain_ttls[domain][-20:]

        return events

    def _check_consistency(self, domain, resolved_ips, src_ip):
        """Layer 3: Check if responses are consistent over time."""
        events = []

        with self._lock:
            self._response_counts[domain] += 1
            prev_ips = self._domain_responses.get(domain, [])

            if prev_ips and resolved_ips:
                overlap = set(resolved_ips) & set(prev_ips)

                # Only flag after seeing the domain at least 3 times
                if not overlap and self._response_counts[domain] > 3:
                    if not self._looks_like_cdn_rotation(prev_ips, resolved_ips):
                        events.append(self._make_spoof_event(
                            domain,
                            ", ".join(resolved_ips),
                            src_ip,
                            f"Response changed completely "
                            f"(was: {', '.join(prev_ips[:2])}) — "
                            f"possible DNS hijack",
                            "HIGH"
                        ))

            # Keep last seen IPs
            self._domain_responses[domain] = resolved_ips

        return events

    def _queue_verification(self, domain, resolved_ips, src_ip):
        """Queue a domain for cross-verification against trusted resolver."""
        with self._verify_lock:
            # Don't re-verify recently checked domains
            if domain in self._verified_cache:
                cached_time = self._verified_cache[domain][1]
                if time.time() - cached_time < 300:  # 5 min cache
                    return

            # Don't queue duplicates
            queued_domains = [q[0] for q in self._verify_queue]
            if domain not in queued_domains:
                self._verify_queue.append(
                    (domain, resolved_ips, src_ip, time.time())
                )
                # Keep queue manageable
                if len(self._verify_queue) > 50:
                    self._verify_queue = self._verify_queue[-50:]

    def _verification_worker(self):
        """Background thread: cross-verify DNS responses."""
        while self._running:
            try:
                item = None
                with self._verify_lock:
                    if self._verify_queue:
                        item = self._verify_queue.pop(0)

                if item:
                    domain, original_ips, src_ip, queued_time = item
                    self._do_cross_verify(domain, original_ips, src_ip)
                    time.sleep(self._rate_limit_interval)
                else:
                    time.sleep(0.5)

            except Exception:
                time.sleep(1)

    def _do_cross_verify(self, domain, original_ips, src_ip):
        """Actually perform cross-verification lookup."""
        trusted_ips = set()

        for resolver in self.TRUSTED_RESOLVERS[:2]:
            try:
                # Use socket for simple lookup via specific resolver
                ips = self._resolve_via(domain, resolver)
                trusted_ips.update(ips)
            except Exception:
                continue

        if not trusted_ips:
            return

        # Compare original response against trusted response
        original_set = set(original_ips)
        overlap = original_set & trusted_ips

        # Check if original IPs share any /24 with trusted IPs
        orig_subnets = {".".join(ip.split(".")[:3]) for ip in original_set if "." in ip}
        trusted_subnets = {".".join(ip.split(".")[:3]) for ip in trusted_ips if "." in ip}
        subnet_overlap = orig_subnets & trusted_subnets

        is_match = bool(overlap) or bool(subnet_overlap)

        with self._verify_lock:
            self._verified_cache[domain] = (trusted_ips, time.time())
            self._verification_results[domain] = {
                "match": is_match,
                "original_ips": list(original_set),
                "trusted_ips": list(trusted_ips),
                "src_ip": src_ip,
                "checked_at": time.time(),
                "consumed": False,
            }

    def _resolve_via(self, domain, resolver):
        """Resolve a domain using a specific DNS server."""
        ips = []
        try:
            # Build raw DNS query
            import select

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)

            # Simple DNS query construction
            tx_id = struct.pack("!H", int(time.time() * 1000) & 0xFFFF)
            flags = b"\x01\x00"  # Standard query, recursion desired
            qdcount = b"\x00\x01"
            ancount = b"\x00\x00"
            nscount = b"\x00\x00"
            arcount = b"\x00\x00"

            # Encode domain name
            qname = b""
            for label in domain.split("."):
                qname += bytes([len(label)]) + label.encode("ascii")
            qname += b"\x00"

            qtype = b"\x00\x01"   # A record
            qclass = b"\x00\x01"  # IN class

            query = (tx_id + flags + qdcount + ancount +
                     nscount + arcount + qname + qtype + qclass)

            sock.sendto(query, (resolver, 53))
            response, _ = sock.recvfrom(1024)
            sock.close()

            # Parse response — skip header (12 bytes) and question
            if len(response) < 12:
                return ips

            ans_count = struct.unpack("!H", response[6:8])[0]

            # Skip question section
            pos = 12
            while pos < len(response) and response[pos] != 0:
                pos += response[pos] + 1
            pos += 5  # null byte + qtype(2) + qclass(2)

            # Parse answer records
            for _ in range(ans_count):
                if pos + 12 > len(response):
                    break

                # Name (could be pointer)
                if response[pos] & 0xC0 == 0xC0:
                    pos += 2
                else:
                    while pos < len(response) and response[pos] != 0:
                        pos += response[pos] + 1
                    pos += 1

                if pos + 10 > len(response):
                    break

                rtype = struct.unpack("!H", response[pos:pos + 2])[0]
                rdlength = struct.unpack("!H", response[pos + 8:pos + 10])[0]
                pos += 10

                if rtype == 1 and rdlength == 4:  # A record
                    ip = ".".join(str(b) for b in response[pos:pos + 4])
                    ips.append(ip)

                pos += rdlength

        except Exception:
            pass

        return ips

    def _check_verification_results(self, domain, src_ip):
        """Check if cross-verification found a mismatch."""
        events = []

        with self._verify_lock:
            result = self._verification_results.get(domain)
            if not result or result.get("consumed"):
                return events

            result["consumed"] = True

            if not result["match"]:
                original = ", ".join(result["original_ips"][:3])
                trusted = ", ".join(result["trusted_ips"][:3])
                events.append(self._make_spoof_event(
                    domain,
                    original,
                    src_ip,
                    f"CROSS-VERIFICATION FAILED! "
                    f"Your DNS returned [{original}] but trusted "
                    f"resolvers say [{trusted}]",
                    "CRITICAL"
                ))

        return events

    def _make_spoof_event(self, domain, ip, src, reason, severity):
        """Create a spoof detection event."""
        event = {
            "timestamp": format_timestamp(),
            "type": "DNS SPOOF",
            "subtype": severity,
            "destination": src,
            "detail": f"{domain} → {ip} | {reason}",
            "sensitive": True,
            "domain": domain,
            "suspicious_ip": ip,
            "reason": reason,
            "severity": severity,
        }
        self.spoofs_detected.append(event)
        self.spoof_count += 1
        return event

    def _get_base_domain(self, domain):
        """Extract base domain."""
        parts = domain.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return domain

    def _is_likely_cdn(self, ip):
        """Check if IP is likely a CDN address."""
        try:
            import ipaddress
            addr = ipaddress.ip_address(ip)
            return not (addr.is_private or addr.is_loopback)
        except ValueError:
            return True

    def _looks_like_cdn_rotation(self, old_ips, new_ips):
        """Check if IP change is normal CDN load balancing."""
        if not old_ips or not new_ips:
            return False
        old_prefix = ".".join(old_ips[0].split(".")[:2])
        new_prefix = ".".join(new_ips[0].split(".")[:2])
        return old_prefix == new_prefix

    def get_stats(self):
        return {
            "spoofs_detected": self.spoof_count,
            "domains_monitored": len(self._domain_responses),
            "domains_verified": len(self._verified_cache),
            "critical_count": sum(
                1 for s in self.spoofs_detected
                if s.get("severity") == "CRITICAL"
            ),
            "high_count": sum(
                1 for s in self.spoofs_detected
                if s.get("severity") == "HIGH"
            ),
            "warning_count": sum(
                1 for s in self.spoofs_detected
                if s.get("severity") == "WARNING"
            ),
            "recent_spoofs": self.spoofs_detected[-5:],
            "ttl_anomalies_tracked": len(self._domain_ttls),
        }
