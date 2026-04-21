"""
Device fingerprinting — identifies OS, browser, device type
from TCP stack behavior, TLS patterns, and User-Agent strings.
"""

import struct
import hashlib
from collections import defaultdict
from scapy.all import TCP, IP, Raw
from utils.helpers import format_timestamp


class FingerprintAnalyzer:

    # OS detection by initial TTL values
    TTL_SIGNATURES = {
        (60, 64): "Linux",
        (64, 64): "Linux",
        (128, 128): "Windows",
        (255, 255): "Cisco/Network Device",
        (56, 64): "Linux (older)",
        (48, 64): "Linux (embedded)",
    }

    # Common TCP window sizes per OS
    WINDOW_SIGNATURES = {
        65535: "Windows",
        64240: "Linux",
        65160: "Linux (newer)",
        29200: "Linux",
        5840: "Linux (older)",
        8192: "Windows (older)",
        16384: "macOS",
        32768: "macOS",
    }

    # TLS cipher suite groups that identify browsers
    BROWSER_SIGNATURES = {
        # JA3-style: specific cipher orderings
        "chrome": [0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f],
        "firefox": [0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f],
        "safari": [0x1303, 0x1301, 0x1302, 0xc02c, 0xc02b],
    }

    # User-Agent based detection
    UA_PATTERNS = {
        "Windows NT 10": ("Windows 10/11", "Desktop"),
        "Windows NT 6.3": ("Windows 8.1", "Desktop"),
        "Windows NT 6.1": ("Windows 7", "Desktop"),
        "Macintosh": ("macOS", "Desktop"),
        "X11; Linux": ("Linux", "Desktop"),
        "Android": ("Android", "Mobile"),
        "iPhone": ("iOS", "Mobile"),
        "iPad": ("iPadOS", "Tablet"),
        "CrOS": ("ChromeOS", "Desktop"),
    }

    UA_BROWSER_PATTERNS = {
        "Chrome/": "Chrome",
        "Firefox/": "Firefox",
        "Safari/": "Safari",
        "Edg/": "Edge",
        "OPR/": "Opera",
        "Brave": "Brave",
        "Vivaldi": "Vivaldi",
    }

    def __init__(self):
        self.fingerprints = []
        self._seen_uas = set()
        self._tcp_sigs = defaultdict(int)
        self._os_votes = defaultdict(int)
        self._browser_votes = defaultdict(int)
        self._device_votes = defaultdict(int)
        self._ja3_hashes = set()
        self._syn_analyzed = False

    def analyze(self, packet):
        """Analyze packet for fingerprinting data."""
        events = []

        # TCP SYN fingerprinting
        if packet.haslayer(TCP) and packet.haslayer(IP):
            tcp = packet[TCP]
            ip = packet[IP]

            # Only analyze SYN packets (outbound connection initiation)
            if tcp.flags & 0x02 and not tcp.flags & 0x10:
                fp_event = self._analyze_tcp_syn(ip, tcp)
                if fp_event:
                    events.append(fp_event)

        # TLS Client Hello fingerprinting (JA3)
        if packet.haslayer(TCP) and packet.haslayer(Raw):
            tcp = packet[TCP]
            if tcp.dport in (443, 8443):
                payload = bytes(packet[Raw].load)
                ja3_event = self._analyze_tls_hello(payload, packet)
                if ja3_event:
                    events.append(ja3_event)

        return events

    def _analyze_tcp_syn(self, ip, tcp):
        """Fingerprint OS from TCP SYN packet characteristics."""
        ttl = ip.ttl
        window = tcp.window
        mss = 0
        wscale = 0
        sack_ok = False
        timestamp_present = False

        # Parse TCP options
        if tcp.options:
            for opt_name, opt_val in tcp.options:
                if opt_name == "MSS":
                    mss = opt_val
                elif opt_name == "WScale":
                    wscale = opt_val
                elif opt_name == "SAckOK":
                    sack_ok = True
                elif opt_name == "Timestamp":
                    timestamp_present = True

        # Build TCP signature string
        sig = f"TTL:{ttl},WIN:{window},MSS:{mss},WS:{wscale},SACK:{sack_ok}"
        self._tcp_sigs[sig] += 1

        # OS detection from TTL
        os_guess = self._guess_os_from_ttl(ttl)

        # Refine with window size
        if window in self.WINDOW_SIGNATURES:
            win_os = self.WINDOW_SIGNATURES[window]
            if os_guess == "Unknown":
                os_guess = win_os
            self._os_votes[win_os] += 1

        if os_guess != "Unknown":
            self._os_votes[os_guess] += 1

        # Only emit event once per unique signature
        if self._syn_analyzed:
            return None

        self._syn_analyzed = True

        confidence = min(0.9, 0.3 + (0.1 * len(self._os_votes)))

        fp_data = {
            "timestamp": format_timestamp(),
            "type": "FINGERPRINT",
            "subtype": "TCP Stack",
            "destination": "",
            "detail": f"OS: {os_guess} | TTL:{ttl} WIN:{window} MSS:{mss}",
            "sensitive": False,
            "os_guess": os_guess,
            "browser_guess": "",
            "device_type": "Desktop",
            "tcp_fingerprint": sig,
            "tls_fingerprint": "",
            "confidence": confidence,
        }

        self.fingerprints.append(fp_data)
        return fp_data

    def _analyze_tls_hello(self, payload, packet):
        """Extract JA3 fingerprint from TLS Client Hello."""
        try:
            if len(payload) < 6 or payload[0] != 22 or payload[5] != 1:
                return None

            # Calculate JA3 hash
            ja3_str = self._compute_ja3(payload)
            if not ja3_str or ja3_str in self._ja3_hashes:
                return None

            self._ja3_hashes.add(ja3_str)
            ja3_hash = hashlib.md5(ja3_str.encode()).hexdigest()

            # Try to identify browser from JA3
            browser = self._guess_browser_from_ja3(ja3_hash)
            if browser:
                self._browser_votes[browser] += 1

            dst_ip = packet[IP].dst if packet.haslayer(IP) else ""

            fp_data = {
                "timestamp": format_timestamp(),
                "type": "FINGERPRINT",
                "subtype": "TLS/JA3",
                "destination": dst_ip,
                "detail": f"JA3: {ja3_hash[:16]}... Browser: {browser or 'Unknown'}",
                "sensitive": False,
                "os_guess": "",
                "browser_guess": browser or "Unknown",
                "device_type": "",
                "tcp_fingerprint": "",
                "tls_fingerprint": ja3_hash,
                "confidence": 0.7 if browser else 0.3,
            }

            self.fingerprints.append(fp_data)
            return fp_data

        except (IndexError, struct.error):
            return None

    def analyze_user_agent(self, user_agent):
        """Analyze a User-Agent string for OS/browser/device."""
        if not user_agent or user_agent in self._seen_uas:
            return None

        self._seen_uas.add(user_agent)

        os_guess = "Unknown"
        device_type = "Unknown"
        browser_guess = "Unknown"

        # Detect OS and device type
        for pattern, (os_name, dev_type) in self.UA_PATTERNS.items():
            if pattern in user_agent:
                os_guess = os_name
                device_type = dev_type
                self._os_votes[os_name] += 3  # UA is high confidence
                self._device_votes[dev_type] += 3
                break

        # Detect browser
        for pattern, browser in self.UA_BROWSER_PATTERNS.items():
            if pattern in user_agent:
                browser_guess = browser
                self._browser_votes[browser] += 3
                break

        fp_data = {
            "timestamp": format_timestamp(),
            "type": "FINGERPRINT",
            "subtype": "User-Agent",
            "destination": "",
            "detail": f"OS: {os_guess} | Browser: {browser_guess} | Device: {device_type}",
            "sensitive": False,
            "os_guess": os_guess,
            "browser_guess": browser_guess,
            "device_type": device_type,
            "tcp_fingerprint": "",
            "tls_fingerprint": "",
            "confidence": 0.95,
        }

        self.fingerprints.append(fp_data)
        return fp_data

    def _guess_os_from_ttl(self, ttl):
        """Guess OS based on TTL value."""
        if 0 < ttl <= 64:
            return "Linux/macOS/Unix"
        elif 64 < ttl <= 128:
            return "Windows"
        elif ttl > 128:
            return "Network Device"
        return "Unknown"

    def _compute_ja3(self, payload):
        """Compute JA3 string from TLS Client Hello."""
        try:
            pos = 5 + 1 + 3  # Record header + handshake type + length
            if pos + 2 > len(payload):
                return None

            # Client version
            tls_version = struct.unpack("!H", payload[pos:pos + 2])[0]
            pos += 2 + 32  # Skip random

            if pos >= len(payload):
                return None

            # Session ID
            sid_len = payload[pos]
            pos += 1 + sid_len

            if pos + 2 > len(payload):
                return None

            # Cipher suites
            cs_len = struct.unpack("!H", payload[pos:pos + 2])[0]
            pos += 2
            ciphers = []
            cs_end = pos + cs_len
            while pos + 2 <= cs_end:
                cs = struct.unpack("!H", payload[pos:pos + 2])[0]
                # Skip GREASE values
                if (cs & 0x0f0f) != 0x0a0a:
                    ciphers.append(str(cs))
                pos += 2

            if pos >= len(payload):
                return None

            # Compression
            comp_len = payload[pos]
            pos += 1 + comp_len

            # Extensions
            extensions = []
            elliptic_curves = []
            ec_formats = []

            if pos + 2 <= len(payload):
                ext_len = struct.unpack("!H", payload[pos:pos + 2])[0]
                pos += 2
                ext_end = pos + ext_len

                while pos + 4 <= ext_end and pos + 4 <= len(payload):
                    ext_type = struct.unpack("!H", payload[pos:pos + 2])[0]
                    ext_data_len = struct.unpack("!H", payload[pos + 2:pos + 4])[0]
                    pos += 4

                    # Skip GREASE
                    if (ext_type & 0x0f0f) != 0x0a0a:
                        extensions.append(str(ext_type))

                    # Supported groups (elliptic curves)
                    if ext_type == 10 and pos + 2 <= len(payload):
                        sg_len = struct.unpack("!H", payload[pos:pos + 2])[0]
                        sg_pos = pos + 2
                        while sg_pos + 2 <= pos + 2 + sg_len:
                            sg = struct.unpack("!H", payload[sg_pos:sg_pos + 2])[0]
                            if (sg & 0x0f0f) != 0x0a0a:
                                elliptic_curves.append(str(sg))
                            sg_pos += 2

                    # EC point formats
                    if ext_type == 11 and pos < len(payload):
                        pf_len = payload[pos]
                        pf_pos = pos + 1
                        while pf_pos < pos + 1 + pf_len:
                            ec_formats.append(str(payload[pf_pos]))
                            pf_pos += 1

                    pos += ext_data_len

            ja3 = f"{tls_version},{'-'.join(ciphers)},{'-'.join(extensions)},{'-'.join(elliptic_curves)},{'-'.join(ec_formats)}"
            return ja3

        except (IndexError, struct.error):
            return None

    def _guess_browser_from_ja3(self, ja3_hash):
        """Match JA3 hash against known browser fingerprints."""
        # Common JA3 hashes (these change with versions but give hints)
        known = {
            "chrome": ["66918128f1b9b03303d77c6f2eefd128", "eb1d94daa7e0344597e756a1fb6e7054"],
            "firefox": ["e4f1a868ccb3e9f97c2aaf37bf7e52ae", "839bbe3ed07fed922ded5aaf714d6842"],
            "safari": ["773906b0efdefa24a7f2b8eb6985bf37"],
            "curl": ["456523fc94726331a4d5a2e1d40b2cd7"],
        }

        for browser, hashes in known.items():
            if ja3_hash in hashes:
                return browser.title()
        return None

    def get_best_guess(self):
        """Return the highest confidence device profile."""
        os_guess = max(self._os_votes, key=self._os_votes.get) if self._os_votes else "Unknown"
        browser_guess = max(self._browser_votes, key=self._browser_votes.get) if self._browser_votes else "Unknown"
        device_guess = max(self._device_votes, key=self._device_votes.get) if self._device_votes else "Desktop"

        return {
            "os": os_guess,
            "browser": browser_guess,
            "device": device_guess,
            "ja3_count": len(self._ja3_hashes),
            "tcp_signatures": len(self._tcp_sigs),
        }

    def get_stats(self):
        return {
            "fingerprints_collected": len(self.fingerprints),
            "unique_ja3": len(self._ja3_hashes),
            "unique_user_agents": len(self._seen_uas),
            "best_guess": self.get_best_guess(),
            "os_votes": dict(self._os_votes),
            "browser_votes": dict(self._browser_votes),
        }
