"""
Sensitive data leak detector.
"""

import re
from utils.helpers import truncate


class SensitiveDetector:

    CREDENTIAL_PATTERNS = [
        (re.compile(rb"(?:password|passwd|pwd|pass)=([^&\s]{1,100})", re.IGNORECASE),
         "Plaintext Password"),
        (re.compile(rb"(?:username|user|login|email)=([^&\s]{1,100})", re.IGNORECASE),
         "Plaintext Username/Email"),
        (re.compile(rb"(?:token|api_key|apikey|api-key|access_token|auth_token)=([^&\s]{1,100})", re.IGNORECASE),
         "API Token/Key"),
        (re.compile(rb"(?:session_id|sessionid|session|sid)=([^&\s]{1,100})", re.IGNORECASE),
         "Session ID"),
        (re.compile(rb"(?:credit.?card|cc.?num|card.?number)=([^&\s]{1,100})", re.IGNORECASE),
         "Credit Card Number"),
        (re.compile(rb"(?:ssn|social.?security)=([^&\s]{1,100})", re.IGNORECASE),
         "Social Security Number"),
        (re.compile(rb"(eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,})"),
         "JSON Web Token (JWT)"),
        (re.compile(rb"((?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16})"),
         "AWS Access Key ID"),
        (re.compile(rb"(ghp_[A-Za-z0-9]{36})"),
         "GitHub Personal Access Token"),
        (re.compile(rb"(https://hooks\.slack\.com/services/T[0-9A-Za-z_]+/B[0-9A-Za-z_]+/[0-9A-Za-z_]+)"),
         "Slack Webhook URL"),
        (re.compile(rb"(-----BEGIN (?:RSA|EC|OPENSSH|DSA) PRIVATE KEY-----)"),
         "Cryptographic Private Key"),
    ]

    AUTH_PATTERNS = [
        (re.compile(r"Basic\s+([A-Za-z0-9+/=]+)", re.IGNORECASE),
         "HTTP Basic Auth (base64 credentials)"),
        (re.compile(r"Bearer\s+([A-Za-z0-9\-._~+/=]+)", re.IGNORECASE),
         "Bearer Token"),
        (re.compile(r"Digest\s+", re.IGNORECASE),
         "HTTP Digest Auth"),
    ]

    SENSITIVE_URL_PATTERNS = [
        (re.compile(r"/login", re.IGNORECASE), "Login Page (unencrypted!)"),
        (re.compile(r"/signin", re.IGNORECASE), "Sign-in Page (unencrypted!)"),
        (re.compile(r"/auth", re.IGNORECASE), "Auth Endpoint (unencrypted!)"),
        (re.compile(r"/register", re.IGNORECASE), "Registration Page (unencrypted!)"),
        (re.compile(r"/signup", re.IGNORECASE), "Sign-up Page (unencrypted!)"),
        (re.compile(r"/account", re.IGNORECASE), "Account Page (unencrypted!)"),
        (re.compile(r"/payment", re.IGNORECASE), "Payment Page (unencrypted!)"),
        (re.compile(r"/checkout", re.IGNORECASE), "Checkout Page (unencrypted!)"),
        (re.compile(r"/admin", re.IGNORECASE), "Admin Page (unencrypted!)"),
        (re.compile(r"/api/", re.IGNORECASE), "API Endpoint (unencrypted!)"),
    ]

    FTP_PATTERNS = [
        (re.compile(rb"^USER\s+(.+)", re.IGNORECASE), "FTP Username"),
        (re.compile(rb"^PASS\s+(.+)", re.IGNORECASE), "FTP Password"),
    ]

    SMTP_PATTERNS = [
        (re.compile(rb"^AUTH\s+LOGIN", re.IGNORECASE), "SMTP Login Auth"),
        (re.compile(rb"^AUTH\s+PLAIN\s+(.+)", re.IGNORECASE), "SMTP Plain Auth"),
    ]

    def __init__(self):
        self.leaks_found = []
        self.leak_count = 0

    def scan_raw_payload(self, payload_bytes, src_ip="", dst_ip="", dst_port=0):
        leaks = []

        if not payload_bytes or len(payload_bytes) < 5:
            return leaks

        for pattern, leak_type in self.CREDENTIAL_PATTERNS:
            match = pattern.search(payload_bytes)
            if match:
                raw_match = match.group(1) if pattern.groups >= 1 else match.group(0)
                leaked_value = raw_match.decode("utf-8", errors="replace")
                redacted = self._redact(leaked_value)
                leak = {
                    "timestamp": "",
                    "type": "LEAK",
                    "subtype": leak_type,
                    "destination": f"{dst_ip}:{dst_port}",
                    "detail": f"{leak_type}: {redacted} (PLAINTEXT!)",
                    "sensitive": True,
                    "leak_type": leak_type,
                    "severity": "CRITICAL",
                }
                leaks.append(leak)
                self.leaks_found.append(leak)
                self.leak_count += 1

        if dst_port == 21:
            for pattern, leak_type in self.FTP_PATTERNS:
                match = pattern.search(payload_bytes)
                if match:
                    value = match.group(1).decode("utf-8", errors="replace").strip()
                    leak = {
                        "timestamp": "",
                        "type": "LEAK",
                        "subtype": leak_type,
                        "destination": f"{dst_ip}:{dst_port}",
                        "detail": f"{leak_type}: {self._redact(value)} (FTP PLAINTEXT!)",
                        "sensitive": True,
                        "leak_type": leak_type,
                        "severity": "CRITICAL",
                    }
                    leaks.append(leak)
                    self.leaks_found.append(leak)
                    self.leak_count += 1

        if dst_port in (25, 587):
            for pattern, leak_type in self.SMTP_PATTERNS:
                match = pattern.search(payload_bytes)
                if match:
                    leak = {
                        "timestamp": "",
                        "type": "LEAK",
                        "subtype": leak_type,
                        "destination": f"{dst_ip}:{dst_port}",
                        "detail": f"{leak_type} detected (PLAINTEXT SMTP!)",
                        "sensitive": True,
                        "leak_type": leak_type,
                        "severity": "HIGH",
                    }
                    leaks.append(leak)
                    self.leaks_found.append(leak)
                    self.leak_count += 1

        return leaks

    def scan_http_event(self, event):
        leaks = []

        url = event.get("url", "") or event.get("path", "")
        if url:
            for pattern, description in self.SENSITIVE_URL_PATTERNS:
                if pattern.search(url):
                    leak = {
                        "timestamp": event.get("timestamp", ""),
                        "type": "WARN",
                        "subtype": "Sensitive URL",
                        "destination": event.get("destination", ""),
                        "detail": f"{description}: {truncate(url, 100)}",
                        "sensitive": True,
                        "leak_type": description,
                        "severity": "WARNING",
                    }
                    leaks.append(leak)
                    self.leaks_found.append(leak)
                    self.leak_count += 1
                    break

            # Check for credentials in URL query parameters
            query_match = re.search(r"[?&](?:token|key|api_key|password|pwd|auth|secret|access_token)=([^&\s]{4,100})", url, re.IGNORECASE)
            if query_match:
                param_val = query_match.group(1)
                leak = {
                    "timestamp": event.get("timestamp", ""),
                    "type": "LEAK",
                    "subtype": "URL Query Credential",
                    "destination": event.get("destination", ""),
                    "detail": f"Exposed credential in URL: {self._redact(param_val)}",
                    "sensitive": True,
                    "leak_type": "URL Query Credential",
                    "severity": "CRITICAL",
                }
                leaks.append(leak)
                self.leaks_found.append(leak)
                self.leak_count += 1

        headers = event.get("headers", {})
        auth_header = headers.get("authorization", "")
        if auth_header:
            for pattern, description in self.AUTH_PATTERNS:
                if pattern.search(auth_header):
                    leak = {
                        "timestamp": event.get("timestamp", ""),
                        "type": "LEAK",
                        "subtype": "Auth Header",
                        "destination": event.get("destination", ""),
                        "detail": f"{description} sent over unencrypted HTTP!",
                        "sensitive": True,
                        "leak_type": description,
                        "severity": "CRITICAL",
                    }
                    leaks.append(leak)
                    self.leaks_found.append(leak)
                    self.leak_count += 1
                    break

        cookie_header = headers.get("cookie", "")
        if cookie_header:
            sess_match = re.search(r"(?:session|sess_id|jwt|auth|token)=([^;\s]{8,})", cookie_header, re.IGNORECASE)
            if sess_match:
                val = sess_match.group(1)
                leak = {
                    "timestamp": event.get("timestamp", ""),
                    "type": "LEAK",
                    "subtype": "Plaintext Session Cookie",
                    "destination": event.get("destination", ""),
                    "detail": f"Session cookie sent over HTTP: {self._redact(val)}",
                    "sensitive": True,
                    "leak_type": "Plaintext Session Cookie",
                    "severity": "HIGH",
                }
                leaks.append(leak)
                self.leaks_found.append(leak)
                self.leak_count += 1

        return leaks

    def _redact(self, value, show_chars=3):
        if len(value) <= show_chars:
            return "*" * len(value)
        return value[:show_chars] + "*" * min(len(value) - show_chars, 15)

    def get_stats(self):
        from collections import Counter
        type_counts = Counter(l["leak_type"] for l in self.leaks_found)
        return {
            "total_leaks": self.leak_count,
            "leak_types": dict(type_counts),
            "critical_count": sum(1 for l in self.leaks_found if l.get("severity") == "CRITICAL"),
            "warning_count": sum(1 for l in self.leaks_found if l.get("severity") == "WARNING"),
        }
