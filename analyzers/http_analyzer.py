"""
HTTP request/response analyzer — extracts URLs, headers, and content
from unencrypted HTTP traffic (port 80).
"""

from scapy.all import TCP, IP, IPv6, Raw
from utils.helpers import format_timestamp, truncate


class HTTPAnalyzer:

    HTTP_METHODS = (b"GET", b"POST", b"PUT", b"DELETE", b"HEAD",
                    b"OPTIONS", b"PATCH", b"CONNECT")

    def __init__(self):
        self.request_count = 0
        self.urls_seen = []
        self.user_agents = set()

    def analyze(self, packet):
        events = []

        if not packet.haslayer(TCP) or not packet.haslayer(Raw):
            return events

        tcp = packet[TCP]
        payload = bytes(packet[Raw].load)

        if tcp.dport in (80, 8080, 8000, 8888):
            events.extend(self._parse_request(packet, payload))

        if tcp.sport in (80, 8080, 8000, 8888):
            events.extend(self._parse_response(packet, payload))

        return events

    def _parse_request(self, packet, payload):
        events = []

        if not any(payload.startswith(method) for method in self.HTTP_METHODS):
            return events

        try:
            if b"\r\n\r\n" in payload:
                header_section, body = payload.split(b"\r\n\r\n", 1)
            else:
                header_section = payload
                body = b""

            lines = header_section.split(b"\r\n")
            if not lines:
                return events

            request_line = lines[0].decode("utf-8", errors="replace")
            parts = request_line.split(" ")
            if len(parts) < 2:
                return events

            method = parts[0]
            path = parts[1]

            headers = {}
            for line in lines[1:]:
                try:
                    decoded = line.decode("utf-8", errors="replace")
                    if ":" in decoded:
                        key, value = decoded.split(":", 1)
                        headers[key.strip().lower()] = value.strip()
                except (UnicodeDecodeError, ValueError):
                    continue

            host = headers.get("host", "")
            url = f"http://{host}{path}" if host else path
            user_agent = headers.get("user-agent", "")

            if user_agent:
                self.user_agents.add(user_agent)

            self.request_count += 1
            self.urls_seen.append(url)

            dst_ip = ""
            if packet.haslayer(IP):
                dst_ip = packet[IP].dst
            elif packet.haslayer(IPv6):
                dst_ip = packet[IPv6].dst

            detail_parts = [f"{method} {truncate(url, 120)}"]
            if user_agent:
                detail_parts.append(f"UA: {truncate(user_agent, 80)}")

            events.append({
                "timestamp": format_timestamp(),
                "type": "HTTP",
                "subtype": "Request",
                "destination": f"{dst_ip}:80",
                "detail": " | ".join(detail_parts),
                "method": method,
                "url": url,
                "host": host,
                "path": path,
                "headers": headers,
                "sensitive": False,
            })

            for header_name in ["referer", "cookie", "authorization"]:
                if header_name in headers:
                    is_sensitive = header_name in ("authorization", "cookie")
                    events.append({
                        "timestamp": format_timestamp(),
                        "type": "HTTP",
                        "subtype": f"Header ({header_name.title()})",
                        "destination": f"{dst_ip}:80",
                        "detail": f"{header_name}: {truncate(headers[header_name], 100)}",
                        "sensitive": is_sensitive,
                    })

            if method == "POST" and body:
                body_event = self._parse_post_body(packet, body, headers, dst_ip)
                if body_event:
                    events.append(body_event)

        except (UnicodeDecodeError, ValueError, IndexError):
            pass

        return events

    def _parse_post_body(self, packet, body, headers, dst_ip):
        content_type = headers.get("content-type", "")

        if "application/x-www-form-urlencoded" in content_type:
            try:
                body_str = body.decode("utf-8", errors="replace")
                return {
                    "timestamp": format_timestamp(),
                    "type": "HTTP",
                    "subtype": "POST Data",
                    "destination": f"{dst_ip}:80",
                    "detail": f"Form data: {truncate(body_str, 150)}",
                    "body": body_str,
                    "sensitive": True,
                }
            except UnicodeDecodeError:
                pass

        if "application/json" in content_type:
            try:
                body_str = body.decode("utf-8", errors="replace")
                return {
                    "timestamp": format_timestamp(),
                    "type": "HTTP",
                    "subtype": "POST JSON",
                    "destination": f"{dst_ip}:80",
                    "detail": f"JSON body: {truncate(body_str, 150)}",
                    "body": body_str,
                    "sensitive": True,
                }
            except UnicodeDecodeError:
                pass

        return None

    def _parse_response(self, packet, payload):
        events = []

        if not payload.startswith(b"HTTP/"):
            return events

        try:
            if b"\r\n\r\n" in payload:
                header_section = payload.split(b"\r\n\r\n", 1)[0]
            else:
                header_section = payload[:2048]

            lines = header_section.split(b"\r\n")

            headers = {}
            for line in lines[1:]:
                try:
                    decoded = line.decode("utf-8", errors="replace")
                    if ":" in decoded:
                        key, value = decoded.split(":", 1)
                        headers[key.strip().lower()] = value.strip()
                except (UnicodeDecodeError, ValueError):
                    continue

            src_ip = ""
            if packet.haslayer(IP):
                src_ip = packet[IP].src
            elif packet.haslayer(IPv6):
                src_ip = packet[IPv6].src

            if "set-cookie" in headers:
                events.append({
                    "timestamp": format_timestamp(),
                    "type": "HTTP",
                    "subtype": "Set-Cookie",
                    "destination": f"{src_ip}:80",
                    "detail": f"Cookie set: {truncate(headers['set-cookie'], 120)}",
                    "sensitive": True,
                })

        except (UnicodeDecodeError, ValueError):
            pass

        return events

    def get_stats(self):
        return {
            "total_requests": self.request_count,
            "unique_urls": len(set(self.urls_seen)),
            "user_agents": list(self.user_agents),
        }
