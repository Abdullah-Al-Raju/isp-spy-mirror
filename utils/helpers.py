"""
Utility functions used across the project.
"""

import socket
import os
import sys
from datetime import datetime


def check_capture_privileges(required=True):
    """Verify if user has root or wireshark/dumpcap packet capture capability."""
    is_root = (os.geteuid() == 0) if hasattr(os, "geteuid") else False
    if is_root:
        return True

    import shutil, subprocess
    dumpcap_path = shutil.which("dumpcap")
    if dumpcap_path:
        try:
            res = subprocess.run(
                [dumpcap_path, "-i", "lo", "-c", "1", "-a", "duration:1"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2
            )
            if res.returncode in (0, 1, 2):
                return True
        except Exception:
            pass

    if required:
        print("[!] Live network packet capture requires root or CAP_NET_RAW / wireshark privileges.")
        print("    Run with: sudo python main.py live")
        print("    Or launch without root using synthetic demo / web dashboard:")
        print("    python main.py web --demo")
        sys.exit(1)
    return False


def check_root(required=True):
    return check_capture_privileges(required=required)


def get_default_interface():
    """Detect the default network interface."""
    try:
        # Read the default route to find the primary interface
        with open("/proc/net/route", "r") as f:
            for line in f.readlines()[1:]:
                parts = line.strip().split()
                if parts[1] == "00000000":  # Default route
                    return parts[0]
    except (FileNotFoundError, IndexError):
        pass

    # Fallback: try common interface names
    import subprocess
    try:
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=5
        )
        if result.stdout:
            parts = result.stdout.strip().split()
            if "dev" in parts:
                return parts[parts.index("dev") + 1]
    except (subprocess.SubprocessError, FileNotFoundError):
        pass

    # Last resort fallback
    for iface in ["eth0", "wlan0", "ens33", "enp0s3"]:
        if os.path.exists(f"/sys/class/net/{iface}"):
            return iface

    return "eth0"


def get_local_ips():
    """Get all local IP addresses for this machine."""
    local_ips = {"127.0.0.1", "::1"}
    try:
        import netifaces
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            for family in (netifaces.AF_INET, netifaces.AF_INET6):
                if family in addrs:
                    for addr in addrs[family]:
                        local_ips.add(addr["addr"].split("%")[0])
    except ImportError:
        # Fallback without netifaces
        try:
            hostname = socket.gethostname()
            for info in socket.getaddrinfo(hostname, None):
                local_ips.add(info[4][0])
        except socket.gaierror:
            pass

        # Also try parsing ip command output
        import subprocess
        try:
            result = subprocess.run(
                ["ip", "-o", "addr", "show"],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.strip().split("\n"):
                parts = line.split()
                for i, part in enumerate(parts):
                    if part == "inet" or part == "inet6":
                        addr = parts[i + 1].split("/")[0]
                        local_ips.add(addr)
        except (subprocess.SubprocessError, FileNotFoundError, IndexError):
            pass

    return local_ips


def format_timestamp(dt=None):
    """Format a datetime object for display."""
    if dt is None:
        dt = datetime.now()
    return dt.strftime("%H:%M:%S.%f")[:-3]


def truncate(text, max_length=80):
    """Truncate text with ellipsis if too long."""
    if not text:
        return ""
    text = str(text)
    if len(text) <= max_length:
        return text
    return text[:max_length - 3] + "..."


def bytes_to_human(num_bytes):
    """Convert bytes to human-readable format."""
    for unit in ["B", "KB", "MB", "GB"]:
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} TB"


# Private / reserved IP ranges for filtering
PRIVATE_RANGES = [
    ("10.0.0.0", "10.255.255.255"),
    ("172.16.0.0", "172.31.255.255"),
    ("192.168.0.0", "192.168.255.255"),
    ("127.0.0.0", "127.255.255.255"),
]


def is_private_ip(ip_str):
    """Check if an IP address is in a private range."""
    try:
        import ipaddress
        addr = ipaddress.ip_address(ip_str)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False
