"""
Reverse DNS hostname resolver with caching.
"""

import socket
from threading import Lock
from collections import OrderedDict


class HostnameResolver:

    def __init__(self, cache_size=2048, timeout=1.0):
        self.cache_size = cache_size
        self.timeout = timeout
        self._cache = OrderedDict()
        self._lock = Lock()

    def resolve(self, ip_address):
        if not ip_address:
            return None

        with self._lock:
            if ip_address in self._cache:
                self._cache.move_to_end(ip_address)
                return self._cache[ip_address]

        hostname = self._do_lookup(ip_address)

        with self._lock:
            self._cache[ip_address] = hostname
            while len(self._cache) > self.cache_size:
                self._cache.popitem(last=False)

        return hostname

    def _do_lookup(self, ip_address):
        try:
            old_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(self.timeout)
            hostname, _, _ = socket.gethostbyaddr(ip_address)
            socket.setdefaulttimeout(old_timeout)
            return hostname
        except (socket.herror, socket.gaierror, socket.timeout, OSError):
            return None

    def get_display_name(self, ip_address):
        hostname = self.resolve(ip_address)
        if hostname:
            return f"{hostname} ({ip_address})"
        return ip_address

    def get_cache_stats(self):
        with self._lock:
            resolved = sum(1 for v in self._cache.values() if v is not None)
            return {
                "cache_size": len(self._cache),
                "resolved": resolved,
                "unresolvable": len(self._cache) - resolved,
            }
