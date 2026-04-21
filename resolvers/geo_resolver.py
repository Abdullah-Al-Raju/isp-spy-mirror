"""
IP geolocation resolver using ip-api.com free tier.
"""

import time
import requests
from threading import Lock, Thread
from collections import OrderedDict
from queue import Queue


class GeoResolver:

    API_URL = "http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as"
    BATCH_URL = "http://ip-api.com/batch?fields=query,status,country,regionName,city,isp,org,as"
    RATE_LIMIT = 45
    RATE_WINDOW = 60

    def __init__(self, enabled=True, cache_size=1024):
        self.enabled = enabled
        self.cache_size = cache_size
        self._cache = OrderedDict()
        self._lock = Lock()
        self._request_times = []
        self._pending_queue = Queue()
        self._running = False
        self._worker_thread = None

    def start(self):
        if not self.enabled:
            return
        self._running = True
        self._worker_thread = Thread(target=self._worker, daemon=True)
        self._worker_thread.start()

    def stop(self):
        self._running = False
        if self._worker_thread:
            self._worker_thread.join(timeout=3)

    def request_lookup(self, ip_address):
        if not self.enabled:
            return
        with self._lock:
            if ip_address in self._cache:
                return
        self._pending_queue.put(ip_address)

    def get_location(self, ip_address):
        if not self.enabled:
            return None
        with self._lock:
            if ip_address in self._cache:
                self._cache.move_to_end(ip_address)
                return self._cache[ip_address]
        self.request_lookup(ip_address)
        return None

    def get_location_string(self, ip_address):
        geo = self.get_location(ip_address)
        if not geo or geo.get("status") != "success":
            return ""

        parts = []
        city = geo.get("city", "")
        region = geo.get("regionName", "")
        country = geo.get("country", "")

        if city:
            parts.append(city)
        if region and region != city:
            parts.append(region)
        if country:
            parts.append(country)

        location = ", ".join(parts)
        isp = geo.get("isp", "")
        if isp:
            location += f" [{isp}]"

        return location

    def _worker(self):
        batch = []
        last_batch_time = 0

        while self._running:
            try:
                try:
                    ip = self._pending_queue.get(timeout=1.0)
                    with self._lock:
                        if ip not in self._cache:
                            batch.append(ip)
                except Exception:
                    pass

                now = time.time()
                should_process = (
                    (len(batch) >= 10) or
                    (len(batch) > 0 and now - last_batch_time > 5)
                )

                if should_process and batch:
                    if self._can_make_request():
                        self._process_batch(batch[:100])
                        last_batch_time = now
                        batch = batch[100:]

            except Exception:
                time.sleep(1)

    def _can_make_request(self):
        now = time.time()
        self._request_times = [
            t for t in self._request_times
            if now - t < self.RATE_WINDOW
        ]
        return len(self._request_times) < self.RATE_LIMIT

    def _process_batch(self, ips):
        if not ips:
            return
        ips = list(set(ips))
        try:
            if len(ips) == 1:
                self._single_lookup(ips[0])
            else:
                self._batch_lookup(ips)
        except Exception:
            pass

    def _single_lookup(self, ip):
        try:
            response = requests.get(
                self.API_URL.format(ip=ip),
                timeout=3
            )
            self._request_times.append(time.time())
            if response.status_code == 200:
                data = response.json()
                with self._lock:
                    self._cache[ip] = data
                    self._evict_if_needed()
        except (requests.RequestException, ValueError):
            pass

    def _batch_lookup(self, ips):
        try:
            payload = [{"query": ip} for ip in ips[:100]]
            response = requests.post(
                self.BATCH_URL,
                json=payload,
                timeout=5
            )
            self._request_times.append(time.time())
            if response.status_code == 200:
                results = response.json()
                with self._lock:
                    for result in results:
                        ip = result.get("query", "")
                        if ip:
                            self._cache[ip] = result
                    self._evict_if_needed()
        except (requests.RequestException, ValueError):
            for ip in ips[:5]:
                if self._can_make_request():
                    self._single_lookup(ip)
                    time.sleep(0.1)

    def _evict_if_needed(self):
        while len(self._cache) > self.cache_size:
            self._cache.popitem(last=False)

    def get_stats(self):
        with self._lock:
            resolved = sum(
                1 for v in self._cache.values()
                if v.get("status") == "success"
            )
            return {
                "cache_size": len(self._cache),
                "resolved": resolved,
                "pending": self._pending_queue.qsize(),
                "api_calls_in_window": len(self._request_times),
            }
