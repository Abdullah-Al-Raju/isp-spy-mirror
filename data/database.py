"""
SQLite database backend — stores all sessions and events
for cross-session analysis and querying.
"""

import sqlite3
import json
import os
from datetime import datetime
from threading import Lock


class Database:

    def __init__(self, db_path="isp_spy.db"):
        self.db_path = db_path
        self._lock = Lock()
        self._conn = None
        self._init_db()

    def _get_conn(self):
        if self._conn is None:
            self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
        return self._conn

    def _init_db(self):
        """Create all tables if they don't exist."""
        with self._lock:
            conn = self._get_conn()
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    started_at TEXT NOT NULL,
                    ended_at TEXT,
                    interface TEXT,
                    duration_seconds REAL,
                    packets_captured INTEGER DEFAULT 0,
                    events_logged INTEGER DEFAULT 0,
                    bytes_sent INTEGER DEFAULT 0,
                    bytes_received INTEGER DEFAULT 0,
                    unique_destinations INTEGER DEFAULT 0,
                    dns_queries INTEGER DEFAULT 0,
                    unique_domains INTEGER DEFAULT 0,
                    tls_handshakes INTEGER DEFAULT 0,
                    http_requests INTEGER DEFAULT 0,
                    leaks_found INTEGER DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id INTEGER NOT NULL,
                    timestamp TEXT,
                    type TEXT,
                    subtype TEXT,
                    destination TEXT,
                    detail TEXT,
                    domain TEXT,
                    sensitive INTEGER DEFAULT 0,
                    geo TEXT,
                    hostname TEXT,
                    severity TEXT,
                    FOREIGN KEY (session_id) REFERENCES sessions(id)
                );

                CREATE TABLE IF NOT EXISTS domains (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id INTEGER NOT NULL,
                    domain TEXT,
                    first_seen TEXT,
                    last_seen TEXT,
                    query_count INTEGER DEFAULT 0,
                    category TEXT,
                    is_tracker INTEGER DEFAULT 0,
                    is_malicious INTEGER DEFAULT 0,
                    FOREIGN KEY (session_id) REFERENCES sessions(id)
                );

                CREATE TABLE IF NOT EXISTS connections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id INTEGER NOT NULL,
                    dst_ip TEXT,
                    dst_port INTEGER,
                    protocol TEXT,
                    hostname TEXT,
                    country TEXT,
                    isp TEXT,
                    first_seen TEXT,
                    last_seen TEXT,
                    packet_count INTEGER DEFAULT 0,
                    bytes INTEGER DEFAULT 0,
                    FOREIGN KEY (session_id) REFERENCES sessions(id)
                );

                CREATE TABLE IF NOT EXISTS leaks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id INTEGER NOT NULL,
                    timestamp TEXT,
                    leak_type TEXT,
                    severity TEXT,
                    destination TEXT,
                    detail TEXT,
                    FOREIGN KEY (session_id) REFERENCES sessions(id)
                );

                CREATE TABLE IF NOT EXISTS fingerprints (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id INTEGER NOT NULL,
                    timestamp TEXT,
                    os_guess TEXT,
                    browser_guess TEXT,
                    device_type TEXT,
                    tls_fingerprint TEXT,
                    tcp_fingerprint TEXT,
                    confidence REAL,
                    FOREIGN KEY (session_id) REFERENCES sessions(id)
                );

                CREATE TABLE IF NOT EXISTS behavior (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id INTEGER NOT NULL,
                    hour INTEGER,
                    minute INTEGER,
                    event_count INTEGER DEFAULT 0,
                    bytes_per_minute INTEGER DEFAULT 0,
                    top_domain TEXT,
                    activity_type TEXT,
                    FOREIGN KEY (session_id) REFERENCES sessions(id)
                );

                CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
                CREATE INDEX IF NOT EXISTS idx_events_type ON events(type);
                CREATE INDEX IF NOT EXISTS idx_domains_session ON domains(session_id);
                CREATE INDEX IF NOT EXISTS idx_connections_session ON connections(session_id);
                CREATE INDEX IF NOT EXISTS idx_leaks_session ON leaks(session_id);
            """)
            conn.commit()

    def create_session(self, interface):
        """Create a new capture session and return its ID."""
        with self._lock:
            conn = self._get_conn()
            cursor = conn.execute(
                "INSERT INTO sessions (started_at, interface) VALUES (?, ?)",
                (datetime.now().isoformat(), interface)
            )
            conn.commit()
            return cursor.lastrowid

    def close_session(self, session_id, stats):
        """Update session record with final statistics."""
        with self._lock:
            conn = self._get_conn()
            meta = stats.get("metadata", {})
            dns = stats.get("dns", {})
            tls = stats.get("tls", {})
            http = stats.get("http", {})
            leaks = stats.get("leaks", {})

            conn.execute("""
                UPDATE sessions SET
                    ended_at = ?,
                    packets_captured = ?,
                    events_logged = ?,
                    bytes_sent = ?,
                    bytes_received = ?,
                    unique_destinations = ?,
                    dns_queries = ?,
                    unique_domains = ?,
                    tls_handshakes = ?,
                    http_requests = ?,
                    leaks_found = ?
                WHERE id = ?
            """, (
                datetime.now().isoformat(),
                stats.get("packets_captured", 0),
                stats.get("events_logged", 0),
                meta.get("bytes_sent", 0),
                meta.get("bytes_received", 0),
                meta.get("unique_destinations", 0),
                dns.get("total_queries", 0),
                dns.get("unique_domains", 0),
                tls.get("total_handshakes", 0),
                http.get("total_requests", 0),
                leaks.get("total_leaks", 0),
                session_id,
            ))
            conn.commit()

    def insert_event(self, session_id, event):
        """Insert a single traffic event."""
        with self._lock:
            conn = self._get_conn()
            conn.execute("""
                INSERT INTO events
                (session_id, timestamp, type, subtype, destination,
                 detail, domain, sensitive, geo, hostname, severity)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                session_id,
                event.get("timestamp", ""),
                event.get("type", ""),
                event.get("subtype", ""),
                event.get("destination", ""),
                event.get("detail", ""),
                event.get("domain", ""),
                1 if event.get("sensitive") else 0,
                event.get("geo", ""),
                event.get("hostname", ""),
                event.get("severity", ""),
            ))
            conn.commit()

    def insert_leak(self, session_id, leak):
        """Insert a detected sensitive leak."""
        with self._lock:
            conn = self._get_conn()
            conn.execute("""
                INSERT INTO leaks
                (session_id, timestamp, leak_type, severity, destination, detail)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                session_id,
                leak.get("timestamp", ""),
                leak.get("leak_type", ""),
                leak.get("severity", ""),
                leak.get("destination", ""),
                leak.get("detail", ""),
            ))
            conn.commit()

    def insert_fingerprint(self, session_id, fp):
        """Insert a device fingerprint result."""
        with self._lock:
            conn = self._get_conn()
            conn.execute("""
                INSERT INTO fingerprints
                (session_id, timestamp, os_guess, browser_guess,
                 device_type, tls_fingerprint, tcp_fingerprint, confidence)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                session_id,
                fp.get("timestamp", ""),
                fp.get("os_guess", ""),
                fp.get("browser_guess", ""),
                fp.get("device_type", ""),
                fp.get("tls_fingerprint", ""),
                fp.get("tcp_fingerprint", ""),
                fp.get("confidence", 0.0),
            ))
            conn.commit()

    def update_domain(self, session_id, domain, category="", is_tracker=False, is_malicious=False):
        """Insert or update a domain record."""
        with self._lock:
            conn = self._get_conn()
            now = datetime.now().isoformat()

            existing = conn.execute(
                "SELECT id, query_count FROM domains WHERE session_id=? AND domain=?",
                (session_id, domain)
            ).fetchone()

            if existing:
                conn.execute("""
                    UPDATE domains SET
                        last_seen=?, query_count=query_count+1,
                        category=?, is_tracker=?, is_malicious=?
                    WHERE id=?
                """, (now, category, 1 if is_tracker else 0,
                      1 if is_malicious else 0, existing["id"]))
            else:
                conn.execute("""
                    INSERT INTO domains
                    (session_id, domain, first_seen, last_seen,
                     query_count, category, is_tracker, is_malicious)
                    VALUES (?, ?, ?, ?, 1, ?, ?, ?)
                """, (session_id, domain, now, now, category,
                      1 if is_tracker else 0, 1 if is_malicious else 0))
            conn.commit()

    def get_all_sessions(self):
        """Return all historical sessions."""
        with self._lock:
            conn = self._get_conn()
            return conn.execute(
                "SELECT * FROM sessions ORDER BY started_at DESC"
            ).fetchall()

    def get_session_events(self, session_id, event_type=None):
        """Return events for a session, optionally filtered by type."""
        with self._lock:
            conn = self._get_conn()
            if event_type:
                return conn.execute(
                    "SELECT * FROM events WHERE session_id=? AND type=? ORDER BY id",
                    (session_id, event_type)
                ).fetchall()
            return conn.execute(
                "SELECT * FROM events WHERE session_id=? ORDER BY id",
                (session_id,)
            ).fetchall()

    def get_cross_session_domains(self, limit=20):
        """Get most seen domains across all sessions."""
        with self._lock:
            conn = self._get_conn()
            return conn.execute("""
                SELECT domain, SUM(query_count) as total,
                       COUNT(DISTINCT session_id) as sessions,
                       MAX(is_tracker) as is_tracker
                FROM domains
                GROUP BY domain
                ORDER BY total DESC
                LIMIT ?
            """, (limit,)).fetchall()

    def get_leak_history(self):
        """Get all leaks across all sessions."""
        with self._lock:
            conn = self._get_conn()
            return conn.execute(
                "SELECT * FROM leaks ORDER BY timestamp DESC"
            ).fetchall()

    def get_recent_sessions(self, limit=10):
        """Get the most recent sessions."""
        with self._lock:
            conn = self._get_conn()
            cursor = conn.execute(
                "SELECT * FROM sessions ORDER BY id DESC LIMIT ?", (limit,)
            )
            return [dict(row) for row in cursor.fetchall()]

    def get_aggregate_stats(self):
        """Aggregate summary statistics across all recorded sessions."""
        with self._lock:
            conn = self._get_conn()
            cursor = conn.execute("""
                SELECT
                    SUM(packets_captured) as packets_captured,
                    SUM(events_logged) as events_logged,
                    SUM(bytes_sent) as bytes_sent,
                    SUM(bytes_received) as bytes_received,
                    SUM(dns_queries) as dns_queries,
                    SUM(unique_domains) as unique_domains,
                    SUM(tls_handshakes) as tls_handshakes,
                    SUM(http_requests) as http_requests,
                    SUM(leaks_found) as leaks_found
                FROM sessions
            """)
            row = cursor.fetchone()
            meta = dict(row) if row else {}
            return {
                "metadata": {
                    "bytes_sent": meta.get("bytes_sent") or 0,
                    "bytes_received": meta.get("bytes_received") or 0,
                    "unique_destinations": 0,
                },
                "dns": {
                    "unique_domains": meta.get("unique_domains") or 0,
                    "total_queries": meta.get("dns_queries") or 0,
                    "top_domains": [],
                },
                "tls": {
                    "unique_domains": meta.get("tls_handshakes") or 0,
                    "total_handshakes": meta.get("tls_handshakes") or 0,
                    "domains": [],
                },
                "http": {
                    "total_requests": meta.get("http_requests") or 0,
                    "unique_urls": 0,
                },
                "leaks": {
                    "total_leaks": meta.get("leaks_found") or 0,
                    "critical_count": meta.get("leaks_found") or 0,
                },
                "packets_captured": meta.get("packets_captured") or 0,
                "events_logged": meta.get("events_logged") or 0,
            }

    def close(self):
        """Close the database connection."""
        with self._lock:
            if self._conn:
                self._conn.close()
                self._conn = None
