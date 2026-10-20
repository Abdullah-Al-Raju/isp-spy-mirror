"""
Automated test suite for ISP Spy Mirror.
Verifies protocol analyzers, sensitive leak detectors, ECH detection,
synthetic traffic generator, capture engine, database, and web endpoints.
Author: Abduallah Al Raju
"""

import os
import sys
import tempfile
import pytest
from scapy.all import IP, TCP, UDP, DNS, DNSQR, Raw

from analyzers.dns_analyzer import DNSAnalyzer
from analyzers.tls_analyzer import TLSAnalyzer
from analyzers.sensitive_detector import SensitiveDetector
from analyzers.tracker_analyzer import TrackerAnalyzer
from analyzers.vpn_leak_detector import VPNLeakDetector
from analyzers.fingerprint_analyzer import FingerprintAnalyzer
from simulation.traffic_generator import SyntheticTrafficGenerator
from capture import CaptureEngine
from data.database import Database
from reports.dossier import ISPDossier
from reports.html_report import HTMLReport


def test_dns_analyzer_query():
    analyzer = DNSAnalyzer()
    pkt = (
        IP(src="192.168.1.100", dst="1.1.1.1")
        / UDP(sport=53421, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="privacy-test.org", qtype="A"))
    )
    events = analyzer.analyze(pkt)
    assert len(events) == 1
    event = events[0]
    assert event["type"] == "DNS"
    assert event["subtype"] == "Query"
    assert event["domain"] == "privacy-test.org"
    assert event["query_type"] == "A"
    assert "privacy-test.org" in analyzer.domains_seen


def test_tls_analyzer_sni_and_ech():
    analyzer = TLSAnalyzer()
    gen = SyntheticTrafficGenerator(packet_callback=None)

    # Standard plaintext SNI
    pkt_sni = gen.build_tls_client_hello_packet("secure-bank.com", ech=False)
    events_sni = analyzer.analyze(pkt_sni)
    assert len(events_sni) == 1
    assert events_sni[0]["domain"] == "secure-bank.com"
    assert events_sni[0]["ech"] is False
    assert "Exposed" in events_sni[0]["subtype"]

    # ECH Protected handshake
    pkt_ech = gen.build_tls_client_hello_packet("cloudflare-ech.com", ech=True)
    events_ech = analyzer.analyze(pkt_ech)
    assert len(events_ech) == 1
    assert events_ech[0]["domain"] == "cloudflare-ech.com"
    assert events_ech[0]["ech"] is True
    assert "ECH Protected" in events_ech[0]["subtype"]

    stats = analyzer.get_stats()
    assert stats["total_handshakes"] == 2
    assert stats["ech_protected_handshakes"] == 1


def test_sensitive_detector_credentials():
    detector = SensitiveDetector()
    raw_payload = b"POST /login HTTP/1.1\r\n\r\nuser=testuser&password=SuperSecretPassword123"
    leaks = detector.scan_raw_payload(raw_payload, dst_ip="192.168.1.1", dst_port=80)
    assert len(leaks) >= 1
    types = [l["leak_type"] for l in leaks]
    assert "Plaintext Password" in types or "Plaintext Username/Email" in types


def test_sensitive_detector_jwt_and_cloud_keys():
    detector = SensitiveDetector()
    jwt_token = b"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFsaWNlIn0.g5Xw48e"
    leaks = detector.scan_raw_payload(jwt_token, dst_ip="10.0.0.1", dst_port=80)
    leak_types = [l["leak_type"] for l in leaks]
    assert "JSON Web Token (JWT)" in leak_types

    aws_payload = b"X-Custom-Auth: AKIAIOSFODNN7EXAMPLE\r\n\r\n"
    leaks_aws = detector.scan_raw_payload(aws_payload, dst_ip="10.0.0.1", dst_port=80)
    leak_types_aws = [l["leak_type"] for l in leaks_aws]
    assert "AWS Access Key ID" in leak_types_aws


def test_sensitive_detector_http_event_url_query_and_cookie():
    detector = SensitiveDetector()
    http_event = {
        "url": "http://insecure-site.com/search?api_key=secret_prod_key_999",
        "destination": "93.184.216.34:80",
        "timestamp": "12:00:00",
        "headers": {
            "cookie": "session=sess_abcdef123456789; track=1",
            "authorization": "Basic dXNlcjpwYXNz",
        },
    }
    leaks = detector.scan_http_event(http_event)
    assert len(leaks) >= 2
    subtypes = [l["subtype"] for l in leaks]
    assert "URL Query Credential" in subtypes or "Auth Header" in subtypes


def test_tracker_analyzer():
    analyzer = TrackerAnalyzer()
    event_ga = {"domain": "google-analytics.com", "type": "DNS"}
    result_ga = analyzer.analyze_domain("google-analytics.com", event_ga)
    assert result_ga is not None
    assert result_ga["type"] == "TRACKER"
    assert "Google" in result_ga["company"]

    event_criteo = {"domain": "criteo.com", "type": "DNS"}
    result_criteo = analyzer.analyze_domain("criteo.com", event_criteo)
    assert result_criteo is not None
    assert result_criteo["company"] == "Criteo"


def test_vpn_leak_detector():
    detector = VPNLeakDetector(interface="eth0")
    detector.vpn_active = True
    detector.vpn_interface = "tun0"

    # DNS query to Google DNS bypassing VPN
    pkt = (
        IP(src="192.168.1.100", dst="8.8.8.8")
        / UDP(sport=53421, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="leaked-query.internal"))
    )
    events = detector.analyze(pkt)
    assert len(events) >= 1
    assert "VPN LEAK" in events[0]["type"]
    assert events[0]["subtype"] == "DNS Leak"


def test_synthetic_traffic_generator_packets():
    gen = SyntheticTrafficGenerator(packet_callback=None)
    dns_pkt = gen.build_dns_query_packet("example.com")
    assert dns_pkt.haslayer(DNS)
    assert dns_pkt.haslayer(DNSQR)

    http_pkt = gen.build_http_packet(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    assert http_pkt.haslayer(TCP)
    assert http_pkt.haslayer(Raw)

    tls_pkt = gen.build_tls_client_hello_packet("example.com", ech=True)
    assert tls_pkt.haslayer(TCP)
    assert tls_pkt.haslayer(Raw)


def test_capture_engine_simulation_and_privacy_score():
    with tempfile.NamedTemporaryFile(suffix=".db") as tmp_db:
        engine = CaptureEngine(
            interface="test0",
            duration=None,
            simulate=False,
            geo_enabled=False,
            db_path=tmp_db.name,
        )

        gen = SyntheticTrafficGenerator(packet_callback=engine._process_packet)

        # Baseline score with no traffic
        score_base = engine.get_privacy_score()
        assert score_base["score"] == 100
        assert score_base["grade"] == "A+"

        # Inject credential leak
        gen.inject_credential_leak()
        score_leak = engine.get_privacy_score()
        assert score_leak["score"] < 100
        assert score_leak["critical_leaks"] >= 1

        # Test pause / resume
        engine.pause()
        assert engine.is_paused() is True
        initial_count = engine.packet_count
        gen.build_dns_query_packet("test.org")
        engine._process_packet(gen.build_dns_query_packet("test.org"))
        assert engine.packet_count == initial_count  # Dropped while paused

        engine.resume()
        assert engine.is_paused() is False
        engine._process_packet(gen.build_dns_query_packet("test.org"))
        assert engine.packet_count == initial_count + 1


def test_database_persistence():
    with tempfile.NamedTemporaryFile(suffix=".db") as tmp_db:
        db = Database(db_path=tmp_db.name)
        session_id = db.create_session(interface="eth0")
        assert session_id is not None

        db.insert_event(session_id, {
            "timestamp": "12:00:00",
            "type": "DNS",
            "subtype": "Query",
            "destination": "1.1.1.1",
            "detail": "example.com (A)",
            "domain": "example.com",
            "sensitive": False,
            "geo": "US",
            "hostname": "one.one.one.one",
            "severity": "INFO",
        })

        db.insert_leak(session_id, {
            "timestamp": "12:00:01",
            "leak_type": "Plaintext Password",
            "severity": "CRITICAL",
            "destination": "93.184.216.34:80",
            "detail": "Password leaked in cleartext",
            "domain": "insecure.com",
        })

        db.update_domain(session_id, "example.com", "Search", False, False)
        db.close_session(session_id, {"packets_captured": 10, "events_logged": 2})

        sessions = db.get_recent_sessions(5)
        assert len(sessions) >= 1
        assert sessions[0]["interface"] == "eth0"
        db.close()


def test_isp_dossier_and_html_report_generation():
    stats = {
        "metadata": {"bytes_sent": 1024, "bytes_received": 4096, "unique_destinations": 5},
        "dns": {"unique_domains": 10, "top_domains": [("google.com", 5), ("github.com", 3)]},
        "tls": {"unique_domains": 4, "domains": ["google.com", "github.com"]},
        "http": {"total_requests": 2, "unique_urls": 2},
        "fingerprint": {"best_guess": {"os": "Linux", "browser": "Chrome", "device": "Desktop"}},
        "tracker": {"companies": ["Google", "Meta"], "categories": {"Tracking": 2}, "top_trackers": []},
        "behavior": {"isp_profile": {"dominant_activity": "Software Engineering", "active_minutes": 15}},
        "leaks": {"total_leaks": 1, "critical_count": 1, "leak_types": {"Plaintext Password": 1}},
        "vpn_leak": {"vpn_active": False, "total_leaks": 0},
        "dns_spoof": {"spoofs_detected": 0},
        "packets_captured": 45,
    }

    # Test Dossier
    dossier_gen = ISPDossier(stats)
    dossier = dossier_gen.dossier
    assert "report_id" in dossier
    assert dossier["executive_summary"]["dominant_activity"] == "Software Engineering"
    assert dossier["device_profile"]["operating_system"] == "Linux"

    # Test HTML Report
    with tempfile.TemporaryDirectory() as tmp_dir:
        html_gen = HTMLReport()
        report_path = html_gen.generate(stats, output_dir=tmp_dir)
        assert os.path.exists(report_path)
        with open(report_path) as f:
            content = f.read()
        assert "ISP Spy Mirror" in content
        assert "Software Engineering" in content


def test_fastapi_rest_endpoints():
    from fastapi.testclient import TestClient
    from web_app import app, get_active_engine

    client = TestClient(app)

    # Status endpoint
    res_status = client.get("/api/status")
    assert res_status.status_code == 200
    data_status = res_status.json()
    assert data_status["status"] == "online"
    assert "telemetry" in data_status

    # Stats endpoint
    res_stats = client.get("/api/stats")
    assert res_stats.status_code == 200

    # Dossier endpoint
    res_dossier = client.get("/api/dossier")
    assert res_dossier.status_code == 200
    assert "report_id" in res_dossier.json()

    # Scenario injection endpoint
    res_inject = client.post("/api/control/inject", json={"scenario": "credential_leak"})
    assert res_inject.status_code == 200
    assert res_inject.json()["status"] == "injected"

    # Control pause / resume
    res_pause = client.post("/api/control/pause")
    assert res_pause.status_code == 200
    assert res_pause.json()["paused"] is True

    res_resume = client.post("/api/control/resume")
    assert res_resume.status_code == 200
    assert res_resume.json()["paused"] is False
