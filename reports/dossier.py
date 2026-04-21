"""
ISP Dossier Mode — generates a realistic intelligence report
showing what an ISP could sell to data brokers.
"""

import os
import json
from datetime import datetime
from utils.helpers import bytes_to_human


class ISPDossier:

    def __init__(self, stats):
        self.stats = stats
        self.dossier = self._generate()

    def _generate(self):
        meta = self.stats.get("metadata", {})
        dns = self.stats.get("dns", {})
        tls = self.stats.get("tls", {})
        http = self.stats.get("http", {})
        fp = self.stats.get("fingerprint", {})
        best = fp.get("best_guess", {})
        tracker = self.stats.get("tracker", {})
        behavior = self.stats.get("behavior", {})
        profile = behavior.get("isp_profile", {})
        leaks = self.stats.get("leaks", {})
        vpn = self.stats.get("vpn_leak", {})
        spoof = self.stats.get("dns_spoof", {})

        total_issues = (leaks.get("total_leaks", 0) +
                       vpn.get("total_leaks", 0) +
                       spoof.get("spoofs_detected", 0))

        return {
            "report_id": f"ISP-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            "classification": "CONFIDENTIAL — ISP INTERNAL",
            "generated_at": datetime.now().isoformat(),
            "subject": "Subscriber Network Activity Profile",

            "executive_summary": {
                "total_packets": self.stats.get("packets_captured", 0),
                "data_sent": bytes_to_human(meta.get("bytes_sent", 0)),
                "data_received": bytes_to_human(meta.get("bytes_received", 0)),
                "unique_destinations": meta.get("unique_destinations", 0),
                "risk_level": "HIGH" if total_issues > 0 else "LOW",
                "dominant_activity": profile.get("dominant_activity", "Unknown"),
            },

            "websites_visited": {
                "dns_domains": dns.get("unique_domains", 0),
                "https_domains": tls.get("unique_domains", 0),
                "top_domains": dns.get("top_domains", [])[:15],
                "https_sites": sorted(tls.get("domains", []))[:30],
                "plaintext_http_requests": http.get("total_requests", 0),
                "plaintext_urls": http.get("unique_urls", 0),
            },

            "device_profile": {
                "operating_system": best.get("os", "Unknown"),
                "browser": best.get("browser", "Unknown"),
                "device_type": best.get("device", "Unknown"),
                "ja3_fingerprints": best.get("ja3_count", 0),
                "user_agents_seen": fp.get("unique_user_agents", 0),
            },

            "behavioral_analysis": {
                "primary_activity": profile.get("dominant_activity", "Unknown"),
                "time_of_day": profile.get("time_period", "Unknown"),
                "active_duration_minutes": profile.get("active_minutes", 0),
                "sleep_pattern": profile.get("sleep_pattern", "Unknown"),
                "derived_interests": profile.get("interests", []),
                "behavioral_inferences": profile.get("inferences", []),
            },

            "advertising_profile": {
                "tracking_companies": len(tracker.get("companies", [])),
                "company_list": tracker.get("companies", [])[:20],
                "tracker_categories": tracker.get("categories", {}),
                "total_tracking_hits": tracker.get("total_tracker_hits", 0),
                "top_trackers": [
                    {"domain": d, "company": c, "category": cat, "hits": h}
                    for d, c, cat, h in tracker.get("top_trackers", [])
                ],
            },

            "security_assessment": {
                "plaintext_data_leaks": leaks.get("total_leaks", 0),
                "critical_leaks": leaks.get("critical_count", 0),
                "leak_types": leaks.get("leak_types", {}),
                "vpn_detected": vpn.get("vpn_active", False),
                "vpn_leaks": vpn.get("total_leaks", 0),
                "dns_spoofing_alerts": spoof.get("spoofs_detected", 0),
            },

            "monetization_potential": {
                "sellable_data_points": self._count_sellable_data(profile, tracker, dns),
                "advertiser_categories": self._suggest_ad_categories(profile),
                "data_broker_value": self._estimate_value(profile, tracker),
            },

            "recommendations_for_subscriber": [
                "Use a VPN to hide destination metadata from ISP",
                "Enable DNS-over-HTTPS (DoH) to encrypt DNS queries",
                "Avoid plaintext HTTP — always use HTTPS",
                "Use browser extensions to block trackers (uBlock Origin)",
                "Consider using Tor for sensitive browsing",
                "Review which apps send data in plaintext",
                "Use encrypted messaging (Signal) instead of SMS",
            ],
        }

    def _count_sellable_data(self, profile, tracker, dns):
        count = 0
        count += dns.get("unique_domains", 0)  # Every domain is sellable
        count += len(profile.get("interests", []))
        count += tracker.get("total_tracker_hits", 0)
        count += len(profile.get("inferences", []))
        return count

    def _suggest_ad_categories(self, profile):
        interest_to_ads = {
            "Media consumption": ["Streaming services", "Entertainment", "Smart TV"],
            "Social networking": ["Social apps", "Dating", "Events"],
            "Gaming": ["Gaming hardware", "Game subscriptions", "Esports"],
            "Online shopping": ["E-commerce", "Deals", "Credit cards"],
            "News & current events": ["News subscriptions", "Politics"],
            "Professional/Work": ["SaaS", "Business tools", "Recruiting"],
            "Messaging & communication": ["Phone plans", "VoIP"],
            "Cybersecurity": ["Security software", "VPN", "Privacy tools"],
            "Privacy & anonymity": ["VPN", "Encrypted email", "Security"],
        }
        categories = []
        for interest in profile.get("interests", []):
            if interest in interest_to_ads:
                categories.extend(interest_to_ads[interest])
        return list(set(categories)) if categories else ["General consumer"]

    def _estimate_value(self, profile, tracker):
        """Estimate the dollar value of this user's data to brokers."""
        base = 0.50  # Base value per user
        base += len(profile.get("interests", [])) * 0.10
        base += tracker.get("total_tracker_hits", 0) * 0.01
        base += len(profile.get("inferences", [])) * 0.05
        if profile.get("dominant_activity") in ("shopping", "work"):
            base *= 1.5  # Higher value users
        return f"${base:.2f}/month (estimated)"

    def save(self, output_dir="reports/dossiers"):
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = os.path.join(output_dir, f"dossier_{timestamp}.json")
        with open(filepath, "w") as f:
            json.dump(self.dossier, f, indent=2, default=str)
        return filepath

    def to_json(self):
        return json.dumps(self.dossier, indent=2, default=str)
