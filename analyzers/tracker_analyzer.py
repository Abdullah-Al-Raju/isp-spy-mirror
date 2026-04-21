"""
Tracker and ad network mapper — identifies tracking companies,
ad networks, and data brokers in your traffic.
"""

import re
from utils.helpers import format_timestamp, truncate


class TrackerAnalyzer:

    # Major tracking/ad domains and their companies
    TRACKER_DB = {
        # Google
        "google-analytics.com": ("Google Analytics", "Analytics"),
        "googletagmanager.com": ("Google Tag Manager", "Analytics"),
        "googleadservices.com": ("Google Ads", "Advertising"),
        "googlesyndication.com": ("Google AdSense", "Advertising"),
        "googletagservices.com": ("Google Tag Services", "Analytics"),
        "doubleclick.net": ("Google DoubleClick", "Advertising"),
        "google.com/ads": ("Google Ads", "Advertising"),
        "ads.google.com": ("Google Ads", "Advertising"),
        "pagead2.googlesyndication.com": ("Google PageAd", "Advertising"),

        # Facebook/Meta
        "facebook.com/tr": ("Facebook Pixel", "Tracking"),
        "connect.facebook.net": ("Facebook Connect", "Tracking"),
        "graph.facebook.com": ("Facebook Graph API", "Tracking"),
        "pixel.facebook.com": ("Facebook Pixel", "Tracking"),
        "analytics.facebook.com": ("Facebook Analytics", "Analytics"),

        # Amazon
        "amazon-adsystem.com": ("Amazon Ads", "Advertising"),
        "assoc-amazon.com": ("Amazon Associates", "Advertising"),
        "fls-na.amazon.com": ("Amazon Tracking", "Tracking"),

        # Microsoft
        "bat.bing.com": ("Microsoft/Bing Ads", "Advertising"),
        "clarity.ms": ("Microsoft Clarity", "Analytics"),
        "c.microsoft.com": ("Microsoft Telemetry", "Telemetry"),
        "telemetry.microsoft.com": ("Microsoft Telemetry", "Telemetry"),
        "vortex.data.microsoft.com": ("Microsoft Vortex", "Telemetry"),
        "settings-win.data.microsoft.com": ("Windows Telemetry", "Telemetry"),

        # Twitter/X
        "ads-twitter.com": ("Twitter Ads", "Advertising"),
        "analytics.twitter.com": ("Twitter Analytics", "Analytics"),
        "static.ads-twitter.com": ("Twitter Ads", "Advertising"),
        "t.co": ("Twitter Tracking", "Tracking"),

        # Analytics
        "hotjar.com": ("Hotjar", "Analytics"),
        "mouseflow.com": ("Mouseflow", "Analytics"),
        "fullstory.com": ("FullStory", "Analytics"),
        "mixpanel.com": ("Mixpanel", "Analytics"),
        "segment.com": ("Segment", "Analytics"),
        "amplitude.com": ("Amplitude", "Analytics"),
        "heap.io": ("Heap Analytics", "Analytics"),
        "newrelic.com": ("New Relic", "Analytics"),
        "datadog-browser-agent.com": ("DataDog", "Analytics"),

        # Ad networks
        "criteo.com": ("Criteo", "Advertising"),
        "criteo.net": ("Criteo", "Advertising"),
        "taboola.com": ("Taboola", "Advertising"),
        "outbrain.com": ("Outbrain", "Advertising"),
        "pubmatic.com": ("PubMatic", "Advertising"),
        "rubiconproject.com": ("Rubicon Project", "Advertising"),
        "openx.net": ("OpenX", "Advertising"),
        "casalemedia.com": ("Index Exchange", "Advertising"),
        "moatads.com": ("Moat/Oracle", "Advertising"),
        "adsrvr.org": ("The Trade Desk", "Advertising"),
        "adnxs.com": ("AppNexus/Xandr", "Advertising"),
        "yldbt.com": ("Yieldbot", "Advertising"),
        "contextweb.com": ("Pulsepoint", "Advertising"),
        "lijit.com": ("Sovrn", "Advertising"),
        "rlcdn.com": ("Rapt Media", "Advertising"),
        "crwdcntrl.net": ("Lotame", "Data Broker"),
        "bluekai.com": ("Oracle BlueKai", "Data Broker"),

        # Data brokers
        "acxiom.com": ("Acxiom", "Data Broker"),
        "liveramp.com": ("LiveRamp", "Data Broker"),
        "quantcast.com": ("Quantcast", "Data Broker"),
        "nielsen.com": ("Nielsen", "Data Broker"),
        "comscore.com": ("Comscore", "Analytics"),
        "scorecardresearch.com": ("Scorecard Research", "Analytics"),

        # CDN/Fingerprinting
        "fingerprintjs.com": ("FingerprintJS", "Fingerprinting"),
        "fpjscdn.net": ("FingerprintJS CDN", "Fingerprinting"),

        # Social tracking
        "linkedin.com/li/track": ("LinkedIn Insight", "Tracking"),
        "snap.licdn.com": ("LinkedIn Tracking", "Tracking"),
        "pinterest.com/ct": ("Pinterest Tag", "Tracking"),

        # OS Telemetry
        "ubuntu.com/telemetry": ("Ubuntu Telemetry", "Telemetry"),
        "incoming.telemetry.mozilla.org": ("Firefox Telemetry", "Telemetry"),
        "telemetry.mozilla.org": ("Firefox Telemetry", "Telemetry"),
        "crash-reports.mozilla.com": ("Firefox Crash", "Telemetry"),
        "safebrowsing.googleapis.com": ("Google Safe Browsing", "Security"),

        # Spyware/PUPs (if present)
        "spyware.com": ("Known Spyware", "Malicious"),
        "track.clicksense.com": ("ClickSense", "Suspicious"),
    }

    # Category colors for display
    CATEGORY_STYLES = {
        "Advertising": "yellow",
        "Analytics": "cyan",
        "Tracking": "red",
        "Data Broker": "bold red",
        "Telemetry": "blue",
        "Fingerprinting": "magenta",
        "Security": "green",
        "Malicious": "bold red",
        "Suspicious": "orange3",
    }

    def __init__(self):
        self.trackers_found = {}  # domain -> (company, category, count)
        self.tracker_count = 0
        self.companies_seen = set()
        self.categories = {}

    def analyze_domain(self, domain, event):
        """
        Check if a domain belongs to a tracker/ad network.
        Returns an event dict if tracker found, else None.
        """
        if not domain:
            return None

        domain_lower = domain.lower().strip(".")

        # Direct match
        tracker_info = self._lookup_tracker(domain_lower)
        if not tracker_info:
            return None

        company, category = tracker_info

        # Track statistics
        if domain_lower not in self.trackers_found:
            self.trackers_found[domain_lower] = [company, category, 0]
        self.trackers_found[domain_lower][2] += 1
        self.tracker_count += 1
        self.companies_seen.add(company)
        self.categories[category] = self.categories.get(category, 0) + 1

        style = self.CATEGORY_STYLES.get(category, "white")
        is_sensitive = category in ("Data Broker", "Tracking", "Malicious", "Suspicious")

        return {
            "timestamp": format_timestamp(),
            "type": "TRACKER",
            "subtype": category,
            "destination": event.get("destination", domain),
            "detail": f"{company} — tracking via {truncate(domain_lower, 50)}",
            "sensitive": is_sensitive,
            "company": company,
            "category": category,
            "domain": domain_lower,
            "style": style,
        }

    def _lookup_tracker(self, domain):
        """Look up a domain in the tracker database."""
        # Exact match first
        if domain in self.TRACKER_DB:
            return self.TRACKER_DB[domain]

        # Check if domain ends with a known tracker domain
        for tracker_domain, info in self.TRACKER_DB.items():
            if domain == tracker_domain or domain.endswith("." + tracker_domain):
                return info

        # Check substrings (for path-based trackers)
        for tracker_domain, info in self.TRACKER_DB.items():
            if tracker_domain in domain:
                return info

        return None

    def get_tracking_companies(self):
        """Return sorted list of tracking companies found."""
        company_counts = {}
        for domain, (company, category, count) in self.trackers_found.items():
            key = (company, category)
            company_counts[key] = company_counts.get(key, 0) + count
        return sorted(company_counts.items(), key=lambda x: x[1], reverse=True)

    def get_stats(self):
        return {
            "total_tracker_hits": self.tracker_count,
            "unique_trackers": len(self.trackers_found),
            "unique_companies": len(self.companies_seen),
            "categories": self.categories,
            "top_trackers": sorted(
                [(d, info[0], info[1], info[2])
                 for d, info in self.trackers_found.items()],
                key=lambda x: x[3], reverse=True
            )[:10],
            "companies": list(self.companies_seen),
        }
