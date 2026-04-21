"""
Behavioral profiling — tracks usage patterns over time.
Builds a profile of when you're active, what you do,
and what an ISP could infer about your habits.
"""

import time
from datetime import datetime, timedelta
from collections import defaultdict
from utils.helpers import format_timestamp, truncate


class BehaviorAnalyzer:

    # Activity classification based on domains/ports
    ACTIVITY_PATTERNS = {
        "streaming": {
            "domains": {"youtube.com", "netflix.com", "twitch.tv",
                       "spotify.com", "soundcloud.com", "hulu.com",
                       "disneyplus.com", "primevideo.com", "vimeo.com"},
            "ports": {1935, 8080},
        },
        "social_media": {
            "domains": {"facebook.com", "instagram.com", "twitter.com",
                       "tiktok.com", "reddit.com", "linkedin.com",
                       "snapchat.com", "pinterest.com", "tumblr.com"},
            "ports": set(),
        },
        "communication": {
            "domains": {"telegram.org", "whatsapp.com", "signal.org",
                       "discord.com", "slack.com", "zoom.us",
                       "meet.google.com", "skype.com", "teams.microsoft.com"},
            "ports": {5222, 5269},
        },
        "browsing": {
            "domains": {"google.com", "bing.com", "duckduckgo.com",
                       "wikipedia.org", "stackoverflow.com",
                       "github.com", "medium.com"},
            "ports": {80, 443},
        },
        "gaming": {
            "domains": {"steam.com", "steampowered.com", "epicgames.com",
                       "riotgames.com", "battlenet.com", "ea.com",
                       "playstation.com", "xbox.com"},
            "ports": {27015, 27016, 3478, 3479},
        },
        "shopping": {
            "domains": {"amazon.com", "ebay.com", "etsy.com",
                       "shopify.com", "walmart.com", "aliexpress.com"},
            "ports": set(),
        },
        "news": {
            "domains": {"bbc.com", "cnn.com", "reuters.com",
                       "nytimes.com", "theguardian.com", "ap.org",
                       "aljazeera.com", "washingtonpost.com"},
            "ports": set(),
        },
        "work": {
            "domains": {"github.com", "gitlab.com", "jira.atlassian.com",
                       "confluence.atlassian.com", "notion.so",
                       "trello.com", "asana.com", "office.com",
                       "docs.google.com"},
            "ports": {22, 3389},
        },
        "security_tools": {
            "domains": {"kali.org", "exploit-db.com", "shodan.io",
                       "virustotal.com", "metasploit.com"},
            "ports": {4444, 9050},
        },
        "vpn_proxy": {
            "domains": {"nordvpn.com", "expressvpn.com", "protonvpn.com",
                       "mullvad.net", "torproject.org"},
            "ports": {1194, 51820, 1723, 500, 4500, 9050},
        },
    }

    # Time of day categories
    TIME_PERIODS = {
        (0, 6): "Late Night",
        (6, 9): "Early Morning",
        (9, 12): "Morning",
        (12, 14): "Lunch",
        (14, 18): "Afternoon",
        (18, 21): "Evening",
        (21, 24): "Night",
    }

    def __init__(self):
        self.session_start = datetime.now()

        # Timeline: minute -> list of events
        self._timeline = defaultdict(list)
        # Activity counts
        self._activity_counts = defaultdict(int)
        # Domain visit times
        self._domain_times = defaultdict(list)
        # Bandwidth per minute
        self._bandwidth_timeline = defaultdict(int)
        # Active periods
        self._active_minutes = set()
        # Burst detection
        self._recent_events = []
        # Inferred behaviors
        self._inferences = []
        self._inference_set = set()

        self.event_count = 0
        self.last_activity = datetime.now()
        self._idle_threshold = 60  # seconds

    def analyze_event(self, event):
        """Process any traffic event for behavioral patterns."""
        now = datetime.now()
        minute_key = now.strftime("%H:%M")
        hour = now.hour

        self.event_count += 1
        self.last_activity = now
        self._active_minutes.add(minute_key)

        # Track timeline
        self._timeline[minute_key].append({
            "type": event.get("type", ""),
            "domain": event.get("domain", ""),
            "detail": event.get("detail", ""),
        })

        # Classify activity
        domain = event.get("domain", "").lower()
        dst_port = event.get("dst_port", 0)

        activity = self._classify_activity(domain, dst_port)
        if activity:
            self._activity_counts[activity] += 1
            if domain:
                self._domain_times[domain].append(now)

        # Track recent events for burst detection
        self._recent_events.append(now)
        self._recent_events = [
            t for t in self._recent_events
            if (now - t).total_seconds() < 60
        ]

        # Generate inferences
        inference = self._generate_inference(now, hour, activity, domain)
        if inference:
            return inference

        return None

    def record_bytes(self, num_bytes, direction="sent"):
        """Record bandwidth usage."""
        now = datetime.now()
        minute_key = now.strftime("%H:%M")
        self._bandwidth_timeline[minute_key] += num_bytes

    def _classify_activity(self, domain, port):
        """Classify what type of activity is happening."""
        if not domain and not port:
            return None

        for activity, patterns in self.ACTIVITY_PATTERNS.items():
            # Domain match
            if domain:
                for pattern_domain in patterns["domains"]:
                    if pattern_domain in domain:
                        return activity

            # Port match
            if port and port in patterns.get("ports", set()):
                return activity

        return "general_browsing"

    def _generate_inference(self, now, hour, activity, domain):
        """
        Generate ISP-style behavioral inferences.
        These are what an ISP could sell to advertisers.
        """
        inferences = []

        # Wake-up time detection
        if hour in (6, 7, 8) and self._is_first_activity_today():
            inferences.append(f"Wake-up time detected: ~{now.strftime('%H:%M')}")

        # Work hours detection
        if hour in range(9, 18) and activity == "work":
            inference_key = f"work_{now.strftime('%Y-%m-%d')}"
            if inference_key not in self._inference_set:
                self._inference_set.add(inference_key)
                inferences.append(
                    f"Work activity detected during business hours "
                    f"({now.strftime('%H:%M')})"
                )

        # Late night activity
        if hour in (23, 0, 1, 2, 3) and self.event_count > 5:
            inference_key = f"latenight_{now.strftime('%Y-%m-%d')}"
            if inference_key not in self._inference_set:
                self._inference_set.add(inference_key)
                inferences.append(
                    f"Late night activity — user likely awake at "
                    f"{now.strftime('%H:%M')}"
                )

        # Streaming session detection
        if activity == "streaming":
            stream_count = self._activity_counts.get("streaming", 0)
            if stream_count == 10:
                inferences.append(
                    f"Streaming session in progress on {domain}"
                )

        # Heavy social media use
        if activity == "social_media":
            social_count = self._activity_counts.get("social_media", 0)
            if social_count in (20, 50, 100):
                inferences.append(
                    f"Heavy social media use detected "
                    f"({social_count} connections)"
                )

        # High traffic burst
        if len(self._recent_events) > 30:
            burst_key = f"burst_{now.strftime('%H:%M')}"
            if burst_key not in self._inference_set:
                self._inference_set.add(burst_key)
                inferences.append(
                    f"High traffic burst: {len(self._recent_events)} "
                    f"events in last 60 seconds"
                )

        # VPN/Privacy tools usage
        if activity == "vpn_proxy":
            inference_key = "vpn_usage"
            if inference_key not in self._inference_set:
                self._inference_set.add(inference_key)
                inferences.append(
                    f"Privacy/VPN tool usage detected — "
                    f"user may be privacy-conscious"
                )

        # Security tools (Kali-relevant)
        if activity == "security_tools":
            inference_key = "security_activity"
            if inference_key not in self._inference_set:
                self._inference_set.add(inference_key)
                inferences.append(
                    f"Security research activity detected via {domain}"
                )

        if not inferences:
            return None

        # Build event
        for inference_text in inferences:
            if inference_text not in self._inference_set:
                self._inference_set.add(inference_text)
                self._inferences.append({
                    "time": now,
                    "text": inference_text,
                    "activity": activity,
                })

        if inferences:
            return {
                "timestamp": format_timestamp(),
                "type": "BEHAVIOR",
                "subtype": activity.replace("_", " ").title() if activity else "General",
                "destination": "",
                "detail": inferences[0],
                "sensitive": False,
            }

        return None

    def _is_first_activity_today(self):
        """Check if this is the first activity of the day."""
        today_start = datetime.now().replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        session_age = (datetime.now() - self.session_start).total_seconds()
        return session_age < 300  # First 5 minutes of session

    def get_activity_timeline(self):
        """Return minute-by-minute activity summary."""
        timeline = []
        for minute, events in sorted(self._timeline.items()):
            timeline.append({
                "minute": minute,
                "event_count": len(events),
                "bandwidth": self._bandwidth_timeline.get(minute, 0),
            })
        return timeline

    def get_time_period(self, hour=None):
        """Get the time period label for an hour."""
        if hour is None:
            hour = datetime.now().hour
        for (start, end), label in self.TIME_PERIODS.items():
            if start <= hour < end:
                return label
        return "Night"

    def get_dominant_activity(self):
        """Return the most frequent activity type."""
        if not self._activity_counts:
            return "Unknown"
        return max(self._activity_counts, key=self._activity_counts.get)

    def get_active_duration(self):
        """Return how many minutes had activity."""
        return len(self._active_minutes)

    def get_isp_profile(self):
        """
        Build the ISP-style behavioral profile —
        what they could sell to data brokers.
        """
        now = datetime.now()
        duration = (now - self.session_start).total_seconds() / 60

        top_activities = sorted(
            self._activity_counts.items(),
            key=lambda x: x[1], reverse=True
        )[:5]

        top_domains = sorted(
            [(d, len(times)) for d, times in self._domain_times.items()],
            key=lambda x: x[1], reverse=True
        )[:10]

        profile = {
            "session_duration_minutes": round(duration, 1),
            "active_minutes": self.get_active_duration(),
            "total_events": self.event_count,
            "dominant_activity": self.get_dominant_activity(),
            "time_period": self.get_time_period(),
            "top_activities": top_activities,
            "top_domains": top_domains,
            "inferences": [i["text"] for i in self._inferences],
            "wake_time": self._estimate_wake_time(),
            "sleep_pattern": self._estimate_sleep_pattern(),
            "interests": self._derive_interests(),
        }

        return profile

    def _estimate_wake_time(self):
        """Estimate wake-up time from first morning activity."""
        start_hour = self.session_start.hour
        if 4 <= start_hour <= 10:
            return self.session_start.strftime("%H:%M")
        return "Unknown"

    def _estimate_sleep_pattern(self):
        """Classify sleep pattern from activity hours."""
        hour = self.session_start.hour
        if 22 <= hour or hour < 2:
            return "Night owl"
        elif 5 <= hour < 8:
            return "Early bird"
        elif 8 <= hour < 11:
            return "Normal schedule"
        return "Unknown"

    def _derive_interests(self):
        """Derive user interests from activity patterns."""
        interests = []
        activity_map = {
            "streaming": "Media consumption",
            "social_media": "Social networking",
            "gaming": "Gaming",
            "shopping": "Online shopping",
            "news": "News & current events",
            "work": "Professional/Work",
            "communication": "Messaging & communication",
            "security_tools": "Cybersecurity",
            "vpn_proxy": "Privacy & anonymity",
        }
        for activity, count in self._activity_counts.items():
            if count >= 3 and activity in activity_map:
                interests.append(activity_map[activity])
        return interests

    def get_stats(self):
        return {
            "total_events": self.event_count,
            "active_minutes": self.get_active_duration(),
            "dominant_activity": self.get_dominant_activity(),
            "activity_breakdown": dict(self._activity_counts),
            "inferences_made": len(self._inferences),
            "inferences": [i["text"] for i in self._inferences[-5:]],
            "time_period": self.get_time_period(),
            "isp_profile": self.get_isp_profile(),
        }
