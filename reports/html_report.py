"""
HTML Report Generator — creates a standalone interactive
HTML report with charts and full session data.
No external dependencies — pure Python string formatting.
"""

import os
import json
from datetime import datetime
from utils.helpers import bytes_to_human


class HTMLReport:

    def generate(self, stats, output_dir="reports/html"):
        os.makedirs(output_dir, exist_ok=True)

        html = self._build_html(stats)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = os.path.join(output_dir, f"report_{timestamp}.html")

        with open(filepath, "w") as f:
            f.write(html)

        return filepath

    def _build_html(self, stats):
        meta = stats.get("metadata", {})
        dns = stats.get("dns", {})
        tls = stats.get("tls", {})
        http = stats.get("http", {})
        fp = stats.get("fingerprint", {})
        best = fp.get("best_guess", {})
        tracker = stats.get("tracker", {})
        behavior = stats.get("behavior", {})
        profile = behavior.get("isp_profile", {})
        leaks = stats.get("leaks", {})
        vpn = stats.get("vpn_leak", {})
        spoof = stats.get("dns_spoof", {})

        total_issues = (leaks.get("total_leaks", 0) +
                       vpn.get("total_leaks", 0) +
                       spoof.get("spoofs_detected", 0))

        # Build domain table rows
        domain_rows = ""
        for domain, count in dns.get("top_domains", [])[:15]:
            domain_rows += f"<tr><td>{domain}</td><td>{count}</td><td>DNS</td></tr>\n"
        for domain in sorted(tls.get("domains", []))[:15]:
            domain_rows += f"<tr><td>{domain}</td><td>-</td><td>TLS/SNI</td></tr>\n"

        # Build tracker table rows
        tracker_rows = ""
        for domain, company, category, count in tracker.get("top_trackers", [])[:15]:
            cat_class = "badge-critical" if category in ("Data Broker", "Tracking") else "badge-warning" if category == "Advertising" else "badge-info"
            tracker_rows += f"""<tr>
                <td>{company}</td>
                <td><span class="badge {cat_class}">{category}</span></td>
                <td>{domain}</td>
                <td>{count}</td>
            </tr>\n"""

        # Build interests list
        interests_html = ""
        for interest in profile.get("interests", []):
            interests_html += f"<li>{interest}</li>\n"
        if not interests_html:
            interests_html = "<li>Not enough data yet</li>"

        # Build inferences list
        inferences_html = ""
        for inf in profile.get("inferences", [])[-8:]:
            inferences_html += f"<li>{inf}</li>\n"
        if not inferences_html:
            inferences_html = "<li>No inferences generated yet</li>"

        # Security issue rows
        security_rows = ""
        if leaks.get("total_leaks", 0) > 0:
            security_rows += f"""<tr>
                <td>Plaintext Data Leaks</td>
                <td>{leaks.get("total_leaks", 0)}</td>
                <td><span class="badge badge-critical">Critical: {leaks.get("critical_count", 0)}</span></td>
            </tr>\n"""
        if vpn.get("total_leaks", 0) > 0:
            security_rows += f"""<tr>
                <td>VPN Leaks</td>
                <td>{vpn.get("total_leaks", 0)}</td>
                <td><span class="badge badge-high">High</span></td>
            </tr>\n"""
        if spoof.get("spoofs_detected", 0) > 0:
            security_rows += f"""<tr>
                <td>DNS Spoofing Alerts</td>
                <td>{spoof.get("spoofs_detected", 0)}</td>
                <td><span class="badge badge-warning">Warning</span></td>
            </tr>\n"""
        if not security_rows:
            security_rows = """<tr>
                <td colspan="3" style="text-align:center; color:#27ae60;">
                    No security issues detected
                </td>
            </tr>\n"""

        # Protocol chart data
        protocols = meta.get("protocols", {})
        proto_labels = json.dumps(list(protocols.keys()))
        proto_values = json.dumps(list(protocols.values()))

        # Category chart data
        categories = tracker.get("categories", {})
        cat_labels = json.dumps(list(categories.keys()))
        cat_values = json.dumps(list(categories.values()))

        # Activity chart data
        activities = behavior.get("activity_breakdown", {})
        act_labels = json.dumps([k.replace("_", " ").title() for k in activities.keys()])
        act_values = json.dumps(list(activities.values()))

        # Top ports
        top_ports = meta.get("top_ports", [])
        port_labels = json.dumps([f"{p}" + (f" ({s})" if s else "") for p, c, s in top_ports[:8]])
        port_values = json.dumps([c for p, c, s in top_ports[:8]])

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ISP Spy Mirror — Privacy Intelligence Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background: #0a0e17;
            color: #e0e0e0;
            padding: 20px;
        }}
        .container {{ max-width: 1400px; margin: 0 auto; }}

        .header {{
            background: linear-gradient(135deg, #1a1f36 0%, #2d1b69 100%);
            padding: 30px;
            border-radius: 12px;
            margin-bottom: 20px;
            border: 1px solid #3d3d6b;
            text-align: center;
        }}
        .header h1 {{ font-size: 28px; color: #00d4ff; margin-bottom: 8px; }}
        .header p {{ color: #8888aa; font-size: 14px; }}

        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin-bottom: 20px; }}
        .grid-3 {{ grid-template-columns: repeat(3, 1fr); }}
        .grid-2 {{ grid-template-columns: repeat(2, 1fr); }}

        .card {{
            background: #141824;
            border: 1px solid #2a2e3f;
            border-radius: 10px;
            padding: 20px;
            transition: border-color 0.3s;
        }}
        .card:hover {{ border-color: #00d4ff; }}
        .card h2 {{ color: #00d4ff; font-size: 18px; margin-bottom: 15px; border-bottom: 1px solid #2a2e3f; padding-bottom: 8px; }}
        .card h3 {{ color: #aab; font-size: 14px; margin: 12px 0 8px 0; }}
        .card.full {{ grid-column: 1 / -1; }}
        .card.alert {{ border-color: #e74c3c; }}
        .card.safe {{ border-color: #27ae60; }}

        .stat-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; }}
        .stat {{
            background: #1a1f36;
            padding: 15px;
            border-radius: 8px;
            text-align: center;
        }}
        .stat-value {{ font-size: 26px; font-weight: bold; color: #00d4ff; }}
        .stat-label {{ font-size: 12px; color: #6b7280; margin-top: 4px; }}

        .table {{ width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 14px; }}
        .table th {{ background: #1a1f36; color: #00d4ff; padding: 10px; text-align: left; font-weight: 600; }}
        .table td {{ padding: 10px; border-bottom: 1px solid #1e2235; }}
        .table tr:hover {{ background: #1a1f36; }}

        .badge {{
            display: inline-block;
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: 600;
            color: white;
        }}
        .badge-critical {{ background: #e74c3c; }}
        .badge-high {{ background: #e67e22; }}
        .badge-warning {{ background: #f39c12; }}
        .badge-info {{ background: #3498db; }}
        .badge-success {{ background: #27ae60; }}
        .badge-tracker {{ background: #9b59b6; }}

        .chart-container {{ position: relative; height: 280px; margin-top: 10px; }}

        .profile-item {{ padding: 8px 0; border-bottom: 1px solid #1e2235; }}
        .profile-item:last-child {{ border: none; }}
        .profile-label {{ color: #6b7280; font-size: 13px; }}
        .profile-value {{ color: #e0e0e0; font-size: 15px; font-weight: 600; }}

        ul {{ padding-left: 20px; }}
        li {{ padding: 4px 0; color: #b0b0b0; }}

        .isp-box {{
            background: linear-gradient(135deg, #1a0a0a 0%, #2d1010 100%);
            border: 1px solid #5a2020;
            border-radius: 10px;
            padding: 25px;
            margin-top: 20px;
        }}
        .isp-box h2 {{ color: #ff6b6b; }}
        .isp-box li {{ color: #ddd; padding: 6px 0; }}

        .footer {{
            text-align: center;
            padding: 20px;
            color: #444;
            font-size: 12px;
            margin-top: 20px;
        }}

        @media (max-width: 768px) {{
            .grid-3, .grid-2 {{ grid-template-columns: 1fr; }}
        }}
    </style>
</head>
<body>
<div class="container">

    <div class="header">
        <h1>ISP Spy Mirror — Full Privacy Intelligence Audit</h1>
        <p>Generated: {timestamp} | Packets: {stats.get("packets_captured", 0):,} | Events: {stats.get("events_logged", 0):,}</p>
    </div>

    <!-- Overview Stats -->
    <div class="card full">
        <h2>Session Overview</h2>
        <div class="stat-grid">
            <div class="stat">
                <div class="stat-value">{stats.get("packets_captured", 0):,}</div>
                <div class="stat-label">Packets</div>
            </div>
            <div class="stat">
                <div class="stat-value">{stats.get("events_logged", 0):,}</div>
                <div class="stat-label">Events</div>
            </div>
            <div class="stat">
                <div class="stat-value">{bytes_to_human(meta.get("bytes_sent", 0))}</div>
                <div class="stat-label">Data Sent</div>
            </div>
            <div class="stat">
                <div class="stat-value">{bytes_to_human(meta.get("bytes_received", 0))}</div>
                <div class="stat-label">Data Received</div>
            </div>
            <div class="stat">
                <div class="stat-value">{meta.get("unique_destinations", 0)}</div>
                <div class="stat-label">Destinations</div>
            </div>
            <div class="stat">
                <div class="stat-value">{dns.get("unique_domains", 0)}</div>
                <div class="stat-label">DNS Domains</div>
            </div>
            <div class="stat">
                <div class="stat-value">{tls.get("unique_domains", 0)}</div>
                <div class="stat-label">HTTPS Sites</div>
            </div>
            <div class="stat">
                <div class="stat-value">{http.get("total_requests", 0)}</div>
                <div class="stat-label">HTTP (plaintext!)</div>
            </div>
        </div>
    </div>

    <!-- Charts Row -->
    <div class="grid grid-2">
        <div class="card">
            <h2>Protocol Distribution</h2>
            <div class="chart-container">
                <canvas id="protoChart"></canvas>
            </div>
        </div>
        <div class="card">
            <h2>Top Ports</h2>
            <div class="chart-container">
                <canvas id="portChart"></canvas>
            </div>
        </div>
    </div>

    <!-- Domains -->
    <div class="card full">
        <h2>Websites Visited ({dns.get("unique_domains", 0)} DNS + {tls.get("unique_domains", 0)} TLS SNI)</h2>
        <table class="table">
            <thead><tr><th>Domain</th><th>Queries</th><th>Source</th></tr></thead>
            <tbody>{domain_rows}</tbody>
        </table>
    </div>

    <!-- Intel Row -->
    <div class="grid grid-3">
        <div class="card">
            <h2>Device Fingerprint</h2>
            <div class="profile-item">
                <div class="profile-label">Operating System</div>
                <div class="profile-value">{best.get("os", "Unknown")}</div>
            </div>
            <div class="profile-item">
                <div class="profile-label">Browser</div>
                <div class="profile-value">{best.get("browser", "Unknown")}</div>
            </div>
            <div class="profile-item">
                <div class="profile-label">Device Type</div>
                <div class="profile-value">{best.get("device", "Unknown")}</div>
            </div>
            <div class="profile-item">
                <div class="profile-label">JA3 Fingerprints</div>
                <div class="profile-value">{best.get("ja3_count", 0)}</div>
            </div>
        </div>

        <div class="card">
            <h2>Behavioral Profile</h2>
            <div class="profile-item">
                <div class="profile-label">Primary Activity</div>
                <div class="profile-value">{profile.get("dominant_activity", "Unknown").replace("_", " ").title()}</div>
            </div>
            <div class="profile-item">
                <div class="profile-label">Time Period</div>
                <div class="profile-value">{profile.get("time_period", "Unknown")}</div>
            </div>
            <div class="profile-item">
                <div class="profile-label">Sleep Pattern</div>
                <div class="profile-value">{profile.get("sleep_pattern", "Unknown")}</div>
            </div>
            <div class="profile-item">
                <div class="profile-label">Active Duration</div>
                <div class="profile-value">{profile.get("active_minutes", 0)} minutes</div>
            </div>
        </div>

        <div class="card">
            <h2>Derived Interests</h2>
            <ul>{interests_html}</ul>
            <h3>ISP Inferences</h3>
            <ul>{inferences_html}</ul>
        </div>
    </div>

    <!-- Activity Chart -->
    <div class="grid grid-2">
        <div class="card">
            <h2>Activity Breakdown</h2>
            <div class="chart-container">
                <canvas id="activityChart"></canvas>
            </div>
        </div>
        <div class="card">
            <h2>Tracker Categories</h2>
            <div class="chart-container">
                <canvas id="trackerChart"></canvas>
            </div>
        </div>
    </div>

    <!-- Trackers -->
    <div class="card full">
        <h2>Tracking Companies ({tracker.get("unique_companies", 0)} companies, {tracker.get("total_tracker_hits", 0)} hits)</h2>
        <table class="table">
            <thead><tr><th>Company</th><th>Category</th><th>Domain</th><th>Hits</th></tr></thead>
            <tbody>{tracker_rows}</tbody>
        </table>
    </div>

    <!-- Security -->
    <div class="card full {'alert' if total_issues > 0 else 'safe'}">
        <h2>Security Assessment</h2>
        <table class="table">
            <thead><tr><th>Issue Type</th><th>Count</th><th>Severity</th></tr></thead>
            <tbody>{security_rows}</tbody>
        </table>
    </div>

    <!-- ISP Knowledge -->
    <div class="isp-box">
        <h2>What Your ISP Knows About You</h2>
        <ul>
            <li>Every website you visited ({dns.get("unique_domains", 0)} DNS + {tls.get("unique_domains", 0)} TLS SNI)</li>
            <li>When you visited them (timestamps on every packet)</li>
            <li>How much data you transferred ({bytes_to_human(meta.get("bytes_sent", 0))} up, {bytes_to_human(meta.get("bytes_received", 0))} down)</li>
            <li>Your device: {best.get("os", "?")} / {best.get("browser", "?")}</li>
            <li>{tracker.get("unique_companies", 0)} tracking companies following you</li>
            <li>Your interests: {", ".join(profile.get("interests", ["browsing"]))}</li>
            <li>Your behavioral pattern: {profile.get("dominant_activity", "unknown").replace("_", " ")} during {profile.get("time_period", "unknown")}</li>
            {"<li style='color:#ff6b6b;'><strong>" + str(leaks.get("total_leaks", 0)) + " pieces of sensitive data leaked in plaintext</strong></li>" if leaks.get("total_leaks", 0) > 0 else ""}
        </ul>
        <p style="color: #666; margin-top: 15px; font-size: 13px;">
            All of this is visible even with HTTPS. Only a VPN hides the destination metadata.
        </p>
    </div>

    <div class="footer">
        ISP Spy Mirror — Educational Tool | Generated {timestamp} | All data captured locally
    </div>

</div>

<script>
    const chartColors = ['#00d4ff', '#ff6b6b', '#ffd93d', '#6bcb77', '#9b59b6', '#e67e22', '#1abc9c', '#e74c3c'];

    // Protocol chart
    new Chart(document.getElementById('protoChart'), {{
        type: 'doughnut',
        data: {{
            labels: {proto_labels},
            datasets: [{{ data: {proto_values}, backgroundColor: chartColors }}]
        }},
        options: {{
            responsive: true,
            maintainAspectRatio: false,
            plugins: {{ legend: {{ labels: {{ color: '#aaa' }} }} }}
        }}
    }});

    // Port chart
    new Chart(document.getElementById('portChart'), {{
        type: 'bar',
        data: {{
            labels: {port_labels},
            datasets: [{{ label: 'Connections', data: {port_values}, backgroundColor: '#00d4ff' }}]
        }},
        options: {{
            responsive: true,
            maintainAspectRatio: false,
            plugins: {{ legend: {{ display: false }} }},
            scales: {{
                x: {{ ticks: {{ color: '#888' }} }},
                y: {{ ticks: {{ color: '#888' }}, beginAtZero: true }}
            }}
        }}
    }});

    // Activity chart
    new Chart(document.getElementById('activityChart'), {{
        type: 'polarArea',
        data: {{
            labels: {act_labels},
            datasets: [{{ data: {act_values}, backgroundColor: chartColors }}]
        }},
        options: {{
            responsive: true,
            maintainAspectRatio: false,
            plugins: {{ legend: {{ labels: {{ color: '#aaa' }} }} }}
        }}
    }});

    // Tracker chart
    new Chart(document.getElementById('trackerChart'), {{
        type: 'doughnut',
        data: {{
            labels: {cat_labels},
            datasets: [{{ data: {cat_values}, backgroundColor: ['#e74c3c', '#9b59b6', '#f39c12', '#3498db', '#1abc9c', '#e67e22'] }}]
        }},
        options: {{
            responsive: true,
            maintainAspectRatio: false,
            plugins: {{ legend: {{ labels: {{ color: '#aaa' }} }} }}
        }}
    }});
</script>
</body>
</html>"""

        return html
