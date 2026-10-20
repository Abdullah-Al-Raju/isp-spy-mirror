// ISP Spy Mirror — Tactical SOC WebSocket Client & Dashboard Controller
let ws = null;
let currentFilter = 'all';
let isPaused = false;
let allEvents = [];
const MAX_DOM_ROWS = 400;

document.addEventListener('DOMContentLoaded', () => {
  initWebSocket();
  setupUIEventListeners();
  pollStatusFallback();
});

function initWebSocket() {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = `${protocol}//${window.location.host}/ws`;

  updateConnectionStatus('CONNECTING...');
  ws = new WebSocket(wsUrl);

  ws.onopen = () => {
    updateConnectionStatus('ACTIVE', false);
    document.getElementById('footerConnectionStatus').textContent = 'WS: CONNECTED';
  };

  ws.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      if (data.type === 'telemetry') {
        updateTelemetry(data.payload);
      } else if (data.type === 'event_batch') {
        renderEventBatch(data.payload);
      } else if (data.type === 'single_event') {
        renderSingleEvent(data.payload);
      } else if (data.type === 'state_change') {
        handleStateChange(data.payload);
      }
    } catch (e) {
      console.error('Error parsing WS frame:', e);
    }
  };

  ws.onclose = () => {
    updateConnectionStatus('DISCONNECTED', true);
    document.getElementById('footerConnectionStatus').textContent = 'WS: RECONNECTING';
    setTimeout(initWebSocket, 2000);
  };

  ws.onerror = (err) => {
    console.warn('WS error:', err);
  };
}

function updateConnectionStatus(text, isError = false) {
  const statusEl = document.getElementById('engineStatus');
  const dotEl = document.getElementById('engineDot');
  if (statusEl) statusEl.textContent = text;
  if (dotEl) {
    dotEl.className = 'pulse-dot' + (isError ? ' dot-error' : isPaused ? ' dot-paused' : '');
  }
}

function setupUIEventListeners() {
  // Capture Pause/Resume Button
  const toggleBtn = document.getElementById('btnToggleCapture');
  if (toggleBtn) {
    toggleBtn.addEventListener('click', toggleCaptureState);
  }

  // Clear Stream Button
  const clearBtn = document.getElementById('btnClearStream');
  if (clearBtn) {
    clearBtn.addEventListener('click', () => {
      allEvents = [];
      document.getElementById('streamTableBody').innerHTML = '';
      document.getElementById('streamCounter').textContent = '[0 Events]';
    });
  }

  // Filter Tabs
  document.querySelectorAll('.filter-tab').forEach((tab) => {
    tab.addEventListener('click', (e) => {
      document.querySelectorAll('.filter-tab').forEach((t) => t.classList.remove('active'));
      tab.classList.add('active');
      currentFilter = tab.getAttribute('data-filter');
      refilterTable();
    });
  });

  // Dropdown Toggles
  setupDropdown('btnInjectMenu', 'injectDropdown');
  setupDropdown('btnExportMenu', 'exportDropdown');

  // Close dropdowns when clicking outside
  document.addEventListener('click', (e) => {
    if (!e.target.closest('.dropdown')) {
      document.querySelectorAll('.dropdown').forEach((d) => d.classList.remove('open'));
    }
  });
}

function setupDropdown(btnId, menuId) {
  const btn = document.getElementById(btnId);
  if (!btn) return;
  const parent = btn.closest('.dropdown');
  btn.addEventListener('click', (e) => {
    e.stopPropagation();
    document.querySelectorAll('.dropdown').forEach((d) => {
      if (d !== parent) d.classList.remove('open');
    });
    parent.classList.toggle('open');
  });
}

async function toggleCaptureState() {
  const endpoint = isPaused ? '/api/control/resume' : '/api/control/pause';
  try {
    const res = await fetch(endpoint, { method: 'POST' });
    const data = await res.json();
    isPaused = data.paused;
    updateToggleButtonUI();
  } catch (err) {
    console.error('Failed to toggle capture:', err);
  }
}

function updateToggleButtonUI() {
  const btn = document.getElementById('btnToggleCapture');
  if (!btn) return;
  if (isPaused) {
    btn.innerHTML = '<span class="btn-text">RESUME STREAM</span>';
    btn.className = 'cyber-btn btn-warning';
    updateConnectionStatus('PAUSED', false);
  } else {
    btn.innerHTML = '<span class="btn-text">PAUSE STREAM</span>';
    btn.className = 'cyber-btn btn-primary';
    updateConnectionStatus('ACTIVE', false);
  }
}

async function injectScenario(scenarioName) {
  document.querySelectorAll('.dropdown').forEach((d) => d.classList.remove('open'));
  try {
    const res = await fetch('/api/control/inject', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scenario: scenarioName }),
    });
    const result = await res.json();
    console.log('Injected scenario:', scenarioName, result);
  } catch (err) {
    console.error('Failed to inject scenario:', err);
  }
}

function updateTelemetry(telemetry) {
  if (!telemetry) return;

  // Interface & Elapsed
  if (telemetry.interface) {
    document.getElementById('currentInterface').textContent = telemetry.interface;
  }
  if (telemetry.elapsed) {
    document.getElementById('sessionElapsed').textContent = telemetry.elapsed;
  }

  // Packets & Counters
  document.getElementById('statTotalPackets').textContent = (telemetry.packets_captured || 0).toLocaleString();
  document.getElementById('statTotalEvents').textContent = (telemetry.events_logged || 0).toLocaleString();
  document.getElementById('statUniqueDomains').textContent = (telemetry.unique_domains || 0).toLocaleString();
  document.getElementById('statUniqueDest').textContent = (telemetry.unique_destinations || 0).toLocaleString();

  if (telemetry.packet_rate !== undefined) {
    document.getElementById('packetRateBadge').textContent = `${telemetry.packet_rate} PKT/S`;
  }

  // Bandwidth
  document.getElementById('txBytes').textContent = telemetry.bytes_sent_formatted || '0 B';
  document.getElementById('rxBytes').textContent = telemetry.bytes_received_formatted || '0 B';

  // Privacy Score
  if (telemetry.privacy_score) {
    const ps = telemetry.privacy_score;
    const scoreVal = ps.score !== undefined ? ps.score : 100;
    const scoreEl = document.getElementById('scoreValue');
    const gradeEl = document.getElementById('scoreGrade');
    const badgeEl = document.getElementById('privacyStatusBadge');
    const ringEl = document.getElementById('scoreRingFill');

    scoreEl.textContent = scoreVal;
    gradeEl.textContent = `GRADE ${ps.grade || 'A+'}`;
    gradeEl.style.color = ps.color || '#00ff88';

    badgeEl.textContent = ps.status || 'NORMAL';
    badgeEl.style.color = ps.color || '#00ff88';
    badgeEl.style.borderColor = ps.color || '#00ff88';

    // SVG stroke-dashoffset: 314 = 0%, 0 = 100%
    const offset = 314 - (314 * scoreVal) / 100;
    ringEl.style.strokeDashoffset = offset;
    ringEl.style.stroke = ps.color || '#00ff88';

    // Metrics
    document.getElementById('metricCredLeaks').textContent = ps.critical_leaks || 0;
    document.getElementById('metricVpnLeaks').textContent = ps.vpn_leaks || 0;
    document.getElementById('metricTrackers').textContent = ps.trackers_detected || 0;
    document.getElementById('metricPlainHttp').textContent = ps.plaintext_http || 0;
    document.getElementById('metricEchShield').textContent = ps.ech_protected || 0;

    // Deductions
    const listEl = document.getElementById('deductionsList');
    if (ps.deductions && ps.deductions.length > 0) {
      listEl.innerHTML = ps.deductions.map((d) => `<li>${escapeHtml(d)}</li>`).join('');
    } else {
      listEl.innerHTML = '<li class="text-success">Zero cleartext leaks observed. Stream protected.</li>';
    }
  }

  // Protocol Distribution
  if (telemetry.protocol_dist) {
    const dist = telemetry.protocol_dist;
    const tlsPct = dist.tls || 0;
    const dnsPct = dist.dns || 0;
    const httpPct = dist.http || 0;
    const otherPct = Math.max(0, 100 - (tlsPct + dnsPct + httpPct));

    document.getElementById('barTls').style.width = `${tlsPct}%`;
    document.getElementById('barDns').style.width = `${dnsPct}%`;
    document.getElementById('barHttp').style.width = `${httpPct}%`;
    document.getElementById('barOther').style.width = `${otherPct}%`;

    document.getElementById('protocolPercentages').textContent =
      `TLS ${tlsPct}% | DNS ${dnsPct}% | HTTP ${httpPct}%`;
  }

  // Dossier Info
  if (telemetry.dossier) {
    const d = telemetry.dossier;
    if (d.device_profile) {
      const dev = d.device_profile;
      document.getElementById('dossierOsBrowser').textContent = `${dev.operating_system} // ${dev.browser}`;
    }
    if (d.behavioral_analysis) {
      const bh = d.behavioral_analysis;
      document.getElementById('dossierActivity').textContent = bh.primary_activity || 'Normal Browsing';
    }
    if (d.monetization_potential) {
      const mon = d.monetization_potential;
      document.getElementById('dossierValue').textContent = mon.data_broker_value || '$0.45 / profile';
      const cats = mon.advertiser_categories || [];
      document.getElementById('dossierAdCategories').textContent =
        cats.length > 0 ? cats.slice(0, 3).join(', ') : 'Building ad profile...';
    }
    if (d.advertising_profile && d.advertising_profile.company_list) {
      const chipsEl = document.getElementById('trackerChips');
      const companies = d.advertising_profile.company_list;
      if (companies.length > 0) {
        chipsEl.innerHTML = companies
          .slice(0, 12)
          .map((c) => `<span class="chip">${escapeHtml(c)}</span>`)
          .join('');
      }
    }
  }
}

function renderSingleEvent(evt) {
  allEvents.unshift(evt);
  if (allEvents.length > 600) allEvents.pop();

  if (matchesFilter(evt)) {
    insertTableRow(evt, true);
  }
  updateStreamCounter();
}

function renderEventBatch(events) {
  if (!events || events.length === 0) return;
  for (let i = 0; i < events.length; i++) {
    const evt = events[i];
    allEvents.unshift(evt);
    if (allEvents.length > 600) allEvents.pop();
    if (matchesFilter(evt)) {
      insertTableRow(evt, true);
    }
  }
  updateStreamCounter();
}

function matchesFilter(evt) {
  if (currentFilter === 'all') return true;
  const type = (evt.type || '').toUpperCase();
  if (currentFilter === 'LEAK') {
    return type.includes('LEAK') || evt.sensitive === true || type.includes('WARN');
  }
  if (currentFilter === 'TRACKER') return type.includes('TRACKER');
  if (currentFilter === 'DNS') return type.includes('DNS');
  if (currentFilter === 'TLS') return type.includes('TLS');
  if (currentFilter === 'HTTP') return type.includes('HTTP');
  return true;
}

function refilterTable() {
  const tbody = document.getElementById('streamTableBody');
  tbody.innerHTML = '';
  const filtered = allEvents.filter(matchesFilter);
  const toShow = filtered.slice(0, MAX_DOM_ROWS);
  for (let i = 0; i < toShow.length; i++) {
    insertTableRow(toShow[i], false);
  }
  updateStreamCounter();
}

function insertTableRow(evt, prepend = true) {
  const tbody = document.getElementById('streamTableBody');
  const tr = document.createElement('tr');

  const badgeClass = getBadgeClass(evt.type);
  const detail = escapeHtml(evt.detail || '');
  const isSensitive = evt.sensitive || (evt.type && evt.type.includes('LEAK'));

  tr.innerHTML = `
    <td class="text-muted">${escapeHtml(evt.timestamp || '')}</td>
    <td><span class="event-badge ${badgeClass}">${escapeHtml(evt.type || 'RAW')}</span></td>
    <td>${escapeHtml(evt.subtype || '--')}</td>
    <td><span class="text-cyan">${escapeHtml(evt.destination || evt.domain || '--')}</span></td>
    <td class="${isSensitive ? 'text-critical' : ''}">${detail}</td>
  `;

  if (prepend && tbody.firstChild) {
    tbody.insertBefore(tr, tbody.firstChild);
  } else {
    tbody.appendChild(tr);
  }

  while (tbody.children.length > MAX_DOM_ROWS) {
    tbody.removeChild(tbody.lastChild);
  }
}

function getBadgeClass(type) {
  if (!type) return 'badge-other';
  const t = type.toUpperCase();
  if (t.includes('LEAK')) return 'badge-leak';
  if (t.includes('DNS')) return 'badge-dns';
  if (t.includes('TLS')) return 'badge-tls';
  if (t.includes('TRACKER')) return 'badge-tracker';
  if (t.includes('HTTP')) return 'badge-http';
  if (t.includes('VPN')) return 'badge-vpn';
  return 'badge-other';
}

function updateStreamCounter() {
  const filteredCount = allEvents.filter(matchesFilter).length;
  document.getElementById('streamCounter').textContent = `[${filteredCount} Visible / ${allEvents.length} Total]`;
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

async function pollStatusFallback() {
  try {
    const res = await fetch('/api/status');
    if (res.ok) {
      const data = await res.json();
      if (data.telemetry) {
        updateTelemetry(data.telemetry);
      }
    }
  } catch (e) {
    // fallback poll error is fine
  }
  setTimeout(pollStatusFallback, 5000);
}
