/**
 * dashboard.js - A-HIDS Dashboard JavaScript
 *
 * Provides chart initialisation, live data updates, client-side filtering
 * for alerts and logs, and utility helpers.
 */

'use strict';

/* ── Configuration ─────────────────────────────────────────────────────── */

const AHIDS_API_BASE = window.location.protocol + '//' +
  (window.location.hostname || 'localhost') + ':5000';
const AUTH_TOKEN = document.querySelector('meta[name="auth-token"]')
  ? document.querySelector('meta[name="auth-token"]').content
  : 'your-secret-token';

const REFRESH_INTERVAL_MS = 30000;

/* ── Colour palette ────────────────────────────────────────────────────── */

const SEVERITY_COLORS = {
  LOW:      '#28a745',
  MEDIUM:   '#ffc107',
  HIGH:     '#fd7e14',
  CRITICAL: '#dc3545',
};

const CHART_DEFAULTS = {
  plugins: {
    legend: {
      labels: { color: '#c9d1d9', font: { size: 12 } },
    },
  },
};

/* ── Global chart references ───────────────────────────────────────────── */

let severityChartInstance = null;
let activityChartInstance = null;

/* ══════════════════════════════════════════════════════════════════════════
   Chart initialisation
   ══════════════════════════════════════════════════════════════════════════ */

/**
 * Initialise the severity distribution pie chart and activity line chart.
 *
 * @param {Object} severityData - Object mapping severity strings to counts,
 *                                e.g. { LOW: 5, HIGH: 3, CRITICAL: 1 }.
 */
function initCharts(severityData) {
  _initSeverityChart(severityData || {});
  _initActivityChart();
}

function _initSeverityChart(severityData) {
  const canvas = document.getElementById('severityChart');
  if (!canvas) return;

  const labels = Object.keys(severityData);
  const values = Object.values(severityData);
  const colors = labels.map(l => SEVERITY_COLORS[l] || '#8b949e');

  if (severityChartInstance) {
    severityChartInstance.destroy();
  }

  severityChartInstance = new Chart(canvas, {
    type: 'doughnut',
    data: {
      labels: labels,
      datasets: [{
        data: values,
        backgroundColor: colors.map(c => c + 'cc'),
        borderColor: colors,
        borderWidth: 2,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: CHART_DEFAULTS.plugins.legend,
        tooltip: {
          callbacks: {
            label: ctx => ` ${ctx.label}: ${ctx.raw}`,
          },
        },
      },
    },
  });
}

function _initActivityChart() {
  const canvas = document.getElementById('activityChart');
  if (!canvas) return;

  // Generate labels for last 7 days
  const labels = [];
  for (let i = 6; i >= 0; i--) {
    const d = new Date();
    d.setDate(d.getDate() - i);
    labels.push(d.toLocaleDateString('ar-SA', { month: 'short', day: 'numeric' }));
  }

  if (activityChartInstance) {
    activityChartInstance.destroy();
  }

  activityChartInstance = new Chart(canvas, {
    type: 'line',
    data: {
      labels: labels,
      datasets: [
        {
          label: 'تنبيهات',
          data: new Array(7).fill(0),
          borderColor: '#dc3545',
          backgroundColor: 'rgba(220,53,69,0.1)',
          tension: 0.4,
          fill: true,
        },
        {
          label: 'أحداث',
          data: new Array(7).fill(0),
          borderColor: '#00bcd4',
          backgroundColor: 'rgba(0,188,212,0.1)',
          tension: 0.4,
          fill: true,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: CHART_DEFAULTS.plugins,
      scales: {
        x: {
          ticks: { color: '#8b949e' },
          grid:  { color: '#30363d' },
        },
        y: {
          ticks: { color: '#8b949e' },
          grid:  { color: '#30363d' },
          beginAtZero: true,
        },
      },
    },
  });
}

/* ══════════════════════════════════════════════════════════════════════════
   Live data updates
   ══════════════════════════════════════════════════════════════════════════ */

/**
 * Fetch latest stats and recent alerts from the A-HIDS server and
 * update the DOM elements on the main dashboard page.
 */
function updateDashboard() {
  _fetchJSON('/api/stats')
    .then(stats => {
      if (!stats) return;
      _setText('stat-total-alerts',   stats.total_alerts   ?? '—');
      _setText('stat-active-clients', stats.active_clients ?? '—');
      _setText('stat-total-events',   stats.total_events   ?? '—');
      _setText('stat-threats',        stats.recent_alert_count ?? '—');

      // Refresh severity chart
      if (stats.alerts_by_severity && severityChartInstance) {
        const labels = Object.keys(stats.alerts_by_severity);
        const values = Object.values(stats.alerts_by_severity);
        severityChartInstance.data.labels = labels;
        severityChartInstance.data.datasets[0].data = values;
        severityChartInstance.data.datasets[0].backgroundColor =
          labels.map(l => (SEVERITY_COLORS[l] || '#8b949e') + 'cc');
        severityChartInstance.data.datasets[0].borderColor =
          labels.map(l => SEVERITY_COLORS[l] || '#8b949e');
        severityChartInstance.update('none');
      }
    })
    .catch(err => console.warn('updateDashboard stats error:', err));

  _fetchJSON('/api/alerts?limit=10')
    .then(data => {
      if (!data || !data.alerts) return;
      _refreshRecentAlerts(data.alerts);
    })
    .catch(err => console.warn('updateDashboard alerts error:', err));
}

function _refreshRecentAlerts(alerts) {
  const tbody = document.getElementById('recent-alerts-tbody');
  if (!tbody) return;

  if (!alerts.length) {
    tbody.innerHTML = `
      <tr>
        <td colspan="6" class="text-center text-muted py-4">
          <i class="fas fa-check-circle text-success me-2"></i>
          لا توجد تنبيهات حديثة
        </td>
      </tr>`;
    return;
  }

  tbody.innerHTML = alerts.map(a => `
    <tr>
      <td>${a.id || ''}</td>
      <td class="text-monospace small">${formatTimestamp(a.timestamp)}</td>
      <td>${a.client_id || ''}</td>
      <td><code>${a.rule_name || '—'}</code></td>
      <td>
        <span class="severity-badge severity-${(a.severity || 'low').toLowerCase()}">
          ${a.severity || 'LOW'}
        </span>
      </td>
      <td class="text-truncate" style="max-width:220px"
          title="${_escape(a.description || '')}">
        ${_escape((a.description || '').slice(0, 60))}…
      </td>
    </tr>
  `).join('');
}

/* ══════════════════════════════════════════════════════════════════════════
   Client-side filtering
   ══════════════════════════════════════════════════════════════════════════ */

/**
 * Filter rows in the alerts table by a text query.
 *
 * @param {string} query - Search string (case-insensitive).
 */
function filterAlerts(query) {
  const q = (query || '').toLowerCase();
  const rows = document.querySelectorAll('#alerts-table tbody tr');
  let visible = 0;
  rows.forEach(row => {
    const match = !q || row.textContent.toLowerCase().includes(q);
    row.style.display = match ? '' : 'none';
    if (match) visible++;
  });
  _updateVisibleCount(visible);
}

/**
 * Filter rows in the logs table by a text query.
 *
 * @param {string} query - Search string (case-insensitive).
 */
function searchLogs(query) {
  const q = (query || '').toLowerCase();
  const rows = document.querySelectorAll('#logs-table tbody tr');
  let visible = 0;
  rows.forEach(row => {
    const match = !q || row.textContent.toLowerCase().includes(q);
    row.style.display = match ? '' : 'none';
    if (match) visible++;
  });
  const countEl = document.getElementById('visible-count');
  if (countEl) countEl.textContent = visible;
}

/* ══════════════════════════════════════════════════════════════════════════
   Utility helpers
   ══════════════════════════════════════════════════════════════════════════ */

/**
 * Format an ISO timestamp string for human-readable display.
 *
 * @param {string} ts - ISO 8601 timestamp string.
 * @returns {string} Formatted date-time string.
 */
function formatTimestamp(ts) {
  if (!ts) return '—';
  try {
    const d = new Date(ts);
    return d.toLocaleString('ar-SA', {
      year: 'numeric', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
      hour12: false,
    });
  } catch (_) {
    return ts.slice(0, 19);
  }
}

/**
 * Fetch JSON from the A-HIDS server API with bearer token auth.
 *
 * @param {string} path - API path, e.g. '/api/stats'.
 * @returns {Promise<Object|null>} Parsed JSON or null on error.
 */
function _fetchJSON(path) {
  return fetch(AHIDS_API_BASE + path, {
    headers: { 'Authorization': 'Bearer ' + AUTH_TOKEN },
  })
    .then(resp => {
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      return resp.json();
    })
    .catch(err => {
      console.warn('Fetch error for', path, err);
      return null;
    });
}

function _setText(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value;
}

function _updateVisibleCount(count) {
  const el = document.getElementById('visible-count');
  if (el) el.textContent = count;
}

function _escape(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/* ══════════════════════════════════════════════════════════════════════════
   Initialisation
   ══════════════════════════════════════════════════════════════════════════ */

document.addEventListener('DOMContentLoaded', function () {
  // Start periodic refresh on dashboard page
  if (document.getElementById('stat-total-alerts')) {
    setInterval(updateDashboard, REFRESH_INTERVAL_MS);
  }
});
