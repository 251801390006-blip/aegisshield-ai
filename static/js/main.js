/**
 * AegisShield AI – Main JavaScript Utilities
 */

'use strict';

// ── CSRF Token Helper ────────────────────────────────────────────
function getCsrf() {
  return document.querySelector('meta[name="csrf-token"]')?.content
    || document.querySelector('[name=csrf_token]')?.value
    || '';
}

// ── Fetch Wrapper ────────────────────────────────────────────────
async function aegisFetch(url, options = {}) {
  const defaults = {
    headers: {
      'Content-Type': 'application/json',
      'X-CSRFToken': getCsrf(),
      'Accept': 'application/json',
    },
  };
  const merged = { ...defaults, ...options };
  if (options.headers) {
    merged.headers = { ...defaults.headers, ...options.headers };
  }
  return fetch(url, merged);
}

// ── Toast Notification ─────────────────────────────────────────
function showToast(message, type = 'info') {
  const icons = { success: '✅', danger: '❌', warning: '⚠️', info: 'ℹ️' };
  const container = document.getElementById('toastContainer') || (() => {
    const el = document.createElement('div');
    el.id = 'toastContainer';
    el.style.cssText = 'position:fixed;top:1.5rem;right:1.5rem;z-index:9999;display:flex;flex-direction:column;gap:0.5rem;pointer-events:none;';
    document.body.appendChild(el);
    return el;
  })();

  const toast = document.createElement('div');
  toast.className = `toast-aegis ${type}`;
  toast.style.pointerEvents = 'auto';
  toast.innerHTML = `<span>${icons[type] || 'ℹ️'}</span><span>${message}</span>`;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transition = 'opacity 0.4s';
    setTimeout(() => toast.remove(), 400);
  }, 4500);
}

// ── Build Result Panel ─────────────────────────────────────────
function buildResultPanel(data, scanType) {
  const isThreat = data.is_threat;
  const panelClass = isThreat ? 'threat' : 'safe';
  const iconClass = isThreat ? '⚠️' : '✅';
  const score = data.risk_score || data.confidence || data.score || 0;

  let indicatorHTML = '';
  const indicators = data.indicators || [];
  if (indicators.length) {
    indicatorHTML = `<div style="margin-top:1rem;">
      <div style="font-size:0.8rem;font-weight:600;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.06em;margin-bottom:0.5rem;">Threat Indicators</div>
      ${indicators.map(i => `<div class="indicator-item ${isThreat ? 'threat' : 'safe'}">
        <span class="indicator-icon">${isThreat ? '🔴' : '🟢'}</span>
        <span class="indicator-text">${escapeHtml(i)}</span>
      </div>`).join('')}
    </div>`;
  }

  const recHTML = data.recommendation ? `<div style="margin-top:1rem;padding:0.75rem;background:var(--bg-tertiary);border-radius:8px;border:1px solid var(--border-color);">
    <div style="font-size:0.75rem;font-weight:600;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.06em;margin-bottom:0.35rem;">Recommendations</div>
    <p style="font-size:0.85rem;color:var(--text-secondary);margin:0;line-height:1.6;">${escapeHtml(data.recommendation)}</p>
  </div>` : '';

  const pdfBtn = data.scan_id ? `<a href="/reports/generate/${data.scan_id}" class="btn-outline-neon" style="font-size:0.8rem;padding:0.4rem 0.9rem;display:inline-flex;align-items:center;gap:0.4rem;" title="Download PDF Report">📄 PDF Report</a>` : '';

  return `<div class="result-panel ${panelClass} slide-up">
    <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:1rem;flex-wrap:wrap;">
      <div style="display:flex;align-items:center;gap:0.75rem;">
        <span style="font-size:1.5rem;">${iconClass}</span>
        <div>
          <div style="font-size:1.1rem;font-weight:800;color:${isThreat ? 'var(--danger)' : 'var(--success)'};">${data.result}</div>
          <div style="font-size:0.8rem;color:var(--text-muted);">${scanType} Analysis Complete</div>
        </div>
      </div>
      <div style="text-align:right;">
        <div style="font-size:2rem;font-weight:900;font-family:var(--font-mono);color:${score >= 80 ? 'var(--danger)' : score >= 50 ? 'var(--warning)' : 'var(--success)'};">${parseFloat(score).toFixed(1)}</div>
        <div style="font-size:0.7rem;color:var(--text-muted);">Risk Score / 100</div>
      </div>
    </div>
    ${indicatorHTML}
    ${recHTML}
    <div style="margin-top:1rem;display:flex;gap:0.75rem;flex-wrap:wrap;align-items:center;">
      ${pdfBtn}
      <button onclick="this.closest('.result-panel').remove();" class="btn-outline-neon" style="font-size:0.8rem;padding:0.4rem 0.9rem;">
        New Scan
      </button>
    </div>
  </div>`;
}

// ── Escape HTML ────────────────────────────────────────────────
function escapeHtml(str) {
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ── Password toggle utility ─────────────────────────────────────
function togglePwdField(inputId, iconId) {
  const f = document.getElementById(inputId);
  const i = document.getElementById(iconId);
  if (f && i) {
    if (f.type === 'password') { f.type = 'text'; i.className = 'bi bi-eye-slash'; }
    else { f.type = 'password'; i.className = 'bi bi-eye'; }
  }
}

// ── Sidebar hover effects ─────────────────────────────────────
document.querySelectorAll('.sidebar-link').forEach(link => {
  link.addEventListener('mouseenter', () => {
    link.style.paddingLeft = '1rem';
  });
  link.addEventListener('mouseleave', () => {
    if (!link.classList.contains('active')) {
      link.style.paddingLeft = '';
    }
  });
});

// ── Quick scan card hover effect ─────────────────────────────
document.querySelectorAll('.glass-card').forEach(card => {
  card.addEventListener('mouseenter', () => {
    card.style.transition = 'all 0.2s';
  });
});

console.log('%c🛡 AegisShield AI', 'color:#00d4ff;font-size:16px;font-weight:800;');
console.log('%cCybersecurity Platform v1.0.0', 'color:#8b949e;font-size:12px;');
