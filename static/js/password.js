/**
 * AegisShield AI – Password Analyzer JavaScript
 */

const STRENGTH_MAP = {
  'VERY WEAK': { color: 'var(--danger)', pct: 10 },
  'WEAK': { color: 'var(--warning)', pct: 28 },
  'MODERATE': { color: '#ffd600', pct: 52 },
  'STRONG': { color: 'var(--neon-blue)', pct: 76 },
  'VERY STRONG': { color: 'var(--neon-green)', pct: 100 },
};

let realtimeTimer = null;

function togglePwd() {
  const input = document.getElementById('passwordInput');
  const eye = document.getElementById('pwdEye');
  if (input.type === 'password') { input.type = 'text'; eye.className = 'bi bi-eye-slash'; }
  else { input.type = 'password'; eye.className = 'bi bi-eye'; }
}

async function realtimeAnalysis(value) {
  clearTimeout(realtimeTimer);
  const panel = document.getElementById('realtimePanel');

  if (!value) {
    panel.style.display = 'none';
    return;
  }

  panel.style.display = 'block';

  realtimeTimer = setTimeout(async () => {
    try {
      const resp = await aegisFetch('/password/realtime', {
        method: 'POST',
        body: JSON.stringify({ password: value }),
      });
      const data = await resp.json();

      const fill = document.getElementById('strengthFill');
      const config = STRENGTH_MAP[data.strength] || { color: 'var(--text-muted)', pct: 0 };
      fill.style.width = config.pct + '%';
      fill.style.background = config.color;
      fill.style.transition = 'width 0.4s, background 0.3s';

      document.getElementById('strengthLabel').textContent = data.strength;
      document.getElementById('strengthLabel').style.color = config.color;
      document.getElementById('scoreLabel').textContent = `Score: ${data.score}/100`;
      document.getElementById('entropyLabel').textContent = `Entropy: ${data.entropy} bits`;
      document.getElementById('crackLabel').textContent = `Crack time: ${data.crack_time}`;
    } catch (e) {}
  }, 200);
}

async function analyzePassword() {
  const password = document.getElementById('passwordInput')?.value;
  if (!password) { showToast('Please enter a password.', 'warning'); return; }

  const btn = document.getElementById('analyzeBtn');
  const btnText = document.getElementById('analyzeBtnText');
  const btnLoader = document.getElementById('analyzeBtnLoader');
  const resultDiv = document.getElementById('pwdResult');

  btn.disabled = true;
  btnText.classList.add('d-none');
  btnLoader.classList.remove('d-none');
  resultDiv.style.display = 'none';

  try {
    const resp = await aegisFetch('/password/analyze', {
      method: 'POST',
      body: JSON.stringify({ password }),
    });

    const data = await resp.json();
    if (!resp.ok) { showToast(data.error || 'Analysis failed.', 'danger'); return; }

    const config = STRENGTH_MAP[data.strength] || { color: 'var(--text-muted)', pct: 50 };

    const chars = data.characteristics || {};
    const charChecks = [
      ['Lowercase letters', chars.has_lowercase],
      ['Uppercase letters', chars.has_uppercase],
      ['Numbers (0-9)', chars.has_digits],
      ['Special characters', chars.has_special_chars],
    ];

    const issues = [
      ['Common password', chars.is_common_password, true],
      ['Repeated characters', chars.has_repeated_chars, true],
      ['Sequential pattern', chars.has_sequential_chars, true],
      ['Keyboard pattern', chars.has_keyboard_pattern, true],
    ];

    const recHTML = data.recommendations?.length
      ? data.recommendations.map(r => `<div style="display:flex;gap:0.5rem;align-items:flex-start;margin-bottom:0.35rem;">
          <i class="bi bi-arrow-right" style="color:var(--neon-blue);font-size:0.75rem;margin-top:3px;flex-shrink:0;"></i>
          <span style="font-size:0.85rem;color:var(--text-secondary);">${escapeHtml(r)}</span>
        </div>`).join('') : '';

    resultDiv.innerHTML = `
      <div class="result-panel ${data.is_threat ? 'threat' : 'safe'} slide-up">
        <div style="display:flex;align-items:center;justify-content:space-between;gap:1rem;flex-wrap:wrap;margin-bottom:1rem;">
          <div>
            <div style="font-size:1.2rem;font-weight:800;color:${config.color};">${data.strength}</div>
            <div style="font-size:0.8rem;color:var(--text-muted);">Password Analysis Complete</div>
          </div>
          <div style="text-align:right;">
            <div style="font-size:2.5rem;font-weight:900;font-family:var(--font-mono);color:${config.color};">${data.score}</div>
            <div style="font-size:0.7rem;color:var(--text-muted);">/ 100</div>
          </div>
        </div>

        <div class="strength-meter mb-3">
          <div class="strength-meter-fill" style="width:${config.pct}%;background:${config.color};"></div>
        </div>

        <div style="display:grid;grid-template-columns:repeat(2,1fr);gap:0.75rem;margin-bottom:1rem;">
          <div style="background:var(--bg-tertiary);padding:0.75rem;border-radius:8px;border:1px solid var(--border-color);">
            <div style="font-size:0.65rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.06em;margin-bottom:0.25rem;">Length</div>
            <div style="font-size:1.1rem;font-weight:700;font-family:var(--font-mono);">${data.length} chars</div>
          </div>
          <div style="background:var(--bg-tertiary);padding:0.75rem;border-radius:8px;border:1px solid var(--border-color);">
            <div style="font-size:0.65rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.06em;margin-bottom:0.25rem;">Entropy</div>
            <div style="font-size:1.1rem;font-weight:700;font-family:var(--font-mono);">${data.entropy} bits</div>
          </div>
          <div style="background:var(--bg-tertiary);padding:0.75rem;border-radius:8px;border:1px solid var(--border-color);">
            <div style="font-size:0.65rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.06em;margin-bottom:0.25rem;">Crack Time</div>
            <div style="font-size:0.9rem;font-weight:700;color:${config.color};">${data.crack_time}</div>
          </div>
          <div style="background:var(--bg-tertiary);padding:0.75rem;border-radius:8px;border:1px solid var(--border-color);">
            <div style="font-size:0.65rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.06em;margin-bottom:0.25rem;">Risk Score</div>
            <div style="font-size:1.1rem;font-weight:700;font-family:var(--font-mono);color:${data.risk_score >= 60 ? 'var(--danger)' : 'var(--success)'};">${data.risk_score}</div>
          </div>
        </div>

        <div style="display:grid;grid-template-columns:1fr 1fr;gap:0.4rem;margin-bottom:1rem;">
          ${charChecks.map(([label, has]) => `
          <div style="display:flex;align-items:center;gap:0.5rem;padding:0.4rem 0.6rem;background:var(--bg-tertiary);border-radius:6px;border:1px solid ${has ? 'rgba(0,204,102,0.2)' : 'rgba(255,68,68,0.2)'};">
            <i class="bi bi-${has ? 'check-circle-fill' : 'x-circle-fill'}" style="color:${has ? 'var(--success)' : 'var(--danger)'};font-size:0.8rem;"></i>
            <span style="font-size:0.75rem;color:var(--text-secondary);">${label}</span>
          </div>`).join('')}
          ${issues.map(([label, triggered]) => triggered ? `
          <div style="display:flex;align-items:center;gap:0.5rem;padding:0.4rem 0.6rem;background:var(--danger-dim);border-radius:6px;border:1px solid rgba(255,68,68,0.2);">
            <i class="bi bi-exclamation-triangle-fill" style="color:var(--danger);font-size:0.8rem;"></i>
            <span style="font-size:0.75rem;color:var(--danger);">${label}</span>
          </div>` : '').join('')}
        </div>

        ${recHTML ? `<div style="margin-top:0.75rem;padding:0.75rem;background:var(--bg-tertiary);border-radius:8px;border:1px solid var(--border-color);">
          <div style="font-size:0.75rem;font-weight:600;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.06em;margin-bottom:0.5rem;">Recommendations</div>
          ${recHTML}
        </div>` : ''}

        ${data.scan_id ? `<div style="margin-top:0.75rem;"><a href="/reports/generate/${data.scan_id}" class="btn-outline-neon" style="font-size:0.8rem;padding:0.4rem 0.9rem;">📄 PDF Report</a></div>` : ''}
      </div>`;

    resultDiv.style.display = 'block';
    resultDiv.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

    showToast(
      data.is_threat ? `⚠️ ${data.strength} password – change recommended` : `✅ ${data.strength} password`,
      data.is_threat ? 'warning' : 'success'
    );

  } catch (e) {
    showToast('Network error.', 'danger');
  } finally {
    btn.disabled = false;
    btnText.classList.remove('d-none');
    btnLoader.classList.add('d-none');
  }
}

// Enter key
document.getElementById('passwordInput')?.addEventListener('keypress', (e) => {
  if (e.key === 'Enter') analyzePassword();
});
