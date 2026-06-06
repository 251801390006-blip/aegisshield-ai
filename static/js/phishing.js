/**
 * AegisShield AI – Phishing URL Detection JavaScript
 */

async function analyzePhishing() {
  const urlInput = document.getElementById('urlInput');
  const url = urlInput?.value?.trim();

  if (!url) { showToast('Please enter a URL to analyze.', 'warning'); return; }

  const btn = document.getElementById('phishBtn');
  const btnText = document.getElementById('phishBtnText');
  const btnLoader = document.getElementById('phishBtnLoader');
  const loader = document.getElementById('phishLoader');
  const resultDiv = document.getElementById('phishResult');

  btn.disabled = true;
  btnText.classList.add('d-none');
  btnLoader.classList.remove('d-none');
  loader.classList.add('active');
  resultDiv.style.display = 'none';
  resultDiv.innerHTML = '';

  try {
    const resp = await aegisFetch('/phishing/analyze', {
      method: 'POST',
      body: JSON.stringify({ url }),
    });

    const data = await resp.json();

    if (!resp.ok) {
      showToast(data.error || 'Analysis failed.', 'danger');
      return;
    }

    // Feature table
    const features = data.features || {};
    const featureRows = Object.entries(features).map(([k, v]) => {
      const label = k.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
      const val = typeof v === 'boolean' ? (v ? '⚠️ Yes' : '✅ No') : v;
      return `<tr>
        <td style="font-size:0.8rem;color:var(--text-muted);padding:0.4rem 0.6rem;">${label}</td>
        <td style="font-size:0.8rem;font-family:var(--font-mono);color:var(--text-primary);padding:0.4rem 0.6rem;">${val}</td>
      </tr>`;
    }).join('');

    const extraHTML = `
      <div style="margin-top:1rem;">
        <div style="font-size:0.8rem;font-weight:600;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.06em;margin-bottom:0.5rem;">URL Feature Analysis</div>
        <div style="background:var(--bg-tertiary);border:1px solid var(--border-color);border-radius:8px;overflow:hidden;">
          <table style="width:100%;border-collapse:collapse;">${featureRows}</table>
        </div>
      </div>
      <div style="margin-top:0.75rem;display:flex;gap:0.75rem;">
        <div style="flex:1;background:var(--bg-tertiary);padding:0.75rem;border-radius:8px;text-align:center;border:1px solid var(--border-color);">
          <div style="font-size:1.3rem;font-weight:800;color:var(--danger);font-family:var(--font-mono);">${data.phishing_probability?.toFixed(1)}%</div>
          <div style="font-size:0.7rem;color:var(--text-muted);">Phishing Probability</div>
        </div>
        <div style="flex:1;background:var(--bg-tertiary);padding:0.75rem;border-radius:8px;text-align:center;border:1px solid var(--border-color);">
          <div style="font-size:1.3rem;font-weight:800;color:var(--success);font-family:var(--font-mono);">${data.safe_probability?.toFixed(1)}%</div>
          <div style="font-size:0.7rem;color:var(--text-muted);">Safe Probability</div>
        </div>
      </div>`;

    resultDiv.innerHTML = buildResultPanel(data, 'Phishing URL');
    const panel = resultDiv.querySelector('.result-panel');
    if (panel) panel.insertAdjacentHTML('beforeend', extraHTML);

    resultDiv.style.display = 'block';
    resultDiv.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

    showToast(
      data.is_threat ? '🚨 PHISHING URL DETECTED!' : '✅ URL appears legitimate',
      data.is_threat ? 'danger' : 'success'
    );

  } catch (e) {
    showToast('Network error. Please check your connection.', 'danger');
  } finally {
    btn.disabled = false;
    btnText.classList.remove('d-none');
    btnLoader.classList.add('d-none');
    loader.classList.remove('active');
  }
}

// Enter key support
document.getElementById('urlInput')?.addEventListener('keypress', (e) => {
  if (e.key === 'Enter') analyzePhishing();
});
