/**
 * Cyber Squad AI – Spam Detection JavaScript
 */

const SPAM_SAMPLE = `Congratulations! You've been selected as our lucky winner! 
Click here to claim your FREE $1,000 Walmart gift card NOW! 
This offer expires in 24 HOURS. Call 1-800-555-SCAM immediately!
Your account has been SUSPENDED. Verify now: http://secure-bank-login.ru/verify`;

const HAM_SAMPLE = `Hi Sarah,

Hope you're doing well! I wanted to follow up on our meeting from last Tuesday regarding the Q3 project timeline.

Could you please review the attached document and share your feedback by end of day Friday? The project team is waiting on your sign-off before we can proceed to the next phase.

Let me know if you have any questions.

Best regards,
Michael`;

function loadSample(type) {
  const input = document.getElementById('emailInput');
  input.value = type === 'spam' ? SPAM_SAMPLE : HAM_SAMPLE;
  updateCharCount();
  input.focus();
}

function updateCharCount() {
  const input = document.getElementById('emailInput');
  const counter = document.getElementById('charCount');
  if (counter) {
    const len = (input?.value || '').length;
    counter.textContent = `${len.toLocaleString()} / 10,000 characters`;
    counter.style.color = len > 9000 ? 'var(--warning)' : 'var(--text-muted)';
  }
}

document.getElementById('emailInput')?.addEventListener('input', updateCharCount);

async function analyzeSpam() {
  const text = document.getElementById('emailInput')?.value?.trim();
  if (!text) { showToast('Please enter email text to analyze.', 'warning'); return; }

  const btn = document.getElementById('analyzeBtn');
  const btnText = document.getElementById('analyzeBtnText');
  const btnLoader = document.getElementById('analyzeBtnLoader');
  const loader = document.getElementById('scanLoader');
  const resultPanel = document.getElementById('resultPanel');

  btn.disabled = true;
  btnText.classList.add('d-none');
  btnLoader.classList.remove('d-none');
  loader.classList.add('active');
  resultPanel.style.display = 'none';
  resultPanel.innerHTML = '';

  try {
    const resp = await aegisFetch('/spam/analyze', {
      method: 'POST',
      body: JSON.stringify({ email_text: text }),
    });

    const data = await resp.json();

    if (!resp.ok) {
      showToast(data.error || 'Analysis failed. Please try again.', 'danger');
      return;
    }

    // Extra details for spam
    const extraHTML = `
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:0.75rem;margin-top:1rem;">
        <div style="background:var(--bg-tertiary);padding:0.75rem;border-radius:8px;text-align:center;border:1px solid var(--border-color);">
          <div style="font-size:1.5rem;font-weight:800;color:var(--danger);font-family:var(--font-mono);">${data.spam_probability?.toFixed(1)}%</div>
          <div style="font-size:0.7rem;color:var(--text-muted);">SPAM Probability</div>
        </div>
        <div style="background:var(--bg-tertiary);padding:0.75rem;border-radius:8px;text-align:center;border:1px solid var(--border-color);">
          <div style="font-size:1.5rem;font-weight:800;color:var(--success);font-family:var(--font-mono);">${data.ham_probability?.toFixed(1)}%</div>
          <div style="font-size:0.7rem;color:var(--text-muted);">SAFE Probability</div>
        </div>
      </div>`;

    resultPanel.innerHTML = buildResultPanel(data, 'Spam Email') + '';
    // Insert extra stats
    const panel = resultPanel.querySelector('.result-panel');
    if (panel) {
      panel.insertAdjacentHTML('beforeend', extraHTML);
    }
    resultPanel.style.display = 'block';
    resultPanel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

    showToast(
      data.is_threat ? '🚨 SPAM DETECTED – Check results below' : '✅ Email appears legitimate',
      data.is_threat ? 'danger' : 'success'
    );

  } catch (e) {
    showToast('Network error. Please check your connection.', 'danger');
    console.error(e);
  } finally {
    btn.disabled = false;
    btnText.classList.remove('d-none');
    btnLoader.classList.add('d-none');
    loader.classList.remove('active');
  }
}
