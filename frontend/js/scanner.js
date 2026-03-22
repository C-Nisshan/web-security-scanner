/* scanner.js — Assessment Console Controller */

const API = 'http://127.0.0.1:5000';
const $   = id => document.getElementById(id);

// ── Tab switching ─────────────────────────────────────────────
function switchTab(tab) {
  const isCrawl = tab === 'crawl';
  document.querySelectorAll('.tab-btn').forEach((b, i) => {
    b.classList.toggle('active', isCrawl ? i === 0 : i === 1);
  });
  $('crawl-config').classList.toggle('hidden', !isCrawl);
  $('payload-config').classList.toggle('hidden', isCrawl);
  resetResults();
}

// ── UI helpers ────────────────────────────────────────────────
function setStatus(msg, type = 'info', loading = false) {
  const bar = $('status-bar');
  bar.className = `status-bar ${type} mb-4`;
  bar.innerHTML = loading
    ? `<div class="spinner"></div><span>${msg}</span>`
    : `<span>${msg}</span>`;
  bar.classList.remove('hidden');
}

function resetResults() {
  $('status-bar').classList.add('hidden');
  $('crawl-results').classList.add('hidden');
  $('payload-results').classList.add('hidden');
  $('empty-state').classList.remove('hidden');
  $('results-title').textContent = 'results';
}

function showPanel(id, title) {
  $('empty-state').classList.add('hidden');
  $('crawl-results').classList.add('hidden');
  $('payload-results').classList.add('hidden');
  $(id).classList.remove('hidden');
  $('results-title').textContent = title;
}

function lockBtn(id, state) {
  const btn = $(id);
  if (btn) btn.disabled = state;
}

function makePill(val, label, cls = '') {
  return `<div class="stat-pill ${cls}">
    <span class="sv">${val}</span>
    <span class="sl">${label}</span>
  </div>`;
}

function escHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

// ══════════════════════════════════════════════════════════════
// DISCOVERY (CRAWLER)
// ══════════════════════════════════════════════════════════════
async function startCrawl() {
  const url      = $('crawl-url').value.trim();
  const maxDepth = parseInt($('crawl-depth').value, 10);
  const maxUrls  = parseInt($('crawl-maxurls').value, 10);

  if (!url) {
    setStatus('Please enter a target URL to begin discovery.', 'error'); return;
  }
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    setStatus('URL must begin with http:// or https://', 'error'); return;
  }

  lockBtn('crawl-btn', true);
  $('crawl-tip').classList.add('hidden');
  showPanel('crawl-results', 'discovery');
  setStatus(`Mapping ${url} — depth ${maxDepth}, up to ${maxUrls} pages…`, 'info', true);

  try {
    const res = await fetch(`${API}/api/scan/crawl`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ target_url: url, max_depth: maxDepth, max_urls: maxUrls }),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || `Server responded with ${res.status}`);
    }

    const data = await res.json();
    renderDiscovery(data);

    const label = data.total_failed > 0
      ? `${data.total_visited} pages mapped, ${data.total_failed} unreachable.`
      : `${data.total_visited} pages mapped successfully.`;
    setStatus(label, 'ok');
    $('crawl-tip').classList.remove('hidden');
    $('payload-url').value = data.seed_url;

  } catch (err) {
    setStatus(`Assessment failed: ${err.message}`, 'error');
  } finally {
    lockBtn('crawl-btn', false);
  }
}

function renderDiscovery(data) {
  const domainLabel = data.base_domain.length > 22
    ? data.base_domain.substring(0, 20) + '…'
    : data.base_domain;

  $('crawl-stats').innerHTML =
    makePill(data.total_visited, 'Pages Found',   data.total_visited > 0 ? 'green' : '') +
    makePill(data.total_failed,  'Unreachable',   data.total_failed  > 0 ? 'red'   : '') +
    makePill(data.crawl_depth,   'Depth Used') +
    makePill(domainLabel,        'Domain');

  $('crawl-url-count').textContent = `${data.total_visited} pages`;
  $('url-list').innerHTML = data.visited_urls.map(u =>
    `<div class="url-item">
      <span class="udot"><i class="bi bi-link-45deg"></i></span>
      <a href="${escHtml(u)}" target="_blank" rel="noopener noreferrer">${escHtml(u)}</a>
    </div>`
  ).join('');

  if (data.failed_urls.length > 0) {
    $('failed-section').classList.remove('hidden');
    $('failed-count').textContent = `${data.total_failed}`;
    $('failed-list').innerHTML = data.failed_urls.map(u =>
      `<div class="url-item">
        <span class="udot fail"><i class="bi bi-x-circle"></i></span>
        <span style="color:var(--text-muted)">${escHtml(u)}</span>
      </div>`
    ).join('');
  } else {
    $('failed-section').classList.add('hidden');
  }
}

// ══════════════════════════════════════════════════════════════
// INJECTION (PAYLOAD ENGINE)
// ══════════════════════════════════════════════════════════════
async function startPayload() {
  const url     = $('payload-url').value.trim();
  const type    = $('payload-type').value;
  const maxPay  = parseInt($('payload-max').value, 10);

  if (!url) {
    setStatus('Please enter a target URL.', 'error'); return;
  }
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    setStatus('URL must begin with http:// or https://', 'error'); return;
  }

  lockBtn('payload-btn', true);
  showPanel('payload-results', 'injection findings');
  setStatus(`Running ${type === 'both' ? 'full' : type.toUpperCase()} assessment against ${url}…`, 'info', true);

  try {
    const res = await fetch(`${API}/api/scan/payload`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ target_url: url, payload_type: type, max_payloads: maxPay }),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || `Server responded with ${res.status}`);
    }

    const data = await res.json();
    renderInjection(data);

    const statusMsg = data.total_vulnerable > 0
      ? `${data.total_vulnerable} potential finding${data.total_vulnerable > 1 ? 's' : ''} detected. Review results below.`
      : 'Assessment complete — no obvious vulnerabilities detected in this pass.';
    setStatus(statusMsg, data.total_vulnerable > 0 ? 'warn' : 'ok');

  } catch (err) {
    setStatus(`Assessment failed: ${err.message}`, 'error');
  } finally {
    lockBtn('payload-btn', false);
  }
}

function renderInjection(data) {
  $('payload-stats').innerHTML =
    makePill(data.total_tested,     'Tests Run') +
    makePill(data.total_vulnerable, 'Flagged',   data.total_vulnerable > 0 ? 'red'    : 'green') +
    makePill(data.total_clean,      'Clean',     data.total_clean      > 0 ? 'green'  : '') +
    makePill(data.total_errors,     'Errors',    data.total_errors     > 0 ? 'yellow' : '');

  $('payload-count').textContent = `${data.total_tested} tests`;

  $('payload-list').innerHTML = data.results.map(r => {
    const isVuln  = r.status === 'vulnerable';
    const isError = r.status === 'error';

    const typeLabel = r.type === 'sqli'
      ? '<span style="color:#60a5fa;font-size:.68rem;font-weight:700">SQL INJECTION</span>'
      : '<span style="color:#fb923c;font-size:.68rem;font-weight:700">XSS</span>';

    const statusHtml = isVuln
      ? '<span class="pc-vuln"><i class="bi bi-exclamation-triangle-fill me-1"></i>Potentially Vulnerable</span>'
      : isError
      ? '<span class="pc-err"><i class="bi bi-wifi-off me-1"></i>Request Failed</span>'
      : '<span class="pc-safe"><i class="bi bi-check-circle-fill me-1"></i>No Issue Detected</span>';

    return `<div class="payload-card ${isVuln ? 'vuln' : ''}">
      <div class="pc-url">
        ${typeLabel}
        <span style="color:var(--text-dim);margin-left:8px">${escHtml(r.url)}</span>
      </div>
      <div class="pc-pl"><i class="bi bi-code me-1"></i>${escHtml(r.payload)}</div>
      <div class="pc-stat">
        ${statusHtml}
        ${r.status_code ? `<span style="color:var(--text-muted)">HTTP ${r.status_code}</span>` : ''}
        ${r.param       ? `<span style="color:var(--text-muted)">param: <code style="color:var(--cyan-dim)">${escHtml(r.param)}</code></span>` : ''}
        ${r.evidence    ? `<span style="color:var(--yellow);font-size:.68rem">evidence: "${escHtml(r.evidence)}"</span>` : ''}
      </div>
    </div>`;
  }).join('');
}

// ── Enter key support ──────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  $('crawl-url')  ?.addEventListener('keydown', e => { if (e.key === 'Enter') startCrawl(); });
  $('payload-url')?.addEventListener('keydown', e => { if (e.key === 'Enter') startPayload(); });
});