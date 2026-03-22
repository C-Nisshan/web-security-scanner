/**
 * app.js — Scanner Frontend Controller
 * Handles both Crawler and Payload Engine API calls.
 */

const API = 'http://127.0.0.1:5000';
const $ = id => document.getElementById(id);

// ── Tab switching ────────────────────────────────────────────
function switchTab(tab) {
  document.querySelectorAll('.tab-btn').forEach((b, i) => {
    b.classList.toggle('active', (i === 0 && tab === 'crawl') || (i === 1 && tab === 'payload'));
  });
  $('crawl-config').classList.toggle('hidden', tab !== 'crawl');
  $('payload-config').classList.toggle('hidden', tab !== 'payload');
  resetResults();
}

// ── Shared UI helpers ────────────────────────────────────────
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
  $('results-title').textContent = '📊 Results';
}

function showResults(id, title) {
  $('empty-state').classList.add('hidden');
  $('crawl-results').classList.add('hidden');
  $('payload-results').classList.add('hidden');
  $(id).classList.remove('hidden');
  $('results-title').textContent = title;
}

// ── Pill builder ─────────────────────────────────────────────
function makePill(val, label, cls = '') {
  return `<div class="stat-pill ${cls}">
    <span class="sv">${val}</span>
    <span class="sl">${label}</span>
  </div>`;
}

// ════════════════════════════════════════════════════════════
// CRAWLER
// ════════════════════════════════════════════════════════════
async function startCrawl() {
  const url      = $('crawl-url').value.trim();
  const maxDepth = parseInt($('crawl-depth').value);
  const maxUrls  = parseInt($('crawl-maxurls').value);

  if (!url) { setStatus('⚠️  Please enter a target URL.', 'error'); return; }
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    setStatus('⚠️  URL must start with http:// or https://', 'error'); return;
  }

  showResults('crawl-results', '🕷️ Crawl Results');
  setStatus(`Crawling ${url} — depth ${maxDepth}, max ${maxUrls} URLs…`, 'info', true);

  try {
    const res = await fetch(`${API}/api/scan/crawl`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target_url: url, max_depth: maxDepth, max_urls: maxUrls }),
    });
    if (!res.ok) { const e = await res.json().catch(() => ({})); throw new Error(e.error || `Server error ${res.status}`); }
    const data = await res.json();
    renderCrawlResults(data);
    setStatus(`✅ Crawl complete — ${data.total_visited} URLs visited, ${data.total_failed} failed.`, 'ok');
    $('crawl-paste-hint').classList.remove('hidden');
    // Pre-fill payload URL with seed
    $('payload-url').value = data.seed_url;
  } catch (err) {
    setStatus(`❌  ${err.message}`, 'error');
  }
}

function renderCrawlResults(data) {
  $('crawl-stats').innerHTML =
    makePill(data.total_visited, 'Visited', 'green') +
    makePill(data.total_failed, 'Failed', data.total_failed > 0 ? 'red' : '') +
    makePill(data.crawl_depth, 'Depth') +
    makePill(data.base_domain.length > 18 ? data.base_domain.substring(0, 16) + '…' : data.base_domain, 'Domain');

  $('crawl-url-count').textContent = `${data.total_visited} URLs`;
  const ul = $('url-list');
  ul.innerHTML = data.visited_urls.map(u =>
    `<div class="url-item">
      <span class="udot">●</span>
      <a href="${u}" target="_blank" rel="noopener">${u}</a>
    </div>`
  ).join('');

  if (data.failed_urls.length > 0) {
    $('failed-section').classList.remove('hidden');
    $('failed-count').textContent = `${data.total_failed}`;
    $('failed-list').innerHTML = data.failed_urls.map(u =>
      `<div class="url-item"><span class="udot fail">●</span><span style="color:var(--text-muted)">${u}</span></div>`
    ).join('');
  } else {
    $('failed-section').classList.add('hidden');
  }
}

// ════════════════════════════════════════════════════════════
// PAYLOAD ENGINE
// ════════════════════════════════════════════════════════════
async function startPayload() {
  const url      = $('payload-url').value.trim();
  const type     = $('payload-type').value;
  const maxPay   = parseInt($('payload-max').value);

  if (!url) { setStatus('⚠️  Please enter a target URL.', 'error'); return; }
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    setStatus('⚠️  URL must start with http:// or https://', 'error'); return;
  }

  showResults('payload-results', '💉 Payload Results');
  setStatus(`Injecting payloads into ${url}…`, 'info', true);

  try {
    const res = await fetch(`${API}/api/scan/payload`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target_url: url, payload_type: type, max_payloads: maxPay }),
    });
    if (!res.ok) { const e = await res.json().catch(() => ({})); throw new Error(e.error || `Server error ${res.status}`); }
    const data = await res.json();
    renderPayloadResults(data);
    const vulnMsg = data.total_vulnerable > 0
      ? `⚠️  ${data.total_vulnerable} potential vulnerabilities found!`
      : `✅ Scan complete — no obvious vulnerabilities detected.`;
    setStatus(vulnMsg, data.total_vulnerable > 0 ? 'warn' : 'ok');
  } catch (err) {
    setStatus(`❌  ${err.message}`, 'error');
  }
}

function renderPayloadResults(data) {
  $('payload-stats').innerHTML =
    makePill(data.total_tested, 'Tested') +
    makePill(data.total_vulnerable, 'Vulnerable', data.total_vulnerable > 0 ? 'red' : 'green') +
    makePill(data.total_errors, 'Errors', 'yellow') +
    makePill(data.total_clean, 'Clean', 'green');

  $('payload-count').textContent = `${data.total_tested} tests`;

  const list = $('payload-list');
  list.innerHTML = data.results.map(r => {
    let statusClass = 'pc-safe', statusLabel = '✅ Clean';
    if (r.status === 'vulnerable') { statusClass = 'pc-vuln'; statusLabel = '🚨 Potentially Vulnerable'; }
    if (r.status === 'error')      { statusClass = 'pc-err';  statusLabel = '⚠️ Request Error'; }

    return `<div class="payload-card">
      <div class="pc-url">🌐 ${r.url}</div>
      <div class="pc-pl">💉 ${escHtml(r.payload)}</div>
      <div class="pc-stat">
        <span class="${statusClass}">${statusLabel}</span>
        ${r.status_code ? `<span style="color:var(--text-muted);margin-left:10px">HTTP ${r.status_code}</span>` : ''}
        ${r.param ? `<span style="color:var(--text-muted);margin-left:10px">param: ${r.param}</span>` : ''}
        ${r.evidence ? `<span style="color:var(--yellow);margin-left:10px;font-size:.68rem">match: "${escHtml(r.evidence)}"</span>` : ''}
      </div>
    </div>`;
  }).join('');
}

function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

// ── Enter key support ────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  $('crawl-url')  ?.addEventListener('keydown', e => { if (e.key === 'Enter') startCrawl(); });
  $('payload-url')?.addEventListener('keydown', e => { if (e.key === 'Enter') startPayload(); });
});