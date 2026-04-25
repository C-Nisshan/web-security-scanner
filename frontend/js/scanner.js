/* scanner.js — Assessment Console Controller
   Handles: Discovery, Injection, Full Scan, Report Download

   Bug fixes applied in this version:
   1. showReportBar / hideReportBar now use element.style.display directly
      (previously toggled a .hidden class that was overridden by an inline
      display:flex on the element, making the bar permanently visible).
   2. Full scan phase messages now start immediately at phase 1; previously
      the first phase only appeared after a 4-second setInterval delay.
   3. Phase percentage values were dead code (destructured but never used);
      replaced with a simple message string array.
   4. resetResults() now also resets the full-findings-section and
      full-recs-section hidden state to prevent stale content flashing
      when switching tabs after a completed scan.
   5. Added null guards throughout renderFullResults for API fields that
      may be absent in partial or error responses.
*/

const API = 'http://127.0.0.1:5000';
const $   = id => document.getElementById(id);

// Active scan tracking
let _currentScanId = null;

// ── Tab switching ──────────────────────────────────────────────
function switchTab(tab) {
  const tabs = ['crawl', 'payload', 'full'];
  document.querySelectorAll('.tab-btn').forEach((b, i) => {
    b.classList.toggle('active', tabs[i] === tab);
  });
  tabs.forEach(t => {
    const el = $(t + '-config');
    if (el) el.classList.toggle('hidden', t !== tab);
  });
  resetResults();
}

// ── UI helpers ─────────────────────────────────────────────────
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
  ['crawl-results', 'payload-results', 'full-results'].forEach(id => {
    const el = $(id);
    if (el) el.classList.add('hidden');
  });
  $('empty-state').classList.remove('hidden');
  $('results-title').textContent = 'results';
  _currentScanId = null;
  hideReportBar();

  // Reset full-scan sub-sections so they don't flash stale content
  // on the next tab switch or scan run
  const findingsSection = $('full-findings-section');
  const recsSection     = $('full-recs-section');
  const cleanMsg        = $('full-clean-msg');
  if (findingsSection) findingsSection.classList.add('hidden');
  if (recsSection)     recsSection.classList.add('hidden');
  if (cleanMsg)        cleanMsg.classList.add('hidden');
}

function showPanel(id, title) {
  $('empty-state').classList.add('hidden');
  ['crawl-results', 'payload-results', 'full-results'].forEach(el => {
    const e = $(el);
    if (e) e.classList.add('hidden');
  });
  const target = $(id);
  if (target) target.classList.remove('hidden');
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
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ── Report download bar ────────────────────────────────────────
//
// BUG FIX: the bar element has a flex layout applied via inline style.
// Toggling a .hidden CSS class cannot override inline styles (inline rules
// have higher CSS specificity). We therefore control visibility directly
// via element.style.display instead of a class.
//
function showReportBar(scanId, hasHtml, hasPdf) {
  const bar     = $('report-bar');
  const htmlBtn = $('dl-html');
  const pdfBtn  = $('dl-pdf');
  if (!bar) return;

  bar.style.display = 'flex';   // direct style — not a class

  if (htmlBtn) {
    htmlBtn.style.display = hasHtml ? 'inline-flex' : 'none';
    htmlBtn.onclick = () => window.open(`${API}/api/report/${scanId}/html`, '_blank');
  }
  if (pdfBtn) {
    pdfBtn.style.display = hasPdf ? 'inline-flex' : 'none';
    pdfBtn.onclick = () => window.open(`${API}/api/report/${scanId}/pdf`, '_blank');
  }
}

function hideReportBar() {
  const bar = $('report-bar');
  if (bar) bar.style.display = 'none';   // direct style — not a class
}

// ══════════════════════════════════════════════════════════════
// DISCOVERY (CRAWLER)
// ══════════════════════════════════════════════════════════════
async function startCrawl() {
  const url      = $('crawl-url').value.trim();
  const maxDepth = parseInt($('crawl-depth').value, 10);
  const maxUrls  = parseInt($('crawl-maxurls').value, 10);

  if (!url) {
    setStatus('Please enter a target URL to begin discovery.', 'error');
    return;
  }
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    setStatus('URL must begin with http:// or https://', 'error');
    return;
  }

  lockBtn('crawl-btn', true);
  $('crawl-tip').classList.add('hidden');
  showPanel('crawl-results', 'discovery');
  setStatus(`Mapping ${url} — depth ${maxDepth}, up to ${maxUrls} pages…`, 'info', true);

  try {
    const res = await fetch(`${API}/api/scan/crawl`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target_url: url, max_depth: maxDepth, max_urls: maxUrls }),
    });
    if (!res.ok) {
      const e = await res.json().catch(() => ({}));
      throw new Error(e.error || `Server error ${res.status}`);
    }
    const data = await res.json();
    renderDiscovery(data);
    const label = data.total_failed > 0
      ? `${data.total_visited} pages mapped, ${data.total_failed} unreachable.`
      : `${data.total_visited} pages mapped successfully.`;
    setStatus(label, 'ok');
    $('crawl-tip').classList.remove('hidden');
    if ($('payload-url')) $('payload-url').value = data.seed_url || url;
    if ($('full-url'))    $('full-url').value    = data.seed_url || url;
  } catch (err) {
    setStatus(`Assessment failed: ${err.message}`, 'error');
  } finally {
    lockBtn('crawl-btn', false);
  }
}

function renderDiscovery(data) {
  const domainLabel = (data.base_domain || '').length > 22
    ? data.base_domain.substring(0, 20) + '…'
    : (data.base_domain || 'unknown');

  $('crawl-stats').innerHTML =
    makePill(data.total_visited || 0, 'Pages Found', data.total_visited > 0 ? 'green' : '') +
    makePill(data.total_failed  || 0, 'Unreachable', data.total_failed  > 0 ? 'red'   : '') +
    makePill(data.crawl_depth   || 0, 'Depth Used') +
    makePill(domainLabel,            'Domain');

  $('crawl-url-count').textContent = `${data.total_visited || 0} pages`;
  $('url-list').innerHTML = (data.visited_urls || []).map(u =>
    `<div class="url-item">
      <span class="udot"><i class="bi bi-link-45deg"></i></span>
      <a href="${escHtml(u)}" target="_blank" rel="noopener noreferrer">${escHtml(u)}</a>
    </div>`
  ).join('');

  const failedSection = $('failed-section');
  if ((data.failed_urls || []).length > 0) {
    failedSection.classList.remove('hidden');
    $('failed-count').textContent = String(data.total_failed);
    $('failed-list').innerHTML = data.failed_urls.map(u =>
      `<div class="url-item">
        <span class="udot fail"><i class="bi bi-x-circle"></i></span>
        <span style="color:var(--text-muted)">${escHtml(u)}</span>
      </div>`
    ).join('');
  } else {
    failedSection.classList.add('hidden');
  }
}

// ══════════════════════════════════════════════════════════════
// INJECTION (PAYLOAD ENGINE)
// ══════════════════════════════════════════════════════════════
async function startPayload() {
  const url    = $('payload-url').value.trim();
  const type   = $('payload-type').value;
  const maxPay = parseInt($('payload-max').value, 10);

  if (!url) {
    setStatus('Please enter a target URL.', 'error');
    return;
  }
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    setStatus('URL must begin with http:// or https://', 'error');
    return;
  }

  lockBtn('payload-btn', true);
  showPanel('payload-results', 'injection findings');
  setStatus(`Running ${type === 'both' ? 'full' : type.toUpperCase()} assessment…`, 'info', true);

  try {
    const res = await fetch(`${API}/api/scan/payload`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target_url: url, payload_type: type, max_payloads: maxPay }),
    });
    if (!res.ok) {
      const e = await res.json().catch(() => ({}));
      throw new Error(e.error || `Server error ${res.status}`);
    }
    const data = await res.json();
    renderInjection(data);
    const statusMsg = data.total_vulnerable > 0
      ? `${data.total_vulnerable} potential finding${data.total_vulnerable > 1 ? 's' : ''} detected.`
      : 'Assessment complete — no obvious vulnerabilities detected.';
    setStatus(statusMsg, data.total_vulnerable > 0 ? 'warn' : 'ok');
  } catch (err) {
    setStatus(`Assessment failed: ${err.message}`, 'error');
  } finally {
    lockBtn('payload-btn', false);
  }
}

function renderInjection(data) {
  $('payload-stats').innerHTML =
    makePill(data.total_tested     || 0, 'Tests Run') +
    makePill(data.total_vulnerable || 0, 'Flagged',  (data.total_vulnerable || 0) > 0 ? 'red'    : 'green') +
    makePill(data.total_clean      || 0, 'Clean',    (data.total_clean      || 0) > 0 ? 'green'  : '') +
    makePill(data.total_errors     || 0, 'Errors',   (data.total_errors     || 0) > 0 ? 'yellow' : '');

  $('payload-count').textContent = `${data.total_tested || 0} tests`;

  $('payload-list').innerHTML = (data.results || []).map(r => {
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
      <div class="pc-url">${typeLabel}
        <span style="color:var(--text-dim);margin-left:8px">${escHtml(r.url)}</span>
      </div>
      <div class="pc-pl"><i class="bi bi-code me-1"></i>${escHtml(r.payload)}</div>
      <div class="pc-stat">
        ${statusHtml}
        ${r.param    ? `<span style="color:var(--text-muted)">param: <code style="color:var(--cyan-dim)">${escHtml(r.param)}</code></span>` : ''}
        ${r.evidence ? `<span style="color:var(--yellow);font-size:.68rem">evidence: "${escHtml(r.evidence)}"</span>` : ''}
      </div>
    </div>`;
  }).join('');
}

// ══════════════════════════════════════════════════════════════
// FULL SCAN PIPELINE
// ══════════════════════════════════════════════════════════════

// BUG FIX: was an array of [percentage, message] pairs, but the percentage
// values were never used (only the message was destructured).
// Replaced with a simple string array. Phase 1 is now shown immediately
// before the interval starts; previously it only appeared after 4 seconds.
const SCAN_PHASES = [
  'Stage 1 of 4 — Crawling application…',
  'Stage 2 of 4 — Selecting injection targets…',
  'Stage 3 of 4 — Running payload tests…',
  'Stage 4 of 4 — Analysing and generating report…',
];

async function startFullScan() {
  const url        = $('full-url').value.trim();
  const maxDepth   = parseInt($('full-depth').value,   10);
  const maxUrls    = parseInt($('full-maxurls').value, 10);
  const maxTargets = parseInt($('full-targets').value, 10);
  const payType    = $('full-payload-type').value;

  if (!url) {
    setStatus('Please enter a target URL.', 'error');
    return;
  }
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    setStatus('URL must begin with http:// or https://', 'error');
    return;
  }

  lockBtn('full-btn', true);
  hideReportBar();
  showPanel('full-results', 'full assessment');

  // BUG FIX: show phase 1 immediately instead of waiting 4 seconds
  setStatus(SCAN_PHASES[0], 'info', true);

  let phaseIdx  = 1;   // phases 2-4 are shown by the interval
  const phaseTimer = setInterval(() => {
    if (phaseIdx < SCAN_PHASES.length) {
      setStatus(SCAN_PHASES[phaseIdx++], 'info', true);
    }
  }, 5000);

  try {
    const res = await fetch(`${API}/api/scan/full`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        target_url:   url,
        max_depth:    maxDepth,
        max_urls:     maxUrls,
        max_targets:  maxTargets,
        payload_type: payType,
        max_payloads: 20,
      }),
    });
    clearInterval(phaseTimer);

    if (!res.ok) {
      const e = await res.json().catch(() => ({}));
      throw new Error(e.error || `Server error ${res.status}`);
    }

    const data = await res.json();
    _currentScanId = data.scan_id;
    renderFullResults(data);

    const risk  = data.analysis?.overall_risk || 'Unknown';
    const total = data.analysis?.total_findings || 0;
    setStatus(
      total > 0
        ? `Full scan complete — ${total} finding${total > 1 ? 's' : ''} detected. Overall risk: ${risk}`
        : 'Full scan complete — no vulnerabilities detected.',
      total > 0 ? 'warn' : 'ok'
    );

    if (data.report_available?.html || data.report_available?.pdf) {
      showReportBar(data.scan_id, data.report_available.html, data.report_available.pdf);
    }
  } catch (err) {
    clearInterval(phaseTimer);
    setStatus(`Full scan failed: ${err.message}`, 'error');
  } finally {
    lockBtn('full-btn', false);
  }
}

function renderFullResults(data) {
  const analysis = data.analysis       || {};
  const crawl    = data.crawl_summary  || {};

  const risk       = analysis.overall_risk    || 'Unknown';
  const total      = analysis.total_findings  || 0;
  const critical   = analysis.critical_count  || 0;
  const high       = analysis.high_count      || 0;
  const findings   = analysis.findings        || [];
  const recs       = analysis.recommendations || [];

  const riskColors = {
    Critical: '#ff4757', High: '#ff6b35', Medium: '#ffd32a',
    Low: '#00d4ff', Clean: '#00ff88',
  };
  const riskColor = riskColors[risk] || '#6b7a99';

  // Stats pills
  $('full-stats').innerHTML =
    makePill(total,                    'Findings', total    > 0 ? 'red'   : 'green') +
    makePill(critical,                 'Critical', critical > 0 ? 'red'   : '') +
    makePill(high,                     'High',     high     > 0 ? 'red'   : '') +
    makePill(crawl.total_visited || 0, 'Pages',    'green') +
    makePill(data.duration        || 'N/A', 'Duration');

  // Risk badge
  $('full-risk-badge').innerHTML =
    `<span style="background:${riskColor}22;color:${riskColor};border:1px solid ${riskColor}44;
      padding:5px 18px;border-radius:100px;font-size:.82rem;font-weight:700;display:inline-block">
      Overall Risk: ${escHtml(risk)}
    </span>`;

  // Findings section
  const findingsSection = $('full-findings-section');
  const cleanMsg        = $('full-clean-msg');

  if (findings.length === 0) {
    findingsSection.classList.add('hidden');
    cleanMsg.classList.remove('hidden');
  } else {
    cleanMsg.classList.add('hidden');
    findingsSection.classList.remove('hidden');

    $('full-findings-count').textContent =
      `${findings.length} finding${findings.length > 1 ? 's' : ''}`;

    $('full-findings-tbody').innerHTML = findings.map(f => {
      const sc = riskColors[f.severity_label] || '#6b7a99';

      const techniques = (f.techniques || []).map(t =>
        `<span class="technique-tag">${escHtml(t)}</span>`
      ).join('');

      // First evidence snippet from findings_detail
      const ev = f.findings_detail?.[0]?.evidence || '';
      const evidenceHtml = ev
        ? `<div style="margin-top:6px;font-size:.7rem;color:var(--yellow);
            font-family:var(--font-mono);word-break:break-all">
            Evidence: ${escHtml(String(ev).slice(0, 120))}
          </div>`
        : '';

      const remediationItems = (f.remediation_steps || []).map(s =>
        `<li style="font-size:.78rem;color:var(--text-dim);margin-bottom:4px">${escHtml(s)}</li>`
      ).join('');

      return `<div class="finding-row">
        <div class="fr-header">
          <span class="fr-id">#${escHtml(f.id)}</span>
          <span class="fr-title">${escHtml(f.vulnerability)}</span>
          <span class="fr-sev" style="background:${sc}22;color:${sc};border:1px solid ${sc}44">
            ${escHtml(f.severity_label)}
          </span>
        </div>
        <div class="fr-body">
          <div class="fr-row">
            <span class="fr-label">URL</span>
            <span class="fr-val">
              <a href="${escHtml(f.url)}" target="_blank" rel="noopener noreferrer">
                ${escHtml(f.url)}
              </a>
            </span>
          </div>
          <div class="fr-row">
            <span class="fr-label">Parameter</span>
            <span class="fr-val">
              <code style="color:var(--cyan-dim)">${escHtml(f.param)}</code>
            </span>
          </div>
          <div class="fr-row">
            <span class="fr-label">Techniques</span>
            <span class="fr-val">${techniques}</span>
          </div>
          <div class="fr-row">
            <span class="fr-label">OWASP / CWE</span>
            <span class="fr-val">
              <a href="${escHtml(f.owasp_url || '')}" target="_blank" rel="noopener noreferrer">
                ${escHtml(f.owasp_ref || 'N/A')}
              </a>
              ${f.cwe ? ` &mdash; ${escHtml(f.cwe)}` : ''}
            </span>
          </div>
          ${evidenceHtml}
          ${remediationItems ? `<details style="margin-top:10px">
            <summary style="font-size:.75rem;color:var(--cyan);cursor:pointer">
              View Remediation Steps
            </summary>
            <ol style="margin-top:8px;padding-left:18px">${remediationItems}</ol>
          </details>` : ''}
        </div>
      </div>`;
    }).join('');
  }

  // Recommendations
  const recsSection = $('full-recs-section');
  if (recs.length > 0) {
    recsSection.classList.remove('hidden');
    $('full-recs-list').innerHTML = recs.map(r =>
      `<li style="padding:8px 14px;border-left:3px solid var(--cyan);
        background:var(--bg);border-radius:0 8px 8px 0;
        font-size:.82rem;color:var(--text-dim);margin-bottom:6px">
        ${escHtml(r)}
      </li>`
    ).join('');
  } else {
    recsSection.classList.add('hidden');
  }
}

// ── Injected styles for finding cards and technique tags ───────
const tagStyle = document.createElement('style');
tagStyle.textContent = `
  .technique-tag {
    display:inline-block;
    background:#00d4ff15;border:1px solid #00d4ff30;
    border-radius:20px;padding:2px 8px;
    font-size:.68rem;color:#00d4ff;margin-right:4px;
  }
  .finding-row {
    background:var(--bg);border:1px solid var(--border);
    border-radius:9px;margin-bottom:10px;overflow:hidden;
  }
  .fr-header {
    display:flex;align-items:center;gap:10px;
    padding:10px 14px;background:var(--surface2);
    border-bottom:1px solid var(--border);
  }
  .fr-id    { font-size:.72rem;font-weight:700;color:var(--text-muted); }
  .fr-title { font-size:.88rem;font-weight:700;color:#fff;flex:1; }
  .fr-sev   { padding:2px 10px;border-radius:20px;font-size:.7rem;font-weight:700; }
  .fr-body  { padding:12px 14px; }
  .fr-row   { display:flex;gap:10px;margin-bottom:6px;font-size:.8rem; }
  .fr-label {
    color:var(--text-muted);font-size:.68rem;
    text-transform:uppercase;letter-spacing:.06em;
    min-width:80px;margin-top:2px;
  }
  .fr-val { color:var(--text-dim);word-break:break-all; }
`;
document.head.appendChild(tagStyle);

// ── Enter-key support ──────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  $('crawl-url')  ?.addEventListener('keydown', e => { if (e.key === 'Enter') startCrawl(); });
  $('payload-url')?.addEventListener('keydown', e => { if (e.key === 'Enter') startPayload(); });
  $('full-url')   ?.addEventListener('keydown', e => { if (e.key === 'Enter') startFullScan(); });
});