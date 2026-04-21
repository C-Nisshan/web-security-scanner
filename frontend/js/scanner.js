/* scanner.js — Assessment Console Controller (v2)
   Handles: Discovery, Injection, Full Scan, Report Download */

const API = 'http://127.0.0.1:5000';
const $   = id => document.getElementById(id);

// ── Active scan tracking ──────────────────────────────────────
let _currentScanId = null;

// ── Tab switching ─────────────────────────────────────────────
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
  ['crawl-results','payload-results','full-results'].forEach(id => {
    const el = $(id); if (el) el.classList.add('hidden');
  });
  $('empty-state').classList.remove('hidden');
  $('results-title').textContent = 'results';
  _currentScanId = null;
  hideReportBar();
}

function showPanel(id, title) {
  $('empty-state').classList.add('hidden');
  ['crawl-results','payload-results','full-results'].forEach(el => {
    const e = $(el); if (e) e.classList.add('hidden');
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
  return String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

// ── Report download bar ───────────────────────────────────────
function showReportBar(scanId, hasHtml, hasPdf) {
  const bar = $('report-bar');
  if (!bar) return;
  bar.classList.remove('hidden');
  const htmlBtn = $('dl-html');
  const pdfBtn  = $('dl-pdf');
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
  if (bar) bar.classList.add('hidden');
}

// ══════════════════════════════════════════════════════════════
// DISCOVERY (CRAWLER)
// ══════════════════════════════════════════════════════════════
async function startCrawl() {
  const url      = $('crawl-url').value.trim();
  const maxDepth = parseInt($('crawl-depth').value, 10);
  const maxUrls  = parseInt($('crawl-maxurls').value, 10);

  if (!url) { setStatus('Please enter a target URL to begin discovery.', 'error'); return; }
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    setStatus('URL must begin with http:// or https://', 'error'); return;
  }

  lockBtn('crawl-btn', true);
  $('crawl-tip').classList.add('hidden');
  showPanel('crawl-results', 'discovery');
  setStatus(`Mapping ${url} — depth ${maxDepth}, up to ${maxUrls} pages…`, 'info', true);

  try {
    const res  = await fetch(`${API}/api/scan/crawl`, {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ target_url:url, max_depth:maxDepth, max_urls:maxUrls }),
    });
    if (!res.ok) { const e = await res.json().catch(()=>({})); throw new Error(e.error||`Server error ${res.status}`); }
    const data = await res.json();
    renderDiscovery(data);
    const label = data.total_failed > 0
      ? `${data.total_visited} pages mapped, ${data.total_failed} unreachable.`
      : `${data.total_visited} pages mapped successfully.`;
    setStatus(label, 'ok');
    $('crawl-tip').classList.remove('hidden');
    if ($('payload-url')) $('payload-url').value = data.seed_url;
    if ($('full-url'))    $('full-url').value    = data.seed_url;
  } catch (err) {
    setStatus(`Assessment failed: ${err.message}`, 'error');
  } finally {
    lockBtn('crawl-btn', false);
  }
}

function renderDiscovery(data) {
  const domainLabel = data.base_domain.length > 22
    ? data.base_domain.substring(0, 20) + '…' : data.base_domain;

  $('crawl-stats').innerHTML =
    makePill(data.total_visited, 'Pages Found', data.total_visited > 0 ? 'green':'') +
    makePill(data.total_failed,  'Unreachable', data.total_failed  > 0 ? 'red':'') +
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
  const url    = $('payload-url').value.trim();
  const type   = $('payload-type').value;
  const maxPay = parseInt($('payload-max').value, 10);

  if (!url) { setStatus('Please enter a target URL.', 'error'); return; }
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    setStatus('URL must begin with http:// or https://', 'error'); return;
  }

  lockBtn('payload-btn', true);
  showPanel('payload-results', 'injection findings');
  setStatus(`Running ${type === 'both' ? 'full' : type.toUpperCase()} assessment…`, 'info', true);

  try {
    const res  = await fetch(`${API}/api/scan/payload`, {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ target_url:url, payload_type:type, max_payloads:maxPay }),
    });
    if (!res.ok) { const e = await res.json().catch(()=>({})); throw new Error(e.error||`Server error ${res.status}`); }
    const data = await res.json();
    renderInjection(data);
    const statusMsg = data.total_vulnerable > 0
      ? `${data.total_vulnerable} potential finding${data.total_vulnerable > 1 ? 's':''} detected.`
      : 'Assessment complete — no obvious vulnerabilities detected.';
    setStatus(statusMsg, data.total_vulnerable > 0 ? 'warn':'ok');
  } catch (err) {
    setStatus(`Assessment failed: ${err.message}`, 'error');
  } finally {
    lockBtn('payload-btn', false);
  }
}

function renderInjection(data) {
  $('payload-stats').innerHTML =
    makePill(data.total_tested,     'Tests Run') +
    makePill(data.total_vulnerable, 'Flagged',  data.total_vulnerable > 0 ? 'red':'green') +
    makePill(data.total_clean,      'Clean',    data.total_clean > 0 ? 'green':'') +
    makePill(data.total_errors,     'Errors',   data.total_errors > 0 ? 'yellow':'');

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

    return `<div class="payload-card ${isVuln ? 'vuln':''}">
      <div class="pc-url">${typeLabel}
        <span style="color:var(--text-dim);margin-left:8px">${escHtml(r.url)}</span>
      </div>
      <div class="pc-pl"><i class="bi bi-code me-1"></i>${escHtml(r.payload)}</div>
      <div class="pc-stat">
        ${statusHtml}
        ${r.status_code ? `<span style="color:var(--text-muted)">HTTP ${r.status_code}</span>`:''}
        ${r.param       ? `<span style="color:var(--text-muted)">param: <code style="color:var(--cyan-dim)">${escHtml(r.param)}</code></span>`:''}
        ${r.evidence    ? `<span style="color:var(--yellow);font-size:.68rem">evidence: "${escHtml(r.evidence)}"</span>`:''}
      </div>
    </div>`;
  }).join('');
}

// ══════════════════════════════════════════════════════════════
// FULL SCAN PIPELINE
// ══════════════════════════════════════════════════════════════
async function startFullScan() {
  const url        = $('full-url').value.trim();
  const maxDepth   = parseInt($('full-depth').value,   10);
  const maxUrls    = parseInt($('full-maxurls').value, 10);
  const maxTargets = parseInt($('full-targets').value, 10);
  const payType    = $('full-payload-type').value;

  if (!url) { setStatus('Please enter a target URL.', 'error'); return; }
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    setStatus('URL must begin with http:// or https://', 'error'); return;
  }

  lockBtn('full-btn', true);
  hideReportBar();
  showPanel('full-results', 'full assessment');
  setStatus('Running full assessment — crawling, injecting, analysing…', 'info', true);

  // Animated progress phases
  const phases = [
    [10, 'Stage 1/4 — Crawling application…'],
    [35, 'Stage 2/4 — Selecting injection targets…'],
    [60, 'Stage 3/4 — Running payload tests…'],
    [85, 'Stage 4/4 — Analysing & generating report…'],
  ];
  let phaseIdx = 0;
  const phaseTimer = setInterval(() => {
    if (phaseIdx < phases.length) {
      const [, msg] = phases[phaseIdx++];
      setStatus(msg, 'info', true);
    }
  }, 4000);

  try {
    const res = await fetch(`${API}/api/scan/full`, {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({
        target_url: url, max_depth: maxDepth,
        max_urls: maxUrls, max_targets: maxTargets,
        payload_type: payType, max_payloads: 20,
      }),
    });
    clearInterval(phaseTimer);
    if (!res.ok) { const e = await res.json().catch(()=>({})); throw new Error(e.error||`Server error ${res.status}`); }
    const data = await res.json();
    _currentScanId = data.scan_id;
    renderFullResults(data);

    const risk     = data.analysis?.overall_risk || 'Unknown';
    const total    = data.analysis?.total_findings || 0;
    const statusType = total > 0 ? 'warn' : 'ok';
    setStatus(
      total > 0
        ? `⚠ Full scan complete — ${total} finding${total > 1 ? 's':''} detected. Overall risk: ${risk}`
        : '✅ Full scan complete — no vulnerabilities detected.',
      statusType
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
  const analysis = data.analysis || {};
  const crawl    = data.crawl_summary || {};
  const risk     = analysis.overall_risk || 'Unknown';

  const riskColors = {
    Critical:'#ff4757', High:'#ff6b35', Medium:'#ffd32a',
    Low:'#00d4ff', Clean:'#00ff88'
  };
  const riskColor = riskColors[risk] || '#6b7a99';

  // ── Stats pills ───────────────────────────────────────────
  $('full-stats').innerHTML =
    makePill(analysis.total_findings || 0, 'Findings', analysis.total_findings > 0 ? 'red':'green') +
    makePill(analysis.critical_count || 0, 'Critical',  analysis.critical_count  > 0 ? 'red':'') +
    makePill(analysis.high_count     || 0, 'High',      analysis.high_count      > 0 ? 'red':'') +
    makePill(crawl.total_visited     || 0, 'Pages',     'green') +
    makePill(data.duration || 'N/A',       'Duration');

  // ── Risk badge ────────────────────────────────────────────
  $('full-risk-badge').innerHTML =
    `<span style="background:${riskColor}22;color:${riskColor};border:1px solid ${riskColor}44;
      padding:5px 18px;border-radius:100px;font-size:.82rem;font-weight:700;display:inline-block">
      Overall Risk: ${escHtml(risk)}
    </span>`;

  // ── Findings table ────────────────────────────────────────
  const findings = analysis.findings || [];
  const tbody    = $('full-findings-tbody');
  const section  = $('full-findings-section');

  if (findings.length === 0) {
    section.classList.add('hidden');
    $('full-clean-msg').classList.remove('hidden');
  } else {
    section.classList.remove('hidden');
    $('full-clean-msg').classList.add('hidden');
    $('full-findings-count').textContent = `${findings.length} finding${findings.length>1?'s':''}`;

    tbody.innerHTML = findings.map(f => {
      const sc = riskColors[f.severity_label] || '#6b7a99';
      const techniques = (f.techniques||[]).map(t =>
        `<span class="technique-tag">${escHtml(t)}</span>`
      ).join('');

      // Show first evidence
      let evidenceHtml = '';
      const ev = f.findings_detail?.[0]?.evidence || '';
      if (ev) {
        evidenceHtml = `<div style="margin-top:6px;font-size:.7rem;color:var(--yellow);
          font-family:var(--font-mono);word-break:break-all">
          ⚡ ${escHtml(String(ev).slice(0,100))}
        </div>`;
      }

      return `<div class="finding-row">
        <div class="fr-header">
          <span class="fr-id">#${f.id}</span>
          <span class="fr-title">${escHtml(f.vulnerability)}</span>
          <span class="fr-sev" style="background:${sc}22;color:${sc};border:1px solid ${sc}44">
            ${escHtml(f.severity_label)}
          </span>
        </div>
        <div class="fr-body">
          <div class="fr-row">
            <span class="fr-label">URL</span>
            <span class="fr-val"><a href="${escHtml(f.url)}" target="_blank">${escHtml(f.url)}</a></span>
          </div>
          <div class="fr-row">
            <span class="fr-label">Parameter</span>
            <span class="fr-val"><code style="color:var(--cyan-dim)">${escHtml(f.param)}</code></span>
          </div>
          <div class="fr-row">
            <span class="fr-label">Techniques</span>
            <span class="fr-val">${techniques}</span>
          </div>
          <div class="fr-row">
            <span class="fr-label">OWASP</span>
            <span class="fr-val">
              <a href="${escHtml(f.owasp_url||'')}" target="_blank">${escHtml(f.owasp_ref||'')}</a>
              &mdash; ${escHtml(f.cwe||'')}
            </span>
          </div>
          ${evidenceHtml}
          <details style="margin-top:10px">
            <summary style="font-size:.75rem;color:var(--cyan);cursor:pointer">
              View Remediation Steps
            </summary>
            <ol style="margin-top:8px;padding-left:18px">
              ${(f.remediation_steps||[]).map(s =>
                `<li style="font-size:.78rem;color:var(--text-dim);margin-bottom:4px">${escHtml(s)}</li>`
              ).join('')}
            </ol>
          </details>
        </div>
      </div>`;
    }).join('');
  }

  // ── Recommendations ───────────────────────────────────────
  const recs = analysis.recommendations || [];
  $('full-recs-list').innerHTML = recs.map(r =>
    `<li style="padding:8px 14px;border-left:3px solid var(--cyan);
      background:var(--bg);border-radius:0 8px 8px 0;
      font-size:.82rem;color:var(--text-dim);margin-bottom:6px">
      ${escHtml(r)}
    </li>`
  ).join('');
}

// Technique tag style (injected into page head via JS)
const tagStyle = document.createElement('style');
tagStyle.textContent = `
  .technique-tag{display:inline-block;background:#00d4ff15;border:1px solid #00d4ff30;
    border-radius:20px;padding:2px 8px;font-size:.68rem;color:#00d4ff;margin-right:4px}
  .finding-row{background:var(--bg);border:1px solid var(--border);border-radius:9px;
    margin-bottom:10px;overflow:hidden}
  .fr-header{display:flex;align-items:center;gap:10px;padding:10px 14px;
    background:var(--surface2);border-bottom:1px solid var(--border)}
  .fr-id{font-size:.72rem;font-weight:700;color:var(--text-muted)}
  .fr-title{font-size:.88rem;font-weight:700;color:#fff;flex:1}
  .fr-sev{padding:2px 10px;border-radius:20px;font-size:.7rem;font-weight:700}
  .fr-body{padding:12px 14px}
  .fr-row{display:flex;gap:10px;margin-bottom:6px;font-size:.8rem}
  .fr-label{color:var(--text-muted);font-size:.68rem;text-transform:uppercase;
    letter-spacing:.06em;min-width:80px;margin-top:2px}
  .fr-val{color:var(--text-dim);word-break:break-all}
`;
document.head.appendChild(tagStyle);

// ── Enter key support ──────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  $('crawl-url')  ?.addEventListener('keydown', e => { if (e.key==='Enter') startCrawl(); });
  $('payload-url')?.addEventListener('keydown', e => { if (e.key==='Enter') startPayload(); });
  $('full-url')   ?.addEventListener('keydown', e => { if (e.key==='Enter') startFullScan(); });
});