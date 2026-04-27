/* scanner.js — Assessment Console Controller  v3.1
   Handles: Discovery, Injection, Full Scan, Report Download, Authentication

   v3.1 additions vs v3.0
   -----------------------
   - testAuth(prefix)  : calls POST /api/auth/test and renders a live
                         pass/fail badge with actionable detail message
   - Auth test button added to every tab; result is cleared on tab switch
   - buildAuthFields now also shows/hides the DVWA hint card inline
   - collectAuth unchanged in interface but uses same prefix convention
   - All scan launchers unchanged (already pass auth)

   Bug fixes carried over from earlier versions
   ---------------------------------------------
   1. showReportBar / hideReportBar use element.style.display directly
   2. Phase 1 shown immediately (no 4-second delay)
   3. resetResults() clears all sub-sections to prevent stale flashes
   4. Null guards throughout renderFullResults
*/

const API = 'http://127.0.0.1:5000';
const $   = id => document.getElementById(id);

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
function showReportBar(scanId, hasHtml, hasPdf) {
  const bar     = $('report-bar');
  const htmlBtn = $('dl-html');
  const pdfBtn  = $('dl-pdf');
  if (!bar) return;
  bar.style.display = 'flex';
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
  if (bar) bar.style.display = 'none';
}

// ══════════════════════════════════════════════════════════════
// AUTHENTICATION HELPERS
// ══════════════════════════════════════════════════════════════

function toggleAuth(prefix) {
  const section = $(prefix + '-auth-section');
  const chevron = $(prefix + '-auth-chevron');
  const toggle  = $(prefix + '-auth-toggle');
  if (!section) return;
  const hidden = section.classList.toggle('hidden');
  if (chevron) chevron.className = hidden ? 'bi bi-chevron-down' : 'bi bi-chevron-up';
  if (toggle)  toggle.classList.toggle('active', !hidden);
  // Clear badge when closing
  if (hidden) _clearAuthBadge(prefix);
}

function _clearAuthBadge(prefix) {
  const badge = $(prefix + '-auth-badge');
  if (badge) badge.innerHTML = '';
}

function _setAuthBadge(prefix, ok, msg) {
  const badge = $(prefix + '-auth-badge');
  if (!badge) return;
  const color = ok ? 'var(--green)' : 'var(--red)';
  const icon  = ok ? 'bi-check-circle-fill' : 'bi-x-circle-fill';
  badge.innerHTML = `
    <div style="display:flex;align-items:flex-start;gap:8px;margin-top:8px;
      padding:9px 12px;border-radius:8px;font-size:.78rem;
      background:${ok ? '#00ff8810' : '#ff475710'};
      border:1px solid ${ok ? '#00ff8830' : '#ff475730'}">
      <i class="bi ${icon}" style="color:${color};margin-top:2px;flex-shrink:0"></i>
      <span style="color:${ok ? 'var(--green)' : '#ffa198'};line-height:1.5">${escHtml(msg)}</span>
    </div>`;
}

/**
 * Call POST /api/auth/test and display a pass/fail badge inline.
 * Also returns true/false so callers can abort if auth already failed.
 */
async function testAuth(prefix) {
  const auth = collectAuth(prefix);
  if (!auth) {
    _setAuthBadge(prefix, false, 'Select an auth type before testing.');
    return false;
  }

  const btn = $(prefix + '-auth-test-btn');
  if (btn) { btn.disabled = true; btn.textContent = 'Testing…'; }
  _setAuthBadge(prefix, null, '');

  try {
    const res  = await fetch(`${API}/api/auth/test`, {
      method : 'POST',
      headers: { 'Content-Type': 'application/json' },
      body   : JSON.stringify({ auth }),
    });
    const data = await res.json();

    if (data.success) {
      const cookieNames = Object.keys(data.cookies || {}).join(', ') || 'none';
      _setAuthBadge(prefix, true,
        `${data.detail} · Cookies: ${cookieNames}`
      );
      return true;
    } else {
      _setAuthBadge(prefix, false, data.detail || 'Authentication failed.');
      return false;
    }
  } catch (err) {
    _setAuthBadge(prefix, false, `Could not reach backend: ${err.message}`);
    return false;
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Test Auth'; }
  }
}

function buildAuthFields(prefix) {
  const typeEl    = $(prefix + '-auth-type');
  const container = $(prefix + '-auth-fields');
  if (!typeEl || !container) return;
  const type = typeEl.value;

  // Clear the badge whenever the type changes
  _clearAuthBadge(prefix);

  const field = (id, label, placeholder, inputType = 'text', value = '') =>
    `<div class="mb-2">
       <label class="cyber-label">${label}</label>
       <input type="${inputType}" id="${prefix}-auth-${id}" class="cyber-input"
              placeholder="${escHtml(placeholder)}" value="${escHtml(value)}"/>
     </div>`;

  const row2 = (idA, labelA, phA, idB, labelB, phB, typeB = 'password', valA = '', valB = '') =>
    `<div class="row g-2 mb-2">
       <div class="col-6">
         <label class="cyber-label">${labelA}</label>
         <input type="text" id="${prefix}-auth-${idA}" class="cyber-input"
                placeholder="${escHtml(phA)}" value="${escHtml(valA)}"/>
       </div>
       <div class="col-6">
         <label class="cyber-label">${labelB}</label>
         <input type="${typeB}" id="${prefix}-auth-${idB}" class="cyber-input"
                placeholder="${escHtml(phB)}" value="${escHtml(valB)}"/>
       </div>
     </div>`;

  const templates = {
    none: '',

    cookie: `
      ${field('cookie', 'Cookie String', 'PHPSESSID=abc123; security=low')}
      <p class="auth-hint">Paste the raw cookie value from DevTools → Application → Cookies.</p>`,

    bearer: `
      ${field('token', 'Bearer Token', 'eyJhbGciOiJIUzI1NiIs...')}
      <p class="auth-hint">JWT or API token — do not include the "Bearer " prefix.</p>`,

    basic: `
      ${row2('user', 'Username', 'admin', 'pass', 'Password', '••••••••', 'password')}`,

    dvwa: `
      ${field('base', 'DVWA Base URL', 'http://dvwa:80', 'text', 'http://dvwa:80')}
      <div class="dvwa-hint-box">
        <i class="bi bi-info-circle me-1"></i>
        Inside Docker use <code>http://dvwa:80</code>.<br/>
        From your browser use <code>http://localhost:8080</code>.
      </div>
      ${row2('user', 'Username', 'admin', 'pass', 'Password', 'password', 'password', 'admin', 'password')}
      <div class="mb-2">
        <label class="cyber-label">Security Level</label>
        <select id="${prefix}-auth-dvwa-sec" class="cyber-input cyber-select">
          <option value="low">Low</option>
          <option value="medium">Medium</option>
          <option value="high">High</option>
          <option value="impossible">Impossible</option>
        </select>
      </div>`,

    form: `
      ${field('login-url', 'Login Endpoint URL', 'http://target/login.php')}
      ${row2('user-field', 'Username Field Name', 'username', 'pass-field', 'Password Field Name', 'password', 'text')}
      ${row2('user', 'Username Value', 'admin', 'pass', 'Password Value', '••••••••', 'password')}
      ${field('success', 'Success Indicator (optional)', 'dashboard')}
      <p class="auth-hint">Field names must match the HTML <code>name</code> attributes exactly.</p>`,
  };

  container.innerHTML = templates[type] !== undefined
    ? `<div class="auth-fields-inner">${templates[type]}</div>` : '';
}

function collectAuth(prefix) {
  const typeEl = $(prefix + '-auth-type');
  if (!typeEl) return null;
  const type = typeEl.value;
  if (type === 'none') return null;

  const g = id => ($(prefix + '-auth-' + id)?.value || '').trim();

  switch (type) {
    case 'cookie':
      return { type: 'cookie', value: g('cookie') };
    case 'bearer':
      return { type: 'bearer', value: g('token') };
    case 'basic':
      return { type: 'basic', username: g('user'), password: g('pass') };
    case 'dvwa':
      return {
        type          : 'dvwa',
        base_url      : g('base'),
        username      : g('user'),
        password      : g('pass'),
        security_level: g('dvwa-sec') || 'low',
      };
    case 'form': {
      const userField = g('user-field') || 'username';
      const passField = g('pass-field') || 'password';
      return {
        type             : 'form',
        login_url        : g('login-url'),
        credentials      : { [userField]: g('user'), [passField]: g('pass') },
        success_indicator: g('success'),
      };
    }
    default: return null;
  }
}

function authLabel(prefix) {
  const typeEl = $(prefix + '-auth-type');
  if (!typeEl || typeEl.value === 'none') return null;
  const labels = { cookie: 'Cookie', bearer: 'Bearer', basic: 'HTTP Basic', dvwa: 'DVWA', form: 'Form Login' };
  return labels[typeEl.value] || typeEl.value;
}

// ══════════════════════════════════════════════════════════════
// DISCOVERY
// ══════════════════════════════════════════════════════════════
async function startCrawl() {
  const url      = $('crawl-url').value.trim();
  const maxDepth = parseInt($('crawl-depth').value, 10);
  const maxUrls  = parseInt($('crawl-maxurls').value, 10);
  const auth     = collectAuth('crawl');

  if (!url) { setStatus('Please enter a target URL.', 'error'); return; }
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    setStatus('URL must begin with http:// or https://', 'error'); return;
  }

  lockBtn('crawl-btn', true);
  $('crawl-tip').classList.add('hidden');
  showPanel('crawl-results', 'discovery');

  const al       = authLabel('crawl');
  const authNote = al ? ` [${al}]` : '';
  setStatus(`Mapping ${url}${authNote}…`, 'info', true);

  try {
    const res = await fetch(`${API}/api/scan/crawl`, {
      method : 'POST',
      headers: { 'Content-Type': 'application/json' },
      body   : JSON.stringify({ target_url: url, max_depth: maxDepth, max_urls: maxUrls, auth }),
    });
    if (!res.ok) { const e = await res.json().catch(() => ({})); throw new Error(e.error || `Server error ${res.status}`); }
    const data = await res.json();
    renderDiscovery(data);

    const authBadge = data.auth_type && data.auth_type !== 'none' && data.auth_type !== 'failed'
      ? ` · Auth: <strong>${escHtml(data.auth_type)}</strong>` : '';
    const failedAuth = data.auth_type === 'failed'
      ? ' · <span style="color:var(--red)">Auth failed — scan ran unauthenticated</span>' : '';
    setStatus(
      `${data.total_visited} page${data.total_visited !== 1 ? 's' : ''} mapped.${authBadge}${failedAuth}`,
      data.auth_type === 'failed' ? 'warn' : 'ok'
    );
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
    ? data.base_domain.substring(0, 20) + '…' : (data.base_domain || 'unknown');

  $('crawl-stats').innerHTML =
    makePill(data.total_visited || 0, 'Pages Found', data.total_visited > 0 ? 'green' : '') +
    makePill(data.total_failed  || 0, 'Unreachable', data.total_failed  > 0 ? 'red'   : '') +
    makePill(data.crawl_depth   || 0, 'Depth Used') +
    makePill(domainLabel,             'Domain');

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
// INJECTION
// ══════════════════════════════════════════════════════════════
async function startPayload() {
  const url    = $('payload-url').value.trim();
  const type   = $('payload-type').value;
  const maxPay = parseInt($('payload-max').value, 10);
  const auth   = collectAuth('payload');

  if (!url) { setStatus('Please enter a target URL.', 'error'); return; }
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    setStatus('URL must begin with http:// or https://', 'error'); return;
  }

  lockBtn('payload-btn', true);
  showPanel('payload-results', 'injection findings');
  const al = authLabel('payload');
  setStatus(`Running ${type === 'both' ? 'full' : type.toUpperCase()} assessment${al ? ` [${al}]` : ''}…`, 'info', true);

  try {
    const res = await fetch(`${API}/api/scan/payload`, {
      method : 'POST',
      headers: { 'Content-Type': 'application/json' },
      body   : JSON.stringify({ target_url: url, payload_type: type, max_payloads: maxPay, auth }),
    });
    if (!res.ok) { const e = await res.json().catch(() => ({})); throw new Error(e.error || `Server error ${res.status}`); }
    const data = await res.json();
    renderInjection(data);
    setStatus(
      data.total_vulnerable > 0
        ? `${data.total_vulnerable} potential finding${data.total_vulnerable > 1 ? 's' : ''} detected.`
        : 'Assessment complete — no obvious vulnerabilities detected.',
      data.total_vulnerable > 0 ? 'warn' : 'ok'
    );
  } catch (err) {
    setStatus(`Assessment failed: ${err.message}`, 'error');
  } finally {
    lockBtn('payload-btn', false);
  }
}

function renderInjection(data) {
  $('payload-stats').innerHTML =
    makePill(data.total_tested     || 0, 'Tests Run') +
    makePill(data.total_vulnerable || 0, 'Flagged',  (data.total_vulnerable || 0) > 0 ? 'red'   : 'green') +
    makePill(data.total_clean      || 0, 'Clean',    (data.total_clean      || 0) > 0 ? 'green' : '') +
    makePill(data.total_errors     || 0, 'Errors',   (data.total_errors     || 0) > 0 ? 'yellow': '');

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
// FULL SCAN
// ══════════════════════════════════════════════════════════════
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
  const auth       = collectAuth('full');

  if (!url) { setStatus('Please enter a target URL.', 'error'); return; }
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    setStatus('URL must begin with http:// or https://', 'error'); return;
  }

  lockBtn('full-btn', true);
  hideReportBar();
  showPanel('full-results', 'full assessment');

  const al       = authLabel('full');
  const authNote = al ? ` [${al}]` : '';
  setStatus(`${SCAN_PHASES[0]}${authNote}`, 'info', true);

  let phaseIdx   = 1;
  const phaseTimer = setInterval(() => {
    if (phaseIdx < SCAN_PHASES.length)
      setStatus(`${SCAN_PHASES[phaseIdx++]}${authNote}`, 'info', true);
  }, 5000);

  try {
    const res = await fetch(`${API}/api/scan/full`, {
      method : 'POST',
      headers: { 'Content-Type': 'application/json' },
      body   : JSON.stringify({
        target_url: url, max_depth: maxDepth, max_urls: maxUrls,
        max_targets: maxTargets, payload_type: payType, max_payloads: 20, auth,
      }),
    });
    clearInterval(phaseTimer);

    if (!res.ok) { const e = await res.json().catch(() => ({})); throw new Error(e.error || `Server error ${res.status}`); }

    const data = await res.json();
    _currentScanId = data.scan_id;
    renderFullResults(data);

    const risk      = data.analysis?.overall_risk || 'Unknown';
    const total     = data.analysis?.total_findings || 0;
    const authBadge = data.auth_type && data.auth_type !== 'none' && data.auth_type !== 'failed'
      ? ` · Auth: ${data.auth_type}` : '';
    const authFail  = data.auth_type === 'failed'
      ? ' · Auth failed — scan ran unauthenticated' : '';

    setStatus(
      total > 0
        ? `Scan complete — ${total} finding${total > 1 ? 's' : ''}. Risk: ${risk}${authBadge}${authFail}`
        : `Scan complete — no vulnerabilities detected.${authBadge}${authFail}`,
      total > 0 ? 'warn' : 'ok',
    );
    if (data.report_available?.html || data.report_available?.pdf)
      showReportBar(data.scan_id, data.report_available.html, data.report_available.pdf);

  } catch (err) {
    clearInterval(phaseTimer);
    setStatus(`Full scan failed: ${err.message}`, 'error');
  } finally {
    lockBtn('full-btn', false);
  }
}

function renderFullResults(data) {
  const analysis = data.analysis      || {};
  const crawl    = data.crawl_summary || {};

  const risk     = analysis.overall_risk    || 'Unknown';
  const total    = analysis.total_findings  || 0;
  const critical = analysis.critical_count  || 0;
  const high     = analysis.high_count      || 0;
  const findings = analysis.findings        || [];
  const recs     = analysis.recommendations || [];

  const riskColors = { Critical:'#ff4757', High:'#ff6b35', Medium:'#ffd32a', Low:'#00d4ff', Clean:'#00ff88' };
  const riskColor  = riskColors[risk] || '#6b7a99';

  $('full-stats').innerHTML =
    makePill(total,                    'Findings', total    > 0 ? 'red'   : 'green') +
    makePill(critical,                 'Critical', critical > 0 ? 'red'   : '') +
    makePill(high,                     'High',     high     > 0 ? 'red'   : '') +
    makePill(crawl.total_visited || 0, 'Pages', 'green') +
    makePill(data.duration || 'N/A',   'Duration');

  const authInfo = data.auth_type && data.auth_type !== 'none' && data.auth_type !== 'failed'
    ? `<span style="background:#8b5cf622;color:#a78bfa;border:1px solid #8b5cf644;
        padding:5px 14px;border-radius:100px;font-size:.78rem;font-weight:700;
        display:inline-block;margin-left:8px">
        <i class="bi bi-key-fill me-1"></i>${escHtml(data.auth_type)}</span>` : '';

  $('full-risk-badge').innerHTML =
    `<span style="background:${riskColor}22;color:${riskColor};border:1px solid ${riskColor}44;
      padding:5px 18px;border-radius:100px;font-size:.82rem;font-weight:700;display:inline-block">
      Overall Risk: ${escHtml(risk)}</span>${authInfo}`;

  const findingsSection = $('full-findings-section');
  const cleanMsg        = $('full-clean-msg');

  if (findings.length === 0) {
    findingsSection.classList.add('hidden');
    cleanMsg.classList.remove('hidden');
  } else {
    cleanMsg.classList.add('hidden');
    findingsSection.classList.remove('hidden');
    $('full-findings-count').textContent = `${findings.length} finding${findings.length > 1 ? 's' : ''}`;
    $('full-findings-tbody').innerHTML = findings.map(f => {
      const sc         = riskColors[f.severity_label] || '#6b7a99';
      const techniques = (f.techniques || []).map(t => `<span class="technique-tag">${escHtml(t)}</span>`).join('');
      const ev         = f.findings_detail?.[0]?.evidence || '';
      const evidenceHtml = ev
        ? `<div style="margin-top:6px;font-size:.7rem;color:var(--yellow);font-family:var(--font-mono);word-break:break-all">
            Evidence: ${escHtml(String(ev).slice(0, 120))}</div>` : '';
      const remediationItems = (f.remediation_steps || [])
        .map(s => `<li style="font-size:.78rem;color:var(--text-dim);margin-bottom:4px">${escHtml(s)}</li>`).join('');

      return `<div class="finding-row">
        <div class="fr-header">
          <span class="fr-id">#${escHtml(f.id)}</span>
          <span class="fr-title">${escHtml(f.vulnerability)}</span>
          <span class="fr-sev" style="background:${sc}22;color:${sc};border:1px solid ${sc}44">${escHtml(f.severity_label)}</span>
        </div>
        <div class="fr-body">
          <div class="fr-row"><span class="fr-label">URL</span>
            <span class="fr-val"><a href="${escHtml(f.url)}" target="_blank" rel="noopener noreferrer">${escHtml(f.url)}</a></span>
          </div>
          <div class="fr-row"><span class="fr-label">Parameter</span>
            <span class="fr-val"><code style="color:var(--cyan-dim)">${escHtml(f.param)}</code></span>
          </div>
          <div class="fr-row"><span class="fr-label">Techniques</span>
            <span class="fr-val">${techniques}</span>
          </div>
          <div class="fr-row"><span class="fr-label">OWASP / CWE</span>
            <span class="fr-val">
              <a href="${escHtml(f.owasp_url || '')}" target="_blank" rel="noopener noreferrer">${escHtml(f.owasp_ref || 'N/A')}</a>
              ${f.cwe ? ` &mdash; ${escHtml(f.cwe)}` : ''}
            </span>
          </div>
          ${evidenceHtml}
          ${remediationItems ? `<details style="margin-top:10px">
            <summary style="font-size:.75rem;color:var(--cyan);cursor:pointer">View Remediation Steps</summary>
            <ol style="margin-top:8px;padding-left:18px">${remediationItems}</ol>
          </details>` : ''}
        </div>
      </div>`;
    }).join('');
  }

  const recsSection = $('full-recs-section');
  if (recs.length > 0) {
    recsSection.classList.remove('hidden');
    $('full-recs-list').innerHTML = recs.map(r =>
      `<li style="padding:8px 14px;border-left:3px solid var(--cyan);background:var(--bg);
        border-radius:0 8px 8px 0;font-size:.82rem;color:var(--text-dim);margin-bottom:6px">${escHtml(r)}</li>`
    ).join('');
  } else { recsSection.classList.add('hidden'); }
}

// ── Injected styles ────────────────────────────────────────────
const _styles = document.createElement('style');
_styles.textContent = `
  .technique-tag {
    display:inline-block;background:#00d4ff15;border:1px solid #00d4ff30;
    border-radius:20px;padding:2px 8px;font-size:.68rem;color:#00d4ff;margin-right:4px;
  }
  .finding-row { background:var(--bg);border:1px solid var(--border);border-radius:9px;margin-bottom:10px;overflow:hidden; }
  .fr-header { display:flex;align-items:center;gap:10px;padding:10px 14px;background:var(--surface2);border-bottom:1px solid var(--border); }
  .fr-id    { font-size:.72rem;font-weight:700;color:var(--text-muted); }
  .fr-title { font-size:.88rem;font-weight:700;color:#fff;flex:1; }
  .fr-sev   { padding:2px 10px;border-radius:20px;font-size:.7rem;font-weight:700; }
  .fr-body  { padding:12px 14px; }
  .fr-row   { display:flex;gap:10px;margin-bottom:6px;font-size:.8rem; }
  .fr-label { color:var(--text-muted);font-size:.68rem;text-transform:uppercase;letter-spacing:.06em;min-width:80px;margin-top:2px; }
  .fr-val   { color:var(--text-dim);word-break:break-all; }

  /* Auth panel */
  .btn-auth-toggle {
    width:100%;background:var(--bg);border:1px solid var(--border);
    border-radius:8px;color:var(--text-dim);font-family:var(--font);
    font-size:.8rem;font-weight:600;padding:8px 12px;
    display:flex;align-items:center;justify-content:space-between;
    cursor:pointer;transition:all 0.25s ease;
  }
  .btn-auth-toggle:hover { border-color:var(--cyan-dim);color:#fff; }
  .btn-auth-toggle.active { border-color:var(--cyan-dim);color:var(--cyan);background:var(--cyan-glow); }
  .auth-panel { background:var(--bg);border:1px solid var(--border);border-radius:9px;padding:14px;margin-top:4px; }
  .auth-fields-inner { margin-top:8px; }
  .auth-hint { font-size:.7rem;color:var(--text-muted);margin:4px 0 0;line-height:1.5; }
  .auth-hint code { color:var(--cyan-dim);font-size:.68rem; }

  /* DVWA hint inside auth panel */
  .dvwa-hint-box {
    margin-bottom:10px;padding:8px 10px;
    background:#8b5cf610;border:1px solid #8b5cf630;
    border-radius:7px;font-size:.72rem;color:#a78bfa;line-height:1.65;
  }
  .dvwa-hint-box code { color:#c4b5fd;font-size:.68rem; }

  /* Test Auth button */
  .btn-auth-test {
    width:100%;margin-top:10px;background:transparent;
    border:1px solid var(--border);border-radius:8px;
    color:var(--text-dim);font-family:var(--font);font-size:.8rem;font-weight:600;
    padding:7px 12px;cursor:pointer;transition:all 0.25s ease;
  }
  .btn-auth-test:hover:not(:disabled) { border-color:var(--cyan-dim);color:var(--cyan); }
  .btn-auth-test:disabled { opacity:.5;cursor:not-allowed; }
`;
document.head.appendChild(_styles);

// ── Enter-key support ──────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  $('crawl-url')  ?.addEventListener('keydown', e => { if (e.key === 'Enter') startCrawl(); });
  $('payload-url')?.addEventListener('keydown', e => { if (e.key === 'Enter') startPayload(); });
  $('full-url')   ?.addEventListener('keydown', e => { if (e.key === 'Enter') startFullScan(); });
});