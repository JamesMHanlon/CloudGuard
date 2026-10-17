const API = '';
let allResources = [];
let summary = {};

// ─── INIT ──────────────────────────────────────────────────────────────────
async function init() {
  await Promise.all([loadSummary(), loadResources()]);
  renderDashboard();
  loadMLInsights();
}

async function loadSummary() {
  const r = await fetch(`${API}/api/summary`);
  summary = await r.json();
}

async function loadResources() {
  const r = await fetch(`${API}/api/resources`);
  allResources = await r.json();
  populateServiceFilter();
}

async function loadMLInsights() {
  const r = await fetch(`${API}/api/ml/importances`);
  const data = await r.json();
  renderImportanceChart(data);
  renderRiskDistChart();
  renderScatterChart();
}

// ─── DASHBOARD ─────────────────────────────────────────────────────────────
function renderDashboard() {
  // KPIs
  q('#kpi-total   .kpi-value').textContent = summary.total_resources;
  q('#kpi-compliant .kpi-value').textContent = summary.compliant;
  q('#kpi-noncompliant .kpi-value').textContent = summary.non_compliant;
  q('#kpi-critical .kpi-value').textContent = summary.critical_violations;
  q('#kpi-rate .kpi-value').textContent = summary.compliance_rate + '%';
  q('#kpi-risk .kpi-value').textContent = Math.round(summary.avg_risk_score * 100) + '%';

  // Header badge
  const badge = q('#compliance-badge');
  const rate = summary.compliance_rate;
  badge.textContent = rate >= 80 ? `✓ ${rate}% compliant` : rate >= 50 ? `⚠ ${rate}% compliant` : `✕ ${rate}% compliant`;
  badge.className = 'header-badge ' + (rate >= 80 ? 'good' : rate >= 50 ? 'warn' : 'bad');

  // Cloud chart
  const cloudItems = Object.entries(summary.by_cloud).map(([k, v]) => ({
    label: k,
    value: v.non_compliant,
    max: v.total,
    color: k === 'AWS' ? '#f97316' : k === 'Azure' ? '#0ea5e9' : '#4ade80',
    suffix: `of ${v.total}`,
  }));
  renderBarChart('cloud-chart', cloudItems);

  // Framework chart
  const fw = summary.violations_by_framework;
  const maxFw = Math.max(...Object.values(fw), 1);
  const fwItems = Object.entries(fw).map(([k, v]) => ({
    label: k,
    value: v,
    max: maxFw,
    color: k === 'CIS' ? '#a855f7' : k === 'NIST' ? '#3b82f6' : '#10b981',
    suffix: 'violations',
  }));
  renderBarChart('framework-chart', fwItems);

  // Risk table — top 8
  renderTable('dash-table-body', allResources.slice(0, 8));
}

function renderBarChart(id, items) {
  const el = q(`#${id}`);
  el.innerHTML = items.map(item => {
    const pct = item.max > 0 ? Math.min((item.value / item.max) * 100, 100) : 0;
    return `
      <div class="bar-row">
        <div class="bar-label" title="${item.label}">${item.label}</div>
        <div class="bar-track">
          <div class="bar-fill" style="width:${pct}%;background:${item.color}"></div>
        </div>
        <div class="bar-count">${item.value} <span style="color:var(--text3);font-weight:400">${item.suffix || ''}</span></div>
      </div>`;
  }).join('');
}

// ─── RESOURCES TABLE ────────────────────────────────────────────────────────
function populateServiceFilter() {
  const services = [...new Set(allResources.map(r => r.service))].sort();
  const sel = q('#filter-service');
  sel.innerHTML = '<option value="">All Services</option>' +
    services.map(s => `<option>${s}</option>`).join('');
}

function applyFilters() {
  const cloud   = q('#filter-cloud').value;
  const status  = q('#filter-status').value;
  const service = q('#filter-service').value;
  let filtered  = allResources;
  if (cloud)          filtered = filtered.filter(r => r.cloud === cloud);
  if (status !== '')  filtered = filtered.filter(r => String(r.compliant) === status);
  if (service)        filtered = filtered.filter(r => r.service === service);
  renderTable('resources-table-body', filtered);
}

function renderTable(tbodyId, resources) {
  const tbody = q(`#${tbodyId}`);
  if (!resources.length) {
    tbody.innerHTML = `<tr><td colspan="8"><div class="empty-state">No resources match the current filters</div></td></tr>`;
    return;
  }
  tbody.innerHTML = resources.map(r => {
    const risk = r.risk_score;
    const rColor = riskColor(risk);
    const cloudCls = `cloud-tag cloud-${r.cloud.toLowerCase()}`;
    return `
      <tr>
        <td>
          <div class="resource-name">${r.resource_name}</div>
          <div class="resource-id">${r.resource_id}</div>
        </td>
        <td><span class="${cloudCls}">${r.cloud}</span></td>
        <td>${r.service}</td>
        <td style="color:var(--text3)">${r.region}</td>
        <td>${r.violation_count > 0
          ? `<span class="badge b-red">${r.violation_count}</span>`
          : `<span class="badge b-green">0</span>`}
        </td>
        <td>
          <div class="risk-inline">
            <div class="risk-track">
              <div class="risk-fill" style="width:${risk*100}%;background:${rColor}"></div>
            </div>
            <span class="risk-pct" style="color:${rColor}">${Math.round(risk*100)}%</span>
          </div>
        </td>
        <td>${r.compliant
          ? `<span class="badge b-green">Compliant</span>`
          : `<span class="badge b-red">Non-Compliant</span>`}
        </td>
        <td><button class="btn-detail" onclick="openResource('${r.resource_id}')">Details →</button></td>
      </tr>`;
  }).join('');
}

// ─── ML INSIGHTS ────────────────────────────────────────────────────────────
function renderImportanceChart(data) {
  const el = q('#importance-chart');
  const max = data[0]?.importance || 1;
  el.innerHTML = data.map(item => {
    const pct = (item.importance / max) * 100;
    return `
      <div class="bar-row">
        <div class="bar-label" title="${item.feature}">${item.feature.replace(/_/g,' ')}</div>
        <div class="bar-track">
          <div class="bar-fill" style="width:${pct}%;background:linear-gradient(90deg,#7c3aed,#3b82f6)"></div>
        </div>
        <div class="bar-count">${(item.importance*100).toFixed(1)}%</div>
      </div>`;
  }).join('');
}

function renderRiskDistChart() {
  const buckets = [
    { label: '0–25%  Low',      min:0,    max:0.25, color:'#10b981' },
    { label: '25–50%  Moderate', min:0.25, max:0.5,  color:'#eab308' },
    { label: '50–75%  High',     min:0.5,  max:0.75, color:'#f97316' },
    { label: '75–100%  Critical',min:0.75, max:1.01, color:'#f43f5e' },
  ];
  const counts = buckets.map(b => allResources.filter(r => r.risk_score >= b.min && r.risk_score < b.max).length);
  const maxC = Math.max(...counts, 1);
  const el = q('#risk-dist-chart');
  el.innerHTML = buckets.map((b, i) => `
    <div class="bar-row">
      <div class="bar-label">${b.label}</div>
      <div class="bar-track">
        <div class="bar-fill" style="width:${(counts[i]/maxC)*100}%;background:${b.color}"></div>
      </div>
      <div class="bar-count">${counts[i]} <span style="color:var(--text3);font-weight:400">resources</span></div>
    </div>`).join('');
}

function renderScatterChart() {
  const el = q('#scatter-chart');
  const padL = 20, padR = 20, padT = 10, padB = 28;
  const W = el.offsetWidth || 600;
  const H = 260;

  const maxV = Math.max(...allResources.map(r => r.violation_count), 1);

  const dots = allResources.map(r => {
    const x = padL + (r.risk_score) * (W - padL - padR);
    const y = padT + (1 - r.violation_count / maxV) * (H - padT - padB);
    const color = riskColor(r.risk_score);
    const cloud = r.cloud;
    return `
      <div class="scatter-dot"
        style="left:${x}px;top:${y}px;background:${color}"
        data-tip="${r.resource_name} | Risk: ${Math.round(r.risk_score*100)}% | Violations: ${r.violation_count} | ${cloud}"
        onmouseenter="showTip(this,event)"
        onmouseleave="hideTip()"
        onclick="openResource('${r.resource_id}')">
      </div>`;
  }).join('');

  el.style.position = 'relative';
  el.style.height = H + 'px';
  el.innerHTML = dots + `
    <div class="scatter-tooltip" id="scatter-tip"></div>
    <div class="scatter-axis-x">ML Risk Score →</div>
    <div class="scatter-axis-y" style="left:-8px;top:50%;transform:translateY(-50%) rotate(-90deg);position:absolute">↑ Violations</div>`;
}

function showTip(el, event) {
  const tip = q('#scatter-tip');
  tip.textContent = el.dataset.tip;
  tip.style.left = (event.offsetX + 14) + 'px';
  tip.style.top  = (event.offsetY - 10) + 'px';
  tip.style.opacity = '1';
}

function hideTip() {
  const tip = q('#scatter-tip');
  if (tip) tip.style.opacity = '0';
}

// ─── RESOURCE MODAL ─────────────────────────────────────────────────────────
async function openResource(id) {
  q('#modal-overlay').classList.remove('hidden');
  const content = q('#modal-content');
  content.innerHTML = `<div style="text-align:center;padding:60px;color:var(--text3)">
    <div class="spinner"></div> Loading resource...
  </div>`;

  const res = await fetch(`${API}/api/resources/${id}`);
  const d = await res.json();

  const rColor = riskColor(d.risk_score);
  const cloudCls = `cloud-tag cloud-${d.cloud.toLowerCase()}`;

  const sevBadge = s => {
    const cls = {CRITICAL:'b-red',HIGH:'b-orange',MEDIUM:'b-yellow',LOW:'b-gray'}[s]||'b-gray';
    return `<span class="badge ${cls}">${s}</span>`;
  };
  const fwBadge = f => {
    const cls = {CIS:'b-purple',NIST:'b-blue',ISO27001:'b-green'}[f]||'b-gray';
    return `<span class="badge ${cls}">${f}</span>`;
  };

  const violationsHtml = d.violations.map(v => `
    <div class="v-card">
      <div class="v-top">
        ${sevBadge(v.severity)} ${fwBadge(v.framework)}
        <span class="v-title">${v.title}</span>
        <span style="font-size:10px;color:var(--text3);font-family:monospace">${v.rule_id}</span>
      </div>
      <div class="v-detail">${v.detail}</div>
      <div class="v-meta">
        <span>Field <code>${v.field}</code></span>
        <span>Actual <code>${v.actual_value}</code></span>
        <span>Expected <code>${v.expected_value}</code></span>
      </div>
      <div class="ai-box" id="exp-${v.rule_id.replace(/\W/g,'_')}">
        <span class="spinner"></span> Generating AI explanation...
      </div>
    </div>`).join('');

  const cfgHtml = Object.entries(d.config||{}).map(([k,v]) => {
    const safe = v === true || ['required','aes256','aws:kms','cmek','tls1_2'].includes(String(v).toLowerCase());
    const risky = v === false || v === null || v === 'optional' || v === 'public-read';
    const cls = safe ? 'cfg-good' : risky ? 'cfg-bad' : 'cfg-neutral';
    return `<div class="cfg-item"><div class="cfg-key">${k}</div><div class="cfg-val ${cls}">${v === null ? 'null' : String(v)}</div></div>`;
  }).join('');

  content.innerHTML = `
    <div class="modal-title">${d.resource_name}</div>
    <div class="modal-meta">
      <span class="badge b-gray"><span class="${cloudCls}">${d.cloud}</span></span>
      <span class="badge b-gray">${d.service}</span>
      <span class="badge b-gray">${d.region}</span>
      ${d.compliant ? `<span class="badge b-green">Compliant</span>` : `<span class="badge b-red">Non-Compliant</span>`}
      <span class="badge" style="background:${riskColor(d.risk_score,'lo')};color:${rColor};border:1px solid ${rColor}40">
        ML Risk: ${Math.round(d.risk_score*100)}%
      </span>
    </div>

    <div class="modal-summary loading" id="modal-summary">
      <span class="spinner"></span> Generating AI compliance summary...
    </div>

    ${d.violations.length ? `
      <div class="violations-title">${d.violations.length} Violation${d.violations.length!==1?'s':''} Found</div>
      ${violationsHtml}
    ` : `<span class="badge b-green" style="padding:8px 16px;font-size:13px">✓ No violations — fully compliant</span>`}

    ${cfgHtml ? `
      <div class="config-grid-section">
        <h4>Configuration</h4>
        <div class="cfg-grid">${cfgHtml}</div>
      </div>` : ''}
  `;

  if (d.violations.length) {
    fetchExplanations(id, d.violations);
  } else {
    const s = q('#modal-summary');
    s.textContent = 'This resource is fully compliant with all evaluated controls.';
    s.classList.remove('loading');
  }
}

async function fetchExplanations(id, violations) {
  try {
    const res = await fetch(`${API}/api/resources/${id}/explain`, { method: 'POST' });
    const summaryEl = q('#modal-summary');

    if (!res.ok) {
      if (summaryEl) { summaryEl.textContent = 'AI explanations unavailable — add ANTHROPIC_API_KEY to .env to enable.'; summaryEl.classList.remove('loading'); }
      violations.forEach(v => {
        const el = q(`#exp-${v.rule_id.replace(/\W/g,'_')}`);
        if (el) el.innerHTML = '<em style="color:var(--text3)">AI explanation requires ANTHROPIC_API_KEY</em>';
      });
      return;
    }

    const data = await res.json();
    if (summaryEl) { summaryEl.textContent = data.summary; summaryEl.classList.remove('loading'); }

    data.violation_explanations.forEach(exp => {
      const el = q(`#exp-${exp.rule_id.replace(/\W/g,'_')}`);
      if (el) el.textContent = exp.explanation;
    });

    violations.slice(5).forEach(v => {
      const el = q(`#exp-${v.rule_id.replace(/\W/g,'_')}`);
      if (el) el.innerHTML = '<em style="color:var(--text3)">See summary above for remediation guidance</em>';
    });
  } catch(e) { console.error(e); }
}

function closeModal() {
  q('#modal-overlay').classList.add('hidden');
  q('#modal-content').innerHTML = '';
}

// ─── CUSTOM SCAN ─────────────────────────────────────────────────────────────
const TEMPLATES = {
  's3-bad':  { cloud:'AWS', service:'S3', name:'prod-bucket', config:{public_access_block:false,versioning:false,encryption:null,logging:false,bucket_acl:'public-read'} },
  's3-good': { cloud:'AWS', service:'S3', name:'secure-bucket', config:{public_access_block:true,versioning:true,encryption:'aws:kms',logging:true,bucket_acl:'private'} },
  'ec2-bad': { cloud:'AWS', service:'EC2', name:'app-server', config:{ssh_unrestricted:true,imdsv2:'optional',ebs_encrypted:false,public_ip:true} },
  'iam-bad': { cloud:'AWS', service:'IAM', name:'root-account', config:{root_mfa:false,root_access_keys:true,password_policy_strong:false,min_password_length:8,mfa_enforced:false} },
};

function loadTemplate(key) {
  const t = TEMPLATES[key]; if(!t) return;
  q('#scan-cloud').value   = t.cloud;
  q('#scan-service').value = t.service;
  q('#scan-name').value    = t.name;
  q('#scan-config').value  = JSON.stringify(t.config, null, 2);
}

async function runCustomScan() {
  const btn = q('.btn-scan');
  const btnText = q('#scan-btn-text');
  btn.disabled = true;
  btnText.innerHTML = '<span class="spinner"></span> Scanning...';

  const resultPanel = q('#scan-result');
  const resultBody  = q('#scan-result-body');
  resultPanel.classList.remove('hidden');
  resultBody.innerHTML = '<div style="padding:20px 22px;color:var(--text3)"><span class="spinner"></span> Running compliance checks...</div>';

  let config;
  try { config = JSON.parse(q('#scan-config').value); }
  catch {
    resultBody.innerHTML = `<div style="padding:20px 22px;color:var(--red)">✕ Invalid JSON — please check your configuration</div>`;
    btn.disabled = false; btnText.innerHTML = '▶ &nbsp;Run Scan'; return;
  }

  try {
    const res = await fetch(`${API}/api/scan/custom`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ cloud: q('#scan-cloud').value, service: q('#scan-service').value, name: q('#scan-name').value, config }),
    });
    const d = await res.json();

    const rColor = riskColor(d.risk_score);
    const sevBadge = s => {
      const cls = {CRITICAL:'b-red',HIGH:'b-orange',MEDIUM:'b-yellow',LOW:'b-gray'}[s]||'b-gray';
      return `<span class="badge ${cls}">${s}</span>`;
    };

    const violHtml = (d.violations||[]).map(v => `
      <div class="v-card">
        <div class="v-top">${sevBadge(v.severity)}<span class="v-title">${v.title}</span></div>
        <div class="v-detail">${v.detail}</div>
        <div class="v-meta">
          <span>Field <code>${v.field}</code></span>
          <span>Actual <code>${v.actual_value}</code></span>
          <span>Expected <code>${v.expected_value}</code></span>
        </div>
      </div>`).join('');

    resultBody.innerHTML = `
      <div class="scan-verdict">
        ${d.compliant
          ? `<span class="badge b-green" style="font-size:13px;padding:6px 16px">✓ Compliant</span>`
          : `<span class="badge b-red" style="font-size:13px;padding:6px 16px">✕ ${d.violation_count} Violation${d.violation_count!==1?'s':''}</span>`}
        <div>
          <div class="verdict-label" style="color:${rColor}">ML Risk: ${Math.round(d.risk_score*100)}%</div>
          <div class="verdict-sub">${d.resource_name} · ${d.cloud} / ${d.service}</div>
        </div>
      </div>
      ${d.summary ? `<div style="padding:16px 22px 0"><div class="ai-box">${d.summary}</div></div>` : ''}
      <div style="padding:16px 0 6px">${violHtml || `<div style="padding:0 22px 16px;color:var(--green)">No violations detected — this configuration is compliant.</div>`}</div>`;
  } catch(e) {
    resultBody.innerHTML = `<div style="padding:20px 22px;color:var(--red)">Error: ${e.message}</div>`;
  }

  btn.disabled = false;
  btnText.innerHTML = '▶ &nbsp;Run Scan';
}

// ─── SCAN TABS ───────────────────────────────────────────────────────────────
function switchScanTab(tab) {
  q('#scan-bulk-tab').classList.toggle('hidden',  tab !== 'bulk');
  q('#scan-single-tab').classList.toggle('hidden', tab !== 'single');
  q('#tab-bulk').classList.toggle('active',   tab === 'bulk');
  q('#tab-single').classList.toggle('active', tab === 'single');
}

// ─── BULK SCAN ────────────────────────────────────────────────────────────────
let _bulkResources = [];

function parseBulkJSON(text) {
  const parsed = JSON.parse(text);
  // Accept: { resources: [...] } or bare array
  const list = Array.isArray(parsed) ? parsed : (parsed.resources || []);
  if (!list.length) throw new Error('No resources found in JSON.');
  return list;
}

function renderPreview(list) {
  _bulkResources = list;
  const body = q('#preview-table-body');
  body.innerHTML = list.map((r, i) => `
    <tr>
      <td style="color:var(--text3)">${i+1}</td>
      <td><strong>${r.name || r.resource_id || `Resource-${i+1}`}</strong></td>
      <td><span class="cloud-tag cloud-${(r.cloud||'?').toLowerCase()}">${r.cloud || '?'}</span></td>
      <td>${r.service || '<em style="color:var(--text3)">auto</em>'}</td>
      <td style="color:var(--text3)">${r.region || '—'}</td>
    </tr>`).join('');

  q('#preview-title').textContent = `${list.length} Resource${list.length !== 1 ? 's' : ''} Detected`;
  q('#preview-sub').textContent = `${[...new Set(list.map(r => r.cloud).filter(Boolean))].join(', ') || 'cloud auto-detected'}`;
  q('#bulk-preview').classList.remove('hidden');
  q('#bulk-scan-btn').disabled = false;
}

function onFileChosen(event) {
  const file = event.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = e => {
    try {
      const list = parseBulkJSON(e.target.result);
      q('#drop-zone').classList.add('has-file');
      q('#drop-zone .drop-title').textContent = `✓ ${file.name}`;
      q('#drop-zone .drop-sub').textContent   = `${list.length} resources detected · click to change`;
      q('#bulk-paste').value = '';
      renderPreview(list);
    } catch(err) {
      alert('Could not parse file: ' + err.message);
    }
  };
  reader.readAsText(file);
}

function onDragOver(e) {
  e.preventDefault();
  q('#drop-zone').classList.add('dragover');
}

function onDragLeave() {
  q('#drop-zone').classList.remove('dragover');
}

function onDrop(e) {
  e.preventDefault();
  q('#drop-zone').classList.remove('dragover');
  const file = e.dataTransfer.files[0];
  if (file) {
    // Simulate file input
    const dt = new DataTransfer();
    dt.items.add(file);
    q('#file-input').files = dt.files;
    onFileChosen({ target: { files: [file] } });
  }
}

function onBulkPaste() {
  const text = q('#bulk-paste').value.trim();
  if (!text) return;
  try {
    const list = parseBulkJSON(text);
    // Reset drop zone if user pasted instead
    q('#drop-zone').classList.remove('has-file');
    q('#drop-zone .drop-title').textContent = 'Drop your JSON file here';
    q('#drop-zone .drop-sub').textContent   = 'or click to browse · .json files only';
    renderPreview(list);
  } catch(_) {
    // Don't show errors while still typing
    if (text.length > 30) {
      q('#bulk-preview').classList.add('hidden');
      q('#bulk-scan-btn').disabled = true;
    }
  }
}

async function runBulkScan() {
  const btn     = q('#bulk-scan-btn');
  const btnText = q('#bulk-btn-text');
  btn.disabled  = true;
  btnText.innerHTML = `<span class="spinner"></span> Scanning ${_bulkResources.length} resources...`;

  try {
    const res = await fetch(`${API}/api/scan/bulk`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ resources: _bulkResources }),
    });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || 'Scan failed');
    }

    const data = await res.json();
    renderBulkResults(data);
  } catch(e) {
    alert('Bulk scan error: ' + e.message);
  }

  btn.disabled = false;
  btnText.innerHTML = '▶ &nbsp;Run Bulk Scan';
}

function renderBulkResults(data) {
  const s = data.summary;
  const rateClass = s.compliance_rate >= 80 ? 'var(--green)' : s.compliance_rate >= 50 ? 'var(--yellow)' : 'var(--red)';

  // Summary KPIs
  q('#bulk-kpis').innerHTML = `
    <div class="bulk-kpi"><div class="bulk-kpi-val">${s.total_resources}</div><div class="bulk-kpi-label">Total</div></div>
    <div class="bulk-kpi"><div class="bulk-kpi-val" style="color:var(--green)">${s.compliant}</div><div class="bulk-kpi-label">Compliant</div></div>
    <div class="bulk-kpi"><div class="bulk-kpi-val" style="color:var(--red)">${s.non_compliant}</div><div class="bulk-kpi-label">Non-Compliant</div></div>
    <div class="bulk-kpi"><div class="bulk-kpi-val" style="color:var(--orange)">${s.critical_violations}</div><div class="bulk-kpi-label">Critical</div></div>
    <div class="bulk-kpi"><div class="bulk-kpi-val" style="color:${rateClass}">${s.compliance_rate}%</div><div class="bulk-kpi-label">Rate</div></div>
  `;

  q('#bulk-summary-sub').textContent = `${s.non_compliant} of ${s.total_resources} resources non-compliant`;

  // Cloud + framework mini-charts
  const cloudItems = Object.entries(s.by_cloud).map(([k,v]) => ({
    label: k, value: v.non_compliant, max: v.total,
    color: k==='AWS' ? '#f97316' : k==='Azure' ? '#0ea5e9' : '#4ade80',
    suffix: `of ${v.total}`,
  }));
  renderMiniBar('bulk-cloud-chart', cloudItems, 'By Cloud');

  const fw = s.violations_by_framework;
  const maxFw = Math.max(...Object.values(fw), 1);
  const fwItems = Object.entries(fw).map(([k,v]) => ({
    label: k, value: v, max: maxFw,
    color: k==='CIS' ? '#a855f7' : k==='NIST' ? '#3b82f6' : '#10b981',
    suffix: 'violations',
  }));
  renderMiniBar('bulk-fw-chart', fwItems, 'By Framework');

  // Results table
  const sevBadge = s => {
    const cls = {CRITICAL:'b-red',HIGH:'b-orange',MEDIUM:'b-yellow',LOW:'b-gray'}[s]||'b-gray';
    return `<span class="badge ${cls}">${s}</span>`;
  };

  q('#bulk-table-body').innerHTML = data.resources.map(r => {
    const rc = riskColor(r.risk_score);
    return `
      <tr style="cursor:pointer" onclick="toggleBulkViolations('${r.resource_id}')">
        <td>
          <div class="resource-name">${r.resource_name}</div>
          <div class="resource-id">${r.resource_id}</div>
        </td>
        <td><span class="cloud-tag cloud-${r.cloud.toLowerCase()}">${r.cloud}</span></td>
        <td>${r.service}</td>
        <td>${r.violation_count > 0
          ? `<span class="badge b-red">${r.violation_count}</span>`
          : `<span class="badge b-green">0</span>`}</td>
        <td>
          <div class="risk-inline">
            <div class="risk-track"><div class="risk-fill" style="width:${r.risk_score*100}%;background:${rc}"></div></div>
            <span class="risk-pct" style="color:${rc}">${Math.round(r.risk_score*100)}%</span>
          </div>
        </td>
        <td>${r.compliant
          ? `<span class="badge b-green">Compliant</span>`
          : `<span class="badge b-red">Non-Compliant</span>`}</td>
        <td><span style="color:var(--text3);font-size:13px">${r.violations.length ? '▾' : '—'}</span></td>
      </tr>
      <tr id="bulk-viols-${r.resource_id}" class="hidden">
        <td colspan="7" style="padding:0 16px 16px;background:var(--bg3)">
          ${r.violations.length ? r.violations.map(v => `
            <div class="v-card" style="margin-top:10px">
              <div class="v-top">${sevBadge(v.severity)}<span class="badge ${({CIS:'b-purple',NIST:'b-blue',ISO27001:'b-green'})[v.framework]||'b-gray'}">${v.framework}</span><span class="v-title">${v.title}</span></div>
              <div class="v-detail">${v.detail}</div>
              <div class="v-meta">
                <span>Field <code>${v.field}</code></span>
                <span>Actual <code>${v.actual_value}</code></span>
                <span>Expected <code>${v.expected_value}</code></span>
              </div>
            </div>`).join('') : '<div style="padding:10px 0;color:var(--green)">✓ No violations</div>'}
        </td>
      </tr>`;
  }).join('');

  q('#bulk-results').classList.remove('hidden');

  // Scroll results into view
  q('#bulk-results').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function renderMiniBar(id, items, title) {
  const el = q(`#${id}`);
  el.innerHTML = `<div style="font-size:11px;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:.07em;margin-bottom:10px">${title}</div>` +
    items.map(item => {
      const pct = item.max > 0 ? Math.min((item.value / item.max) * 100, 100) : 0;
      return `<div class="bar-row">
        <div class="bar-label" style="width:80px" title="${item.label}">${item.label}</div>
        <div class="bar-track"><div class="bar-fill" style="width:${pct}%;background:${item.color}"></div></div>
        <div class="bar-count">${item.value} <span style="color:var(--text3);font-weight:400">${item.suffix||''}</span></div>
      </div>`;
    }).join('');
}

function toggleBulkViolations(id) {
  const row = q(`#bulk-viols-${id}`);
  if (row) row.classList.toggle('hidden');
}

// ─── VIEW SWITCHING ───────────────────────────────────────────────────────────
function showView(name) {
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(l => l.classList.remove('active'));
  q(`#view-${name}`).classList.add('active');
  document.querySelector(`[data-view="${name}"]`).classList.add('active');
  if (name === 'resources') renderTable('resources-table-body', allResources);
}

// ─── HELPERS ──────────────────────────────────────────────────────────────────
function q(sel) { return document.querySelector(sel); }

function riskColor(score, mode) {
  if (score >= 0.75) return mode==='lo' ? 'rgba(244,63,94,0.12)'  : '#f43f5e';
  if (score >= 0.5)  return mode==='lo' ? 'rgba(249,115,22,0.12)' : '#f97316';
  if (score >= 0.25) return mode==='lo' ? 'rgba(234,179,8,0.12)'  : '#eab308';
  return               mode==='lo' ? 'rgba(16,185,129,0.12)' : '#10b981';
}

document.addEventListener('DOMContentLoaded', init);
