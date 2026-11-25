'use strict';

const $ = (id) => document.getElementById(id);

const MAP_COLORS = ['#0b1220', '#22c55e', '#3b82f6', '#eab308', '#ef4444'];
const VERDICT_LABEL = {
  verified: 'VERIFIED — HASH MATCH',
  known: 'FIRMA ÍNTEGRA VERIFICADA',
  malware: 'MALWARE CONFIRMADO',
  clean: 'CLEAN — NO ANOMALIES FOUND',
  suspicious: 'SUSPICIOUS',
  danger: 'DANGEROUS',
  mismatch: 'HASH MISMATCH',
  modified: 'ARCHIVO MODIFICADO / POSIBLE MALWARE'
};
const BAD_VERDICTS = ['danger', 'mismatch', 'modified', 'malware'];
const HEX64 = /^[0-9a-f]{64}$/i;

let scan = { status: 'idle' };
let prefs = { mode: 'full', expected: '', url: '', tab: 'url' };
let armed = false;

/* ---------- utils ---------- */
function fmtBytes(n) {
  if (!n) return '0 B';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.min(u.length - 1, Math.floor(Math.log(n) / Math.log(1024)));
  return (n / Math.pow(1024, i)).toFixed(i ? 2 : 0) + ' ' + u[i];
}
function fmtSpeed(bps) { return (bps / 1048576).toFixed(1) + ' MB/s'; }
function send(type, data) {
  return chrome.runtime.sendMessage({ target: 'background', type, ...(data || {}) });
}
function savePrefs() { chrome.storage.local.set({ prefs }); }
function showError(msg) {
  const el = $('error');
  el.textContent = msg || '';
  el.classList.toggle('hidden', !msg);
}
const isDemo = (s) => typeof s.mode === 'string' && s.mode.startsWith('demo-');

/* ---------- init ---------- */
async function init() {
  const stored = await chrome.storage.local.get('prefs');
  if (stored.prefs) prefs = { ...prefs, ...stored.prefs };
  $('mode').value = prefs.mode;
  $('expected').value = prefs.expected;
  $('url').value = prefs.url;
  if (prefs.expected) $('customDet').open = true;
  setTab(prefs.tab || 'url', false);

  const st = await send('GET_STATE');
  if (st && st.ok) { armed = st.armed; scan = st.scan; }
  if (scan.url && scan.status !== 'idle' && !isDemo(scan)) $('url').value = scan.url;
  render();
  scanPage(false);

  document.querySelectorAll('.tab').forEach(t => t.addEventListener('click', () => setTab(t.dataset.tab, true)));
  $('mode').addEventListener('change', () => { prefs.mode = $('mode').value; savePrefs(); });
  $('url').addEventListener('input', () => { prefs.url = $('url').value.trim(); savePrefs(); });
  $('expected').addEventListener('input', () => {
    const v = $('expected').value.trim();
    prefs.expected = v;
    $('hashWarn').classList.toggle('hidden', !v || HEX64.test(v));
    savePrefs();
  });
  $('btnArm').addEventListener('click', async () => {
    armed = !armed;
    await send('ARM', { armed });
    renderArm();
  });
  $('btnStart').addEventListener('click', startScan);
  $('btnDemoClean').addEventListener('click', () => startDemo('clean'));
  $('btnDemoThreat').addEventListener('click', () => startDemo('threat'));
  $('btnDemoKnown').addEventListener('click', () => startDemo('known'));
  $('btnCancel').addEventListener('click', () => send('CANCEL'));
  $('btnCopy').addEventListener('click', copyReport);
  $('btnDownload').addEventListener('click', downloadAnyway);
  $('btnRescan').addEventListener('click', (e) => { e.preventDefault(); scanPage(false); });
  $('btnHighlight').addEventListener('click', (e) => { e.preventDefault(); scanPage(true); });
}

function setTab(tab, persist) {
  prefs.tab = tab;
  document.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t.dataset.tab === tab));
  $('paneUrl').classList.toggle('hidden', tab !== 'url');
  $('paneIntercept').classList.toggle('hidden', tab !== 'intercept');
  if (persist) savePrefs();
  if (typeof render === 'function' && scan) updateButtons();
}

/* ---------- actions ---------- */
async function startScan() {
  showError('');
  const url = $('url').value.trim();
  const expected = $('expected').value.trim().toLowerCase();
  if (!/^https?:\/\//i.test(url)) { showError('Introduce una URL directa http(s):// válida.'); return; }
  if (expected && !HEX64.test(expected)) {
    $('customDet').open = true;
    showError('El SHA-256 personalizado no es válido (64 hex).');
    return;
  }
  prefs.url = url; prefs.mode = $('mode').value; prefs.expected = expected; savePrefs();
  const res = await send('START_SCAN', { url, mode: prefs.mode, expected });
  if (res && !res.ok) showError(res.error);
}

async function startDemo(variant) {
  showError('');
  const res = await send('START_SCAN', { url: 'https://demo.local/demo_sample.exe', mode: 'demo-' + variant, expected: '' });
  if (res && !res.ok) showError(res.error);
}

async function downloadAnyway() {
  const url = scan.url || $('url').value.trim();
  const v = scan.result && scan.result.verdict;
  if (BAD_VERDICTS.includes(v) &&
      !confirm('El veredicto es PELIGROSO. ¿Descargar de todos modos bajo tu responsabilidad?')) return;
  const res = await send('DOWNLOAD', { url });
  if (res && !res.ok) showError(res.error);
}

/* ---------- page detection ---------- */
async function scanPage(highlight) {
  const box = $('detections');
  let tab;
  try { [tab] = await chrome.tabs.query({ active: true, currentWindow: true }); } catch (_) {}
  if (!tab || !tab.id || !/^https?:/i.test(tab.url || '')) {
    box.innerHTML = '<span class="none">Página no escaneable.</span>';
    return;
  }
  const ask = () => chrome.tabs.sendMessage(tab.id, { type: 'ENICRAY_SCAN_PAGE', highlight });
  let res;
  try { res = await ask(); }
  catch (_) {
    try {
      await chrome.scripting.executeScript({ target: { tabId: tab.id }, files: ['content.js'] });
      res = await ask();
    } catch (e) { box.innerHTML = '<span class="none">No se pudo escanear esta página.</span>'; return; }
  }
  if (!res || !res.ok) { box.innerHTML = '<span class="none">Sin respuesta del detector.</span>'; return; }
  renderDetections(res.info);
}

function chip(text, cls, onClick, title) {
  const b = document.createElement('button');
  b.className = 'chip ' + (cls || '');
  b.textContent = text;
  if (title) b.title = title;
  b.addEventListener('click', onClick);
  return b;
}
function group(box, title) {
  const d = document.createElement('div');
  d.className = 'grp'; d.textContent = title;
  box.appendChild(d);
}
function renderDetections(info) {
  const box = $('detections');
  box.textContent = '';
  const total = info.hashes.length + info.traps.length + info.directLinks.length;
  $('detCount').textContent = total ? `(${total})` : '';
  if (!total) {
    box.innerHTML = '<span class="none">Nada relevante detectado en esta página.</span>';
    return;
  }
  if (info.traps.some(t => t.severity >= 2)) $('detBox').open = true;
  if (info.hashes.length) {
    group(box, `SHA-256 encontrados (${info.hashes.length}) — clic para usar como hash personalizado`);
    info.hashes.forEach(h => box.appendChild(chip(
      `${h.hash.slice(0, 16)}…${h.hash.slice(-8)}  ${h.context ? '· ' + h.context : ''}`, '',
      () => {
        $('expected').value = h.hash;
        $('customDet').open = true;
        $('expected').dispatchEvent(new Event('input'));
      }, h.hash)));
  }
  if (info.directLinks.length) {
    group(box, `Enlaces directos (${info.directLinks.length}) — clic para usar`);
    info.directLinks.forEach(l => box.appendChild(chip(
      l.href, '', () => {
        $('url').value = l.href;
        $('url').dispatchEvent(new Event('input'));
        setTab('url', true);
      }, l.href)));
  }
  if (info.traps.length) {
    group(box, `Botones trampa sospechosos (${info.traps.length})`);
    info.traps.forEach(t => box.appendChild(chip(
      `[${t.severity >= 2 ? 'ALTO' : 'MEDIO'}] ${t.text || t.href} — ${t.reasons.join('; ')}`,
      'sev' + t.severity, () => {}, t.href)));
  }
}

/* ---------- rendering ---------- */
function drawMap(map) {
  const c = $('xray'), g = c.getContext('2d');
  const w = c.width, h = c.height;
  // idle background: dark base + cyan grid
  g.fillStyle = '#0c1a2e';
  g.fillRect(0, 0, w, h);
  g.fillStyle = 'rgba(34, 211, 238, 0.10)';
  for (let x = 0; x < w; x += 16) g.fillRect(x, 0, 1, h);
  g.fillStyle = 'rgba(34, 211, 238, 0.16)';
  g.fillRect(0, Math.floor(h / 2), w, 1);
  g.fillRect(0, 0, w, 1);
  g.fillRect(0, h - 1, w, 1);
  if (!map) return;
  for (let i = 0; i < w; i++) {
    const v = map[i] || 0;
    if (!v) continue;
    g.fillStyle = MAP_COLORS[v];
    g.fillRect(i, 0, 1, h);
  }
  // keep grid faintly visible over data
  g.fillStyle = 'rgba(0, 0, 0, 0.18)';
  for (let x = 0; x < w; x += 16) g.fillRect(x, 0, 1, h);
}

function renderArm() {
  const b = $('btnArm');
  b.classList.toggle('armed', armed);
  b.textContent = armed ? 'Interceptor ARMADO — inicia una descarga…' : 'Interceptar Próxima Descarga';
}

function updateButtons() {
  const running = scan.status === 'running';
  $('btnStart').classList.toggle('hidden', prefs.tab === 'intercept' || running);
  $('btnCancel').classList.toggle('hidden', !running);
  $('btnStart').disabled = running;
  $('mode').disabled = running;
}

function render() {
  renderArm();
  const running = scan.status === 'running';
  const st = $('status');
  st.className = 'status ' + (running ? 'running' : scan.status === 'done' ? 'done' : scan.status === 'error' ? 'error' : 'idle');
  st.textContent = ({ idle: 'IDLE', running: 'SCANNING', done: 'COMPLETE', error: 'ERROR', cancelled: 'CANCELLED' })[scan.status] || 'IDLE';
  updateButtons();

  showError(scan.status === 'error' ? scan.error : '');

  const p = scan.progress;
  const r = scan.result;
  const src = p || (r && {
    bytes: r.bytes, total: r.bytes, speed: r.speed, avgEntropy: r.avgEntropy,
    hash: r.sha256 || '(not computed in X-Ray mode)', map: r.map,
    blocks: r.blocks || (r.samples ? r.samples.length : 0)
  });
  if (src) {
    drawMap(src.map);
    $('tBytes').textContent = fmtBytes(src.bytes);
    $('tSpeed').textContent = fmtSpeed(src.speed || 0);
    $('tEnt').textContent = (src.avgEntropy || 0).toFixed(3);
    $('tBlocks').textContent = String(src.blocks || 0);
    $('tHash').textContent = src.hash || '—';
    $('barFill').style.width = (r ? 100 : (src.total ? Math.min(100, src.bytes / src.total * 100) : 0)) + '%';
  } else {
    drawMap(null);
    $('barFill').style.width = '0';
  }

  const vc = $('verdictCard');
  if (scan.status === 'done' && r) {
    vc.classList.remove('hidden');
    $('btnDownload').classList.toggle('hidden', !!r.demo || r.verdict === 'malware');
    $('verdict').className = 'verdict ' + r.verdict;
    $('verdict').textContent = (VERDICT_LABEL[r.verdict] || r.verdict.toUpperCase()) +
      (r.verdict === 'malware' && r.intel ? ' — ' + (r.intel.signature || 'sin clasificar') : '');
    const ul = $('findings');
    ul.textContent = '';
    r.findings.forEach(f => {
      const li = document.createElement('li');
      li.className = f.level;
      li.textContent = f.text;
      ul.appendChild(li);
    });
  } else {
    vc.classList.add('hidden');
  }
}

/* ---------- report ---------- */
function buildReport(r) {
  const icon = { verified: '✅', known: '🔷', clean: '🟢', suspicious: '⚠️', danger: '🛑', mismatch: '🛑', modified: '🛑', malware: '☠️' }[r.verdict] || '';
  const lines = [];
  lines.push('## 🛡️ EnicRay Forensic Report');
  lines.push('');
  lines.push(`**Verdict:** ${icon} ${VERDICT_LABEL[r.verdict]}`);
  lines.push(`**Mode:** ${r.demo ? 'DEMO (simulated data) — ' : ''}${r.mode === 'full' ? 'Full Audit (100% streaming)' : 'X-Ray (HTTP Range sampling)'}`);
  lines.push('');
  lines.push(`- **File:** \`${r.fileName}\``);
  lines.push(`- **Source:** ${r.url}`);
  lines.push(`- **Real format:** ${r.format}`);
  lines.push(`- **Size:** ${fmtBytes(r.bytes)} (${r.bytes} bytes)`);
  lines.push(`- **SHA-256:** ${r.sha256 ? '`' + r.sha256 + '`' : 'not computed (X-Ray mode)'}`);
  if (r.signature) lines.push(`- **Known signature:** ${r.signature}`);
  if (r.intel && r.intel.status === 'malware') {
    lines.push(`- **MalwareBazaar:** CONFIRMED MALWARE — family \`${r.intel.signature || 'unclassified'}\` (${r.intel.link})`);
  } else if (r.intel && r.intel.status === 'not_found') {
    lines.push('- **MalwareBazaar:** hash not found');
  }
  if (r.innerExes && r.innerExes.length) {
    lines.push('- **Inner `.exe` entries (ZIP deep scan):**');
    r.innerExes.forEach(e => {
      if (e.error) lines.push(`  - \`${e.name}\`: error (\`${e.error}\`)`);
      else {
        const tag = e.known ? `allowlist: ${e.known}`
          : (e.intel && e.intel.status === 'malware') ? `MALWARE: ${e.intel.signature || 'unclassified'}`
          : (e.intel && e.intel.status === 'not_found') ? 'MalwareBazaar: not found'
          : 'local only';
        lines.push(`  - \`${e.name}\` (${fmtBytes(e.bytes)}): \`${e.sha256}\` — ${tag}`);
      }
    });
  }
  if (r.expected) {
    lines.push(`- **Custom SHA-256:** \`${r.expected}\``);
    lines.push(`- **Custom hash match:** ${r.hashMatch === null ? 'n/a' : r.hashMatch ? 'YES' : 'NO'}`);
  }
  lines.push(`- **Entropy:** avg ${r.avgEntropy.toFixed(3)} / max ${r.maxEntropy.toFixed(3)} (bits per byte)`);
  if (r.mode === 'full') {
    lines.push(`- **Blocks (1 MiB):** ${r.blocks} total, ${r.highBlocks} high-entropy, ${r.padBlocks} padding-like`);
  } else {
    lines.push(`- **Samples:** ${r.samples.map(s => `${s.label}: H=${s.entropy.toFixed(2)}, zeros=${(s.zeroRatio * 100).toFixed(0)}%`).join(' | ')}`);
  }
  lines.push(`- **Scan time:** ${(r.elapsed / 1000).toFixed(1)} s @ ${fmtSpeed(r.speed)}`);
  if (r.dangerous.length) lines.push(`- **Suspicious strings:** ${r.dangerous.join(', ')}`);
  if (r.libraries.length) lines.push(`- **Runtime libs:** ${r.libraries.join(', ')}`);
  lines.push('');
  lines.push('**Findings**');
  r.findings.forEach(f => {
    const tag = { crit: '🔴', warn: '🟡', info: '🔵' }[f.level];
    lines.push(`- ${tag} ${f.text}`);
  });
  lines.push('');
  lines.push('_Generated by EnicRay — zero-disk, pre-download file auditing. Heuristic results are not a guarantee of safety._');
  return lines.join('\n');
}

async function copyReport() {
  if (!scan.result) return;
  const text = buildReport(scan.result);
  try { await navigator.clipboard.writeText(text); }
  catch (_) {
    const ta = document.createElement('textarea');
    ta.value = text; document.body.appendChild(ta); ta.select();
    document.execCommand('copy'); ta.remove();
  }
  const b = $('btnCopy');
  const old = b.textContent;
  b.textContent = '¡Copiado!';
  setTimeout(() => { b.textContent = old; }, 1500);
}

/* ---------- live updates ---------- */
chrome.runtime.onMessage.addListener((msg) => {
  if (msg && msg.target === 'popup' && msg.type === 'STATE') {
    scan = msg.scan;
    if (scan.url && !isDemo(scan) && document.activeElement !== $('url')) $('url').value = scan.url;
    render();
  }
});

init();
