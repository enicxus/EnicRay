/*
 * EnicRay - Offscreen streaming engine.
 * Runs in an offscreen document so long scans are not killed by the MV3
 * service-worker idle timeout. Nothing is ever written to disk; memory is
 * bounded by one 1 MiB block buffer plus the network chunk currently in flight.
 */
'use strict';

const BLOCK = Forensics.BLOCK_SIZE;
const MAP_BINS = 512;
const EMIT_INTERVAL_MS = 250;
// severity codes used by the X-Ray map: 0 unscanned, 1 clean, 2 valid header, 3 high entropy, 4 threat
const SEV = { NONE: 0, CLEAN: 1, HEADER: 2, ENTROPY: 3, THREAT: 4 };

let current = null; // { ctrl }

console.assert(Sha256.selfTest(), 'SHA-256 self-test failed');

function emit(event) {
  chrome.runtime.sendMessage({ target: 'background', type: 'SCAN_EVENT', event }).catch(() => {});
}

// Keep the extension alive while a scan is running.
setInterval(() => {
  if (current) chrome.runtime.sendMessage({ target: 'background', type: 'KEEPALIVE' }).catch(() => {});
}, 20000);

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (!msg || msg.target !== 'offscreen') return;
  if (msg.type === 'START_SCAN') {
    if (current) { sendResponse({ ok: false, error: 'A scan is already running.' }); return; }
    sendResponse({ ok: true });
    runScan(msg).catch(err => {
      if (err && err.name === 'AbortError') emit({ type: 'CANCELLED' });
      else emit({ type: 'ERROR', message: String(err && err.message || err) });
    }).finally(() => { current = null; });
  } else if (msg.type === 'CANCEL') {
    if (current) current.ctrl.abort();
    sendResponse({ ok: true });
  } else if (msg.type === 'PING') {
    sendResponse({ ok: true });
  }
});

/* ---------- X-Ray map (fixed 512 bins, rescales when size is unknown) ---------- */
class BinMap {
  constructor(total) {
    this.a = new Uint8Array(MAP_BINS);
    this.total = total;
    this.scale = 1;
  }
  setBlock(idx, sev) {
    let bin;
    if (this.total > 0) {
      bin = Math.min(MAP_BINS - 1, Math.floor((idx * BLOCK) / this.total * MAP_BINS));
    } else {
      while (Math.floor(idx / this.scale) >= MAP_BINS) {
        for (let i = 0; i < MAP_BINS / 2; i++) this.a[i] = Math.max(this.a[2 * i], this.a[2 * i + 1]);
        this.a.fill(0, MAP_BINS / 2);
        this.scale *= 2;
      }
      bin = Math.floor(idx / this.scale);
    }
    if (sev > this.a[bin]) this.a[bin] = sev;
  }
  setBand(center, width, sev) {
    for (let b = center - width; b <= center + width; b++) {
      if (b >= 0 && b < MAP_BINS && sev > this.a[b]) this.a[b] = sev;
    }
  }
  toArray() { return Array.from(this.a); }
}

/* ---------- helpers ---------- */
function fileNameFrom(url, resp) {
  const cd = resp && resp.headers.get('content-disposition');
  if (cd) {
    const m = /filename\*?=(?:UTF-8'')?"?([^";]+)"?/i.exec(cd);
    if (m) { try { return decodeURIComponent(m[1]); } catch (_) { return m[1]; } }
  }
  try {
    const p = new URL(url).pathname;
    const last = p.substring(p.lastIndexOf('/') + 1);
    return decodeURIComponent(last) || 'unknown';
  } catch (_) { return 'unknown'; }
}
function extOf(name) {
  const m = /\.([A-Za-z0-9]+)$/.exec(name);
  return m ? m[1].toLowerCase() : '';
}
function classifyBlock(len, ent) {
  if (len < 4096) return SEV.CLEAN; // tiny trailing block: statistics are meaningless
  if (ent < Forensics.ENTROPY_LOW) return SEV.THREAT;
  if (ent > Forensics.ENTROPY_HIGH) return SEV.ENTROPY;
  return SEV.CLEAN;
}
function safeUrlLabel(url) {
  try { const u = new URL(url); return u.origin + u.pathname; } catch (_) { return url; }
}

/* ---------- verdict engine ---------- */
function evaluate(c) {
  const f = [];
  const add = (level, text) => f.push({ level, text });
  const ext = extOf(c.fileName);
  const fmt = c.magic ? c.magic.id : null;

  if (c.magic) add('info', `Real format by magic bytes: ${c.magic.label}.`);
  else add('info', 'No known magic bytes recognised at the start of the file.');

  if (fmt === 'PE' && c.magic.validHeader === false) add('warn', 'MZ signature present but the PE header is malformed.');
  const expectedFmt = Forensics.EXT_FORMAT[ext];
  if (fmt === 'PE' && !Forensics.PE_EXTS.has(ext)) {
    add('crit', `Executable payload disguised behind the extension ".${ext || 'none'}".`);
  } else if (expectedFmt && fmt && expectedFmt !== fmt) {
    add('warn', `Extension ".${ext}" suggests ${expectedFmt} but the real format is ${fmt}.`);
  } else if (expectedFmt && !fmt) {
    add('warn', `Extension ".${ext}" suggests ${expectedFmt} but the signature was not recognised.`);
  }

  if (c.mode === 'full') {
    const padRatio = c.blocks ? c.padBlocks / c.blocks : 0;
    if (padRatio > 0.2) add('crit', `${(padRatio * 100).toFixed(1)}% of blocks are near-zero entropy: file is likely artificially inflated / padded.`);
    else if (c.padBlocks > 0 && padRatio > 0.05) add('warn', `${c.padBlocks} low-entropy (padding-like) blocks detected (${(padRatio * 100).toFixed(1)}%).`);

    const highRatio = c.blocks ? c.highBlocks / c.blocks : 0;
    const compressedContainer = c.magic && c.magic.compressed;
    if (compressedContainer) {
      if (c.highBlocks) add('info', `High entropy across ${(highRatio * 100).toFixed(0)}% of blocks is expected for a compressed container.`);
    } else if (highRatio > 0.6) {
      add('crit', `${(highRatio * 100).toFixed(0)}% of blocks have entropy > 7.5: strong sign of packed/encrypted payload.`);
    } else if (highRatio > 0.3) {
      add('warn', `${(highRatio * 100).toFixed(0)}% of blocks have entropy > 7.5: possibly packed or obfuscated.`);
    }
  } else {
    const padded = c.samples.filter(s => s.sev === SEV.THREAT && s.entropy < Forensics.ENTROPY_LOW).length;
    if (padded >= 2) add('crit', `${padded}/${c.samples.length} sampled regions are empty/zero-filled: file is almost certainly inflated.`);
    else if (padded === 1) add('warn', '1 sampled region is empty/zero-filled: possible padding or sparse data.');
    const highs = c.samples.filter(s => s.entropy > Forensics.ENTROPY_HIGH).length;
    if (!(c.magic && c.magic.compressed) && highs >= 3) add('warn', `${highs}/${c.samples.length} sampled regions have very high entropy (possible packing/encryption).`);
  }

  const crit = c.dangerous.filter(p => p.critical);
  if (crit.length) add('crit', `Encoded PowerShell command pattern found: "${crit[0].name}".`);
  const names = c.dangerous.filter(p => !p.critical);
  if (names.length >= 3) add('crit', `Multiple malicious API/strings found together: ${names.map(p => p.name).join(', ')}.`);
  else if (names.length) add('warn', `Suspicious API/strings: ${names.map(p => p.name + ' (' + p.cat + ')').join(', ')}.`);
  if (c.libraries.length) add('info', `Runtime libraries referenced: ${c.libraries.map(p => p.name).join(', ')}.`);
  if (c.mode === 'full' && !c.libraries.length && fmt === 'PE') add('info', 'No standard graphics/runtime library references found in plain text.');

  if (c.mode === 'full' && c.declared > 0 && !c.encoded && c.bytes !== c.declared) {
    add('warn', `Received ${c.bytes} bytes but the server declared ${c.declared}.`);
  }

  // Known-signature allowlist (auto-detection, always on in full mode)
  let known = c.forceKnown || null;
  if (!known && c.mode === 'full') known = Signatures.find(c.sha);

  let hashMatch = null;
  if (c.expected) {
    if (c.mode === 'full') {
      hashMatch = c.sha === c.expected;
      add(hashMatch || known ? 'info' : 'crit', hashMatch
        ? 'El SHA-256 coincide con el hash personalizado.'
        : 'El SHA-256 NO coincide con el hash personalizado.');
    } else {
      add('info', 'Hash personalizado indicado, pero el SHA-256 requiere Auditoría Completa (el modo Rayos X solo muestrea).');
    }
  }

  let modified = false;
  const intel = c.intel || { status: 'skipped' };
  const zipIns = c.zipInspection || null;
  const innerExes = (zipIns && zipIns.exes) || [];
  const innerMalware = innerExes.find(e => e.intel && e.intel.status === 'malware') || null;
  const innerKnownEntry = (!known && !innerMalware) ? (innerExes.find(e => e.known) || null) : null;
  const effectiveKnown = known || (innerKnownEntry ? innerKnownEntry.known : null);
  const effectiveIntel = (intel.status === 'malware') ? intel : (innerMalware ? innerMalware.intel : intel);

  const sizeInfo = { fileName: c.fileName, fmt, ext, size: c.mode === 'full' ? c.bytes : c.declared };
  if (known) {
    add('info', `Firma Íntegra Verificada: ${known.label}. Archivo sin alterar (SHA-256 idéntico), sin malware.`);
    if (known.kind === 'exe') {
      add('warn', 'Aviso: este ejecutable es un binario de consola y NO es compatible con Windows; no se puede ejecutar en PC.');
    }
  } else {
    if (intel.status === 'malware') {
      add('crit', `MALWARE CONFIRMADO (MalwareBazaar): familia ${intel.signature || 'sin clasificar'}. No descargues ni ejecutes este archivo.`);
    } else if (intel.status === 'not_found') {
      add('info', 'MalwareBazaar: hash no encontrado; se continúa con el análisis heurístico local.');
    } else if (intel.status === 'unavailable') {
      add('info', `MalwareBazaar no disponible (${intel.detail || 'error'}); consulta omitida, análisis local activo.`);
    } else if (intel.status === 'no_key') {
      add('info', 'MalwareBazaar: sin Auth-Key en config.js; consulta en la nube omitida.');
    }
  }

  // Deep ZIP inner-.exe inspection findings
  if (zipIns && zipIns.skippedTooLarge) {
    add('info', 'Archivo ZIP >= 300 MB: inspección en memoria de .exe internos omitida por límite de tamaño.');
  }
  for (const ex of innerExes) {
    if (ex.error === 'encrypted') {
      add('warn', `EXE interno "${ex.name}" cifrado con contraseña: no se pudo descomprimir en memoria.`);
    } else if (ex.error === 'zip_bomb_limit') {
      add('crit', `EXE interno "${ex.name}" superó el límite descomprimido (posible zip bomb).`);
    } else if (ex.error) {
      add('warn', `EXE interno "${ex.name}" no pudo analizarse (${ex.error}).`);
    } else if (ex.sha256) {
      if (ex.known) {
        add('info', `EXE interno verificado en allowlist ("${ex.name}"): ${ex.known.label}. Binario íntegro sin alterar (SHA-256: ${ex.sha256.slice(0, 16)}…).`);
        if (ex.known.kind === 'exe') {
          add('warn', `Aviso: el ejecutable interno "${ex.name}" es un binario de consola y NO es compatible con Windows.`);
        }
      } else if (ex.intel && ex.intel.status === 'malware') {
        add('crit', `MALWARE CONFIRMADO en EXE interno "${ex.name}" (MalwareBazaar): familia ${ex.intel.signature || 'sin clasificar'} (SHA-256: ${ex.sha256}).`);
      } else {
        const mbNote = ex.intel
          ? (ex.intel.status === 'not_found' ? 'no encontrado en MalwareBazaar'
            : ex.intel.status === 'no_key' ? 'MalwareBazaar omitido sin Auth-Key'
            : `MalwareBazaar no disponible: ${ex.intel.detail || 'error'}`)
          : 'no consultado';
        add('info', `EXE interno "${ex.name}" (${ex.bytesDecompressed} B) — SHA-256: ${ex.sha256.slice(0, 16)}… (${mbNote}).`);
      }
      if (ex.expectedMatch === true) {
        add('info', `El EXE interno "${ex.name}" coincide con el SHA-256 personalizado.`);
      }
    }
  }

  if (effectiveKnown) {
    // allowlist hit (outer file or inner EXE): nothing else may raise red alerts
  } else if (c.mode === 'full') {
    if (!c.demo && Signatures.looksLikeInstaller(sizeInfo)) {
      modified = true;
      add('crit', 'ARCHIVO MODIFICADO / POSIBLE MALWARE: se presenta como instalador o paquete (.exe/.zip) pero su SHA-256 no coincide con ninguna firma conocida.');
    } else {
      add('info', 'Auto-detección: sin coincidencia con las firmas conocidas.');
    }
  } else {
    add('info', 'La auto-detección de firmas requiere Auditoría Completa (SHA-256).');
    if (!c.demo && Signatures.looksLikeInstaller(sizeInfo)) {
      add('warn', 'El tamaño/nombre se parece a un instalador conocido: ejecuta la Auditoría Completa para verificar su integridad.');
    }
  }

  if (effectiveKnown) f.forEach(x => { if (x.level === 'crit') x.level = 'warn'; }); // allowlist stops red alerts
  const hasCrit = f.some(x => x.level === 'crit');
  const hasWarn = f.some(x => x.level === 'warn');
  let verdict;
  if (known) verdict = 'known';
  else if (effectiveIntel.status === 'malware') verdict = 'malware';
  else if (innerKnownEntry) verdict = 'known';
  else if (hashMatch === true && !hasCrit) verdict = 'verified';
  else if (hashMatch === false) verdict = 'mismatch';
  else if (modified) verdict = 'modified';
  else if (hasCrit) verdict = 'danger';
  else if (hasWarn) verdict = 'suspicious';
  else verdict = 'clean';
  return { verdict, findings: f, hashMatch, known: effectiveKnown, intel: effectiveIntel };
}

/* ---------- Threat intelligence: MalwareBazaar (abuse.ch) ---------- */
const MB_ENDPOINT = 'https://mb-api.abuse.ch/api/v1/';
const MB_TIMEOUT_MS = 3000;

/** Only the SHA-256 leaves the machine. Never throws; failures degrade to local analysis. */
async function queryMalwareBazaar(sha, authKey, parentSignal) {
  if (!authKey) return { status: 'no_key' };
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), MB_TIMEOUT_MS);
  const onAbort = () => ctrl.abort();
  if (parentSignal) parentSignal.addEventListener('abort', onAbort, { once: true });
  try {
    const fd = new FormData();
    fd.append('query', 'get_info');
    fd.append('hash', sha);
    const r = await fetch(MB_ENDPOINT, {
      method: 'POST', body: fd, headers: { 'Auth-Key': authKey },
      signal: ctrl.signal, cache: 'no-store', credentials: 'omit'
    });
    if (!r.ok) return { status: 'unavailable', detail: 'HTTP ' + r.status };
    const j = await r.json();
    if (j.query_status === 'ok' && Array.isArray(j.data) && j.data.length) {
      const d = j.data[0];
      return {
        status: 'malware', signature: d.signature || null, fileName: d.file_name || null,
        link: 'https://bazaar.abuse.ch/sample/' + sha + '/'
      };
    }
    if (j.query_status === 'hash_not_found') return { status: 'not_found' };
    return { status: 'unavailable', detail: String(j.query_status || 'unknown') };
  } catch (e) {
    return { status: 'unavailable', detail: e && e.name === 'AbortError' ? 'timeout' : String((e && e.message) || e) };
  } finally {
    clearTimeout(timer);
    if (parentSignal) parentSignal.removeEventListener('abort', onAbort);
  }
}

/* ---------- entry ---------- */
async function runScan(job) {
  const ctrl = new AbortController();
  current = { ctrl };
  const expected = (job.expected || '').trim().toLowerCase();
  emit({ type: 'STARTED', url: job.url, mode: job.mode });
  if (job.mode === 'range') await rangeInspection(job, expected, ctrl);
  else if (/^demo-/.test(job.mode)) await fullAudit({ ...job, demo: job.mode.slice(5) }, expected, ctrl);
  else await fullAudit(job, expected, ctrl);
}

/* ---------- Demo: synthetic stream fed through the REAL pipeline (no network) ---------- */
function makeDemoResponse(variant, signal) {
  const CHUNK = 256 * 1024, TOTAL = 128 * 1024 * 1024;
  const threat = variant === 'threat';
  const enc = new TextEncoder();
  let offset = 0, idx = 0, seed = 0x9e3779b9;
  const rnd = () => { seed ^= seed << 13; seed ^= seed >>> 17; seed ^= seed << 5; return seed >>> 0; };
  const inject = threat
    ? { 40: 'CryptUnprotectData', 120: 'SetWindowsHookExW', 200: 'VirtualAllocEx', 280: 'URLDownloadToFileA', 360: 'powershell -enc JABzAD0A' }
    : { 100: 'd3d12.dll', 300: 'xgameruntime.dll' };

  const body = new ReadableStream({
    async pull(controller) {
      if (signal.aborted) { controller.error(new DOMException('Aborted', 'AbortError')); return; }
      if (offset >= TOTAL) { controller.close(); return; }
      await new Promise(r => setTimeout(r, 12));
      const f = offset / TOTAL;
      const c = new Uint8Array(CHUNK);
      const padded = threat && f >= 0.35 && f < 0.65;
      const hot = threat ? (f >= 0.8 && f < 0.9) : (f >= 0.45 && f < 0.52);
      if (!padded) {
        for (let i = 0; i < CHUNK; i += 4) {
          const r = rnd();
          if (hot) { c[i] = r; c[i + 1] = r >>> 8; c[i + 2] = r >>> 16; c[i + 3] = r >>> 24; }
          else { c[i] = 32 + (r & 63); c[i + 1] = 32 + ((r >>> 8) & 63); c[i + 2] = 32 + ((r >>> 16) & 63); c[i + 3] = 32 + ((r >>> 24) & 63); }
        }
      }
      if (idx === 0) { c[0] = 0x4D; c[1] = 0x5A; c[0x3C] = 0x80; c[0x80] = 0x50; c[0x81] = 0x45; c[0x82] = 0; c[0x83] = 0; }
      if (inject[idx]) c.set(enc.encode(inject[idx]), 1024);
      offset += CHUNK; idx++;
      controller.enqueue(c);
    }
  });
  return {
    ok: true, status: 200, statusText: 'OK', body, url: 'https://demo.local/demo_sample.exe',
    headers: new Headers({ 'content-length': String(TOTAL), 'content-disposition': 'attachment; filename="demo_sample.exe"' })
  };
}

/* ---------- Mode A: full streaming audit ---------- */
async function fullAudit(job, expected, ctrl) {
  const t0 = performance.now();
  const resp = job.demo
    ? makeDemoResponse(job.demo, ctrl.signal)
    : await fetch(job.url, { signal: ctrl.signal, credentials: 'include', cache: 'no-store', redirect: 'follow' });
  if (!resp.ok) throw new Error(`HTTP ${resp.status} ${resp.statusText}`);
  if (!resp.body) throw new Error('Response has no readable body.');

  const encoded = !!resp.headers.get('content-encoding');
  const declared = encoded ? 0 : (parseInt(resp.headers.get('content-length') || '0', 10) || 0);
  const fileName = fileNameFrom(resp.url || job.url, resp);
  const reader = resp.body.getReader();

  const hasher = new Sha256();
  const scanner = new Forensics.StringScanner();
  const map = new BinMap(declared);
  const canInspectZip = !job.demo && typeof ZipExeInspector === 'function' && (declared === 0 || declared <= ZIP_MAX_INSPECT_BYTES);
  const zipInspector = canInspectZip ? new ZipExeInspector({ maxZipBytes: ZIP_MAX_INSPECT_BYTES }) : null;
  const buf = new Uint8Array(BLOCK); // the ONLY large buffer; reused for the whole scan
  let fill = 0, bytes = 0, blockIdx = 0;
  let magic = null;
  let entSum = 0, entCount = 0, entMax = 0;
  let padBlocks = 0, highBlocks = 0, zeroBytes = 0;
  let lastEmit = 0, lastBytes = 0, lastT = t0, speed = 0;

  function processBlock(view) {
    const { entropy, zeros } = Forensics.entropy(view);
    hasherUpdate(view);
    const hits = scanner.scan(view);
    let sev = classifyBlock(view.length, entropy);
    if (view.length >= 4096) { entSum += entropy; entCount++; if (entropy > entMax) entMax = entropy; }
    if (sev === SEV.THREAT) padBlocks++;
    if (sev === SEV.ENTROPY) highBlocks++;
    zeroBytes += zeros;
    if (hits.some(h => h.danger)) sev = SEV.THREAT;
    if (blockIdx === 0) {
      magic = Forensics.detectMagic(view);
      if (magic && sev < SEV.THREAT) sev = SEV.HEADER;
    }
    map.setBlock(blockIdx, sev);
    blockIdx++;
  }
  function hasherUpdate(v) { hasher.update(v); }

  function progress(force) {
    const now = performance.now();
    if (!force && now - lastEmit < EMIT_INTERVAL_MS) return;
    const dt = (now - lastT) / 1000;
    if (dt > 0) {
      const inst = (bytes - lastBytes) / dt;
      speed = speed ? speed * 0.6 + inst * 0.4 : inst;
    }
    lastT = now; lastBytes = bytes; lastEmit = now;
    emit({
      type: 'PROGRESS', mode: 'full', bytes, total: declared, speed,
      avgEntropy: entCount ? entSum / entCount : 0, hash: hasher.digest(),
      map: map.toArray(), blocks: blockIdx, elapsed: now - t0
    });
  }

  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (zipInspector) await zipInspector.feed(value);
    let off = 0;
    while (off < value.length) {
      const n = Math.min(value.length - off, BLOCK - fill);
      buf.set(value.subarray(off, off + n), fill);
      fill += n; off += n;
      if (fill === BLOCK) { processBlock(buf); fill = 0; }
    }
    bytes += value.length; // `value` is released on the next iteration
    progress(false);
  }
  if (fill > 0) processBlock(buf.subarray(0, fill));

  const sha = hasher.digest();
  const elapsed = performance.now() - t0;
  const res = scanner.results();
  const zipRes = zipInspector ? await zipInspector.finalize() : null;
  const innerExes = (zipRes && zipRes.exes) || [];

  // Cascade: 1) local allowlist (inside evaluate)  2) MalwareBazaar  3) inner .exe checks  4) local heuristics
  let intel = { status: 'skipped' };
  const allowlisted = job.demo === 'known' || !!Signatures.find(sha);
  if (!allowlisted && !job.demo) {
    intel = await queryMalwareBazaar(sha, job.abuseKey, ctrl.signal);
    if (ctrl.signal.aborted) throw new DOMException('Aborted', 'AbortError');
  }
  for (const ex of innerExes) {
    if (!ex.sha256) continue;
    ex.known = Signatures.find(ex.sha256);
    ex.expectedMatch = expected ? (ex.sha256 === expected) : null;
    if (!ex.known && !job.demo) {
      ex.intel = await queryMalwareBazaar(ex.sha256, job.abuseKey, ctrl.signal);
      if (ctrl.signal.aborted) throw new DOMException('Aborted', 'AbortError');
    } else {
      ex.intel = { status: 'skipped' };
    }
  }

  const zipInspection = (magic && magic.id === 'ZIP') ? {
    skippedTooLarge: (declared > ZIP_MAX_INSPECT_BYTES) || !!(zipRes && zipRes.abortReason === 'exceeds_300mb'),
    exes: innerExes
  } : null;

  const ctx = {
    mode: 'full', url: job.url, fileName, magic, bytes, declared, encoded,
    blocks: blockIdx, padBlocks, highBlocks, zeroBytes,
    dangerous: res.dangerous, libraries: res.libraries, sha, expected,
    demo: !!job.demo, forceKnown: job.demo === 'known' ? Signatures.LIST[1] : null, intel, zipInspection
  };
  const ev = evaluate(ctx);
  if (job.demo) ev.findings.unshift({ level: 'info', text: 'SIMULATED DEMO DATA: synthetic stream, not a real remote file.' });
  progress(true);
  emit({
    type: 'DONE',
    result: {
      demo: !!job.demo, mode: 'full', url: safeUrlLabel(job.url), fileName, format: magic ? magic.label : 'Unknown',
      bytes, sha256: sha, expected: expected || null, hashMatch: ev.hashMatch,
      avgEntropy: entCount ? entSum / entCount : 0, maxEntropy: entMax,
      blocks: blockIdx, padBlocks, highBlocks, zeroBytes,
      signature: ev.known ? ev.known.label : null, intel: ev.intel,
      innerExes: innerExes.map(e => ({
        name: e.name, bytes: e.bytesDecompressed, sha256: e.sha256, error: e.error,
        known: e.known ? e.known.label : null, intel: e.intel || null
      })),
      dangerous: res.dangerous.map(p => p.name), libraries: res.libraries.map(p => p.name),
      elapsed, speed: elapsed > 0 ? bytes / (elapsed / 1000) : 0,
      verdict: ev.verdict, findings: ev.findings, map: map.toArray()
    }
  });
}

/* ---------- Mode B: HTTP Range X-Ray ---------- */
async function readUpTo(resp, limit) {
  const reader = resp.body.getReader();
  const out = new Uint8Array(limit);
  let n = 0;
  while (n < limit) {
    const { done, value } = await reader.read();
    if (done) break;
    const take = Math.min(value.length, limit - n);
    out.set(value.subarray(0, take), n);
    n += take;
  }
  try { await reader.cancel(); } catch (_) {}
  return out.subarray(0, n);
}

async function rangeInspection(job, expected, ctrl) {
  const t0 = performance.now();
  const opts = (range) => ({
    signal: ctrl.signal, credentials: 'include', cache: 'no-store', redirect: 'follow',
    headers: { Range: range }
  });

  const probe = await fetch(job.url, opts('bytes=0-0'));
  if (probe.status !== 206) {
    try { await probe.body.cancel(); } catch (_) {}
    throw new Error(`Server does not support HTTP Range (status ${probe.status}). Use Full Audit mode instead.`);
  }
  const cr = /\/(\d+)\s*$/.exec(probe.headers.get('content-range') || '');
  try { await probe.body.cancel(); } catch (_) {}
  if (!cr) throw new Error('Server did not report the total file size in Content-Range.');
  const size = parseInt(cr[1], 10);
  const fileName = fileNameFrom(probe.url || job.url, probe);

  const len = Math.min(BLOCK, size);
  const marks = [['0%', 0], ['25%', 0.25], ['50%', 0.5], ['75%', 0.75], ['100%', 1]];
  const seen = new Set();
  const plan = [];
  for (const [label, frac] of marks) {
    let start = frac === 1 ? size - len : Math.floor(size * frac);
    start = Math.max(0, Math.min(start, size - len));
    if (seen.has(start)) continue;
    seen.add(start);
    plan.push({ label, start });
  }

  const scanner = new Forensics.StringScanner();
  const map = new BinMap(size);
  const samples = [];
  let magic = null, sampled = 0, entSum = 0, entMax = 0;

  for (const p of plan) {
    const r = await fetch(job.url, opts(`bytes=${p.start}-${p.start + len - 1}`));
    if (r.status !== 206) {
      try { await r.body.cancel(); } catch (_) {}
      throw new Error(`Range request at ${p.label} returned HTTP ${r.status}; server ignored the Range header.`);
    }
    const data = await readUpTo(r, len);
    sampled += data.length;
    const { entropy, zeros } = Forensics.entropy(data);
    const hits = scanner.scan(data);
    let sev = classifyBlock(data.length, entropy);
    if (hits.some(h => h.danger)) sev = SEV.THREAT;
    if (p.start === 0) {
      magic = Forensics.detectMagic(data);
      if (magic && sev < SEV.THREAT) sev = SEV.HEADER;
    }
    entSum += entropy; if (entropy > entMax) entMax = entropy;
    const center = Math.min(MAP_BINS - 1, Math.floor(p.start / size * MAP_BINS));
    map.setBand(center, 2, sev);
    samples.push({
      label: p.label, pos: p.start, entropy,
      zeroRatio: data.length ? zeros / data.length : 0,
      sev: classifyBlock(data.length, entropy) === SEV.THREAT ? SEV.THREAT : sev
    });
    const now = performance.now();
    emit({
      type: 'PROGRESS', mode: 'range', bytes: sampled, total: size,
      speed: sampled / ((now - t0) / 1000), avgEntropy: entSum / samples.length,
      hash: '(not computed in X-Ray mode)', map: map.toArray(), blocks: samples.length,
      elapsed: now - t0, note: `Sampled ${p.label}`
    });
  }

  const res = scanner.results();
  const ctx = {
    mode: 'range', url: job.url, fileName, magic, bytes: sampled, declared: size, encoded: false,
    samples, dangerous: res.dangerous, libraries: res.libraries, sha: null, expected
  };
  const ev = evaluate(ctx);
  const elapsed = performance.now() - t0;
  emit({
    type: 'DONE',
    result: {
      mode: 'range', url: safeUrlLabel(job.url), fileName, format: magic ? magic.label : 'Unknown',
      bytes: size, sampledBytes: sampled, sha256: null, expected: expected || null, hashMatch: ev.hashMatch,
      avgEntropy: entSum / samples.length, maxEntropy: entMax, samples,
      signature: ev.known ? ev.known.label : null, intel: ev.intel,
      dangerous: res.dangerous.map(p => p.name), libraries: res.libraries.map(p => p.name),
      elapsed, speed: sampled / (elapsed / 1000),
      verdict: ev.verdict, findings: ev.findings, map: map.toArray()
    }
  });
}
