/*
 * EnicRay - content script.
 * On request, scans the current page for SHA-256 strings (64 hex chars),
 * direct file links and "trap" download buttons (deceptive/overlay/disguised).
 * It only reads the DOM; nothing is sent anywhere.
 */
(() => {
  'use strict';
  if (window.__enicrayLoaded) return;
  window.__enicrayLoaded = true;

  const HEX64 = /(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])/g;
  const DL_TEXT = /download|descargar|t[eé]l[eé]charger|herunterladen|get\s+now|install\s+now|free\s+download|scarica/i;
  const RISKY_EXT = /\.(exe|msi|scr|bat|cmd|vbs|js|jar|ps1|lnk|hta|com|pif)(\?|#|$)/i;
  const DOUBLE_EXT = /\.(pdf|docx?|xlsx?|jpe?g|png|gif|zip|rar|txt|mp4|mp3)\.(exe|scr|bat|cmd|js|vbs|lnk|com|pif)(\?|#|$)/i;
  const FILE_EXT = /\.(zip|7z|rar|exe|msi|iso|rpf|dll|bin|tar|gz|dmg|apk)(\?|#|$)/i;
  const SHORTENERS = new Set(['bit.ly', 'tinyurl.com', 'adf.ly', 'ouo.io', 'shorte.st', 'cutt.ly',
    'is.gd', 'linkvertise.com', 'rebrand.ly', 't.co', 'goo.gl', 'bc.vc']);

  function collectHashes() {
    const found = new Map();
    const text = (document.body && document.body.innerText) || '';
    let m;
    HEX64.lastIndex = 0;
    while ((m = HEX64.exec(text)) !== null && found.size < 25) {
      const h = m[0].toLowerCase();
      if (found.has(h)) continue;
      const before = text.slice(Math.max(0, m.index - 70), m.index).split('\n').pop().trim();
      found.set(h, before.slice(-50));
    }
    document.querySelectorAll('[data-sha256],[data-hash],[data-checksum],input[value]').forEach(el => {
      if (found.size >= 25) return;
      const v = (el.getAttribute('data-sha256') || el.getAttribute('data-hash') ||
                 el.getAttribute('data-checksum') || el.value || '').trim();
      if (/^[0-9a-fA-F]{64}$/.test(v) && !found.has(v.toLowerCase())) found.set(v.toLowerCase(), 'attribute');
    });
    return Array.from(found, ([hash, context]) => ({ hash, context }));
  }

  function hostOf(href) {
    try { return new URL(href, location.href).hostname.toLowerCase(); } catch (_) { return ''; }
  }

  function analyseElement(el) {
    const text = (el.innerText || el.value || el.getAttribute('aria-label') || '').trim().replace(/\s+/g, ' ');
    const href = el.href || el.getAttribute('data-href') || '';
    const isDlLabel = DL_TEXT.test(text);
    const reasons = [];
    let severity = 0;

    if (href && DOUBLE_EXT.test(href)) { reasons.push('double extension (disguised executable)'); severity = 2; }
    else if (href && RISKY_EXT.test(href)) { reasons.push('links directly to an executable/script'); severity = Math.max(severity, 1); }
    if (href && SHORTENERS.has(hostOf(href))) { reasons.push('URL shortener / ad-gate redirect'); severity = Math.max(severity, 1); }
    if (isDlLabel && href && hostOf(href) && hostOf(href) !== location.hostname) {
      reasons.push(`download button leaves site (${hostOf(href)})`);
      severity = Math.max(severity, 1);
    }
    if (isDlLabel && (!href || href === '#' || /^javascript:/i.test(href)) && (el.onclick || el.hasAttribute('onclick'))) {
      reasons.push('script-driven download (target hidden)');
      severity = Math.max(severity, 1);
    }
    try {
      const cs = getComputedStyle(el);
      const r = el.getBoundingClientRect();
      if (parseFloat(cs.opacity) < 0.05 && (cs.position === 'fixed' || cs.position === 'absolute') && r.width * r.height > 10000) {
        reasons.push('invisible full-area click overlay');
        severity = 2;
      }
    } catch (_) { /* ignore */ }

    return { text: text.slice(0, 80), href: href.slice(0, 300), isDlLabel, reasons, severity };
  }

  function scanPage(highlight) {
    const hashes = collectHashes();
    const traps = [];
    const directLinks = [];
    let dlLabelCount = 0;
    const els = document.querySelectorAll('a[href], button, input[type=button], input[type=submit], [role=button]');
    for (const el of els) {
      const a = analyseElement(el);
      if (a.isDlLabel) dlLabelCount++;
      if (el.tagName === 'A' && el.href && FILE_EXT.test(el.href) && directLinks.length < 20) {
        directLinks.push({ href: el.href, text: a.text });
      }
      if (a.reasons.length) {
        traps.push({ text: a.text, href: a.href, reasons: a.reasons, severity: a.severity });
        if (highlight) {
          el.style.outline = `3px solid ${a.severity >= 2 ? '#ef4444' : '#eab308'}`;
          el.style.outlineOffset = '2px';
          el.title = 'EnicRay: ' + a.reasons.join('; ');
        }
      }
      if (traps.length >= 30) break;
    }
    if (dlLabelCount > 4) {
      traps.unshift({
        text: `${dlLabelCount} "download" buttons on this page`,
        href: '', reasons: ['multiple competing download buttons (decoy pattern)'], severity: 1
      });
    }
    return { pageUrl: location.href, title: document.title, hashes, traps, directLinks };
  }

  chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (msg && msg.type === 'ENICRAY_SCAN_PAGE') {
      try { sendResponse({ ok: true, info: scanPage(!!msg.highlight) }); }
      catch (e) { sendResponse({ ok: false, error: String(e) }); }
    }
  });
})();
