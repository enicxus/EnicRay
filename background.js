/*
 * EnicRay - MV3 service worker.
 * Orchestrates the offscreen engine (which does the long-running streaming),
 * intercepts the next download when armed, persists scan state so the popup
 * can be closed and re-opened mid-scan.
 */
'use strict';

importScripts('config.js');

const OFFSCREEN_PATH = 'offscreen.html';
const BADGE = {
  verified: ['OK', '#16a34a'], known: ['OK', '#06b6d4'], neutral: ['—', '#64748b'],
  danger: ['X', '#ef4444'], mismatch: ['X', '#ef4444']
};

async function hasOffscreen() {
  const ctx = await chrome.runtime.getContexts({
    contextTypes: ['OFFSCREEN_DOCUMENT'],
    documentUrls: [chrome.runtime.getURL(OFFSCREEN_PATH)]
  });
  return ctx.length > 0;
}

let creating = null;
async function ensureOffscreen() {
  if (await hasOffscreen()) return;
  if (!creating) {
    creating = chrome.offscreen.createDocument({
      url: OFFSCREEN_PATH,
      reasons: ['WORKERS'],
      justification: 'Long-running streaming analysis (hashing/entropy) that must outlive the service worker idle timeout.'
    }).finally(() => { creating = null; });
  }
  await creating;
}

async function toOffscreen(message) {
  await ensureOffscreen();
  let lastErr;
  for (let i = 0; i < 8; i++) {
    try {
      const res = await chrome.runtime.sendMessage({ target: 'offscreen', ...message });
      if (res) return res;
    } catch (e) { lastErr = e; }
    await new Promise(r => setTimeout(r, 150));
  }
  throw lastErr || new Error('Offscreen engine did not respond.');
}

async function getState() {
  const s = await chrome.storage.session.get(['armed', 'scan']);
  return { armed: !!s.armed, scan: s.scan || { status: 'idle' } };
}
async function setScan(scan) { await chrome.storage.session.set({ scan }); }

function broadcast(payload) {
  chrome.runtime.sendMessage({ target: 'popup', ...payload }).catch(() => {});
}

async function startScan(url, mode, expected) {
  const scan = { status: 'running', url, mode, progress: null, result: null, error: null, startedAt: Date.now() };
  await setScan(scan);
  await chrome.action.setBadgeText({ text: '...' });
  await chrome.action.setBadgeBackgroundColor({ color: '#3b82f6' });
  broadcast({ type: 'STATE', scan });
  try {
    const res = await toOffscreen({
      type: 'START_SCAN', url, mode, expected,
      abuseKey: (typeof ENICRAY_CONFIG !== 'undefined' && ENICRAY_CONFIG.abuseChAuthKey) || ''
    });
    if (!res.ok) throw new Error(res.error || 'Could not start scan.');
  } catch (e) {
    const failed = { ...scan, status: 'error', error: String(e.message || e) };
    await setScan(failed);
    await chrome.action.setBadgeText({ text: 'ERR' });
    broadcast({ type: 'STATE', scan: failed });
    return { ok: false, error: failed.error };
  }
  return { ok: true };
}

async function handleScanEvent(ev) {
  const { scan } = await getState();
  const next = { ...scan };
  switch (ev.type) {
    case 'PROGRESS':
      next.status = 'running';
      next.progress = ev;
      break;
    case 'DONE':
      next.status = 'done';
      next.result = ev.result;
      next.progress = null;
      {
        const b = BADGE[ev.result.verdict] || ['', '#000000'];
        await chrome.action.setBadgeText({ text: b[0] });
        await chrome.action.setBadgeBackgroundColor({ color: b[1] });
      }
      break;
    case 'ERROR':
      next.status = 'error';
      next.error = ev.message;
      await chrome.action.setBadgeText({ text: 'ERR' });
      await chrome.action.setBadgeBackgroundColor({ color: '#ef4444' });
      break;
    case 'CANCELLED':
      next.status = 'cancelled';
      await chrome.action.setBadgeText({ text: '' });
      break;
    default:
      return;
  }
  await setScan(next);
  broadcast({ type: 'STATE', scan: next });
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (!msg || msg.target !== 'background') return;
  (async () => {
    switch (msg.type) {
      case 'GET_STATE':
        return { ok: true, ...(await getState()) };
      case 'START_SCAN':
        return startScan(msg.url, msg.mode, msg.expected);
      case 'CANCEL':
        try { await chrome.runtime.sendMessage({ target: 'offscreen', type: 'CANCEL' }); } catch (_) {}
        return { ok: true };
      case 'ARM': {
        await chrome.storage.session.set({ armed: !!msg.armed });
        await chrome.action.setBadgeText({ text: msg.armed ? 'ARM' : '' });
        await chrome.action.setBadgeBackgroundColor({ color: '#a855f7' });
        return { ok: true };
      }
      case 'DOWNLOAD': {
        if (!/^https?:/i.test(msg.url || '')) return { ok: false, error: 'Invalid URL.' };
        const { scan } = await getState();
        if (scan.result && scan.result.verdict === 'malware') {
          return { ok: false, error: 'Descarga bloqueada: malware confirmado por MalwareBazaar.' };
        }
        await chrome.downloads.download({ url: msg.url });
        return { ok: true };
      }
      case 'SCAN_EVENT':
        await handleScanEvent(msg.event);
        return { ok: true };
      case 'KEEPALIVE':
        return { ok: true };
      default:
        return { ok: false, error: 'Unknown message.' };
    }
  })().then(sendResponse);
  return true;
});

// Intercept the next download: cancel it and audit the URL instead.
chrome.downloads.onCreated.addListener(async (item) => {
  const { armed } = await chrome.storage.session.get('armed');
  if (!armed) return;
  const url = item.finalUrl || item.url;
  if (!/^https?:/i.test(url || '')) return; // blob:/data: cannot be re-fetched
  await chrome.storage.session.set({ armed: false });
  try {
    await chrome.downloads.cancel(item.id);
    await chrome.downloads.erase({ id: item.id });
  } catch (_) { /* already gone */ }
  const { prefs } = await chrome.storage.local.get('prefs');
  await startScan(url, (prefs && prefs.mode) || 'full', (prefs && prefs.expected) || '');
  try { await chrome.action.openPopup(); } catch (_) { /* needs a recent Chrome / user gesture */ }
});
