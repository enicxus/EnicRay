/*
 * EnicRay - Binary forensics primitives (no dependencies):
 *  - magic byte detection
 *  - Shannon entropy per block
 *  - case-insensitive ASCII + UTF-16LE string/import scanner that works across chunk boundaries
 */
(function (root) {
  'use strict';

  const BLOCK_SIZE = 1 << 20; // 1 MiB
  const ENTROPY_HIGH = 7.5;
  const ENTROPY_LOW = 0.5;

  const MAGICS = [
    { id: 'ZIP', label: 'ZIP Archive', sig: [0x50, 0x4B, 0x03, 0x04], compressed: true },
    { id: '7Z', label: '7-Zip Archive', sig: [0x37, 0x7A, 0xBC, 0xAF], compressed: true },
    { id: 'PE', label: 'Windows PE Executable (EXE/DLL)', sig: [0x4D, 0x5A], compressed: false },
    { id: 'RPF', label: 'RPF Container (v7)', sig: [0x52, 0x50, 0x46, 0x37], compressed: false },
    { id: 'RPF', label: 'RPF Container (v8)', sig: [0x52, 0x50, 0x46, 0x38], compressed: false },
    { id: 'RAR', label: 'RAR Archive', sig: [0x52, 0x61, 0x72, 0x21], compressed: true },
    { id: 'GZIP', label: 'GZIP Stream', sig: [0x1F, 0x8B, 0x08], compressed: true },
    { id: 'PDF', label: 'PDF Document', sig: [0x25, 0x50, 0x44, 0x46], compressed: false },
    { id: 'ELF', label: 'ELF Executable', sig: [0x7F, 0x45, 0x4C, 0x46], compressed: false },
    { id: 'PNG', label: 'PNG Image', sig: [0x89, 0x50, 0x4E, 0x47], compressed: true }
  ];

  const EXT_FORMAT = {
    zip: 'ZIP', '7z': '7Z', exe: 'PE', dll: 'PE', sys: 'PE', scr: 'PE', ocx: 'PE', cpl: 'PE',
    rpf: 'RPF', rar: 'RAR', gz: 'GZIP', pdf: 'PDF', png: 'PNG'
  };
  const PE_EXTS = new Set(['exe', 'dll', 'sys', 'scr', 'ocx', 'cpl', 'msi']);

  function detectMagic(b) {
    for (const m of MAGICS) {
      if (b.length < m.sig.length) continue;
      let ok = true;
      for (let i = 0; i < m.sig.length; i++) if (b[i] !== m.sig[i]) { ok = false; break; }
      if (!ok) continue;
      const res = { id: m.id, label: m.label, compressed: m.compressed };
      if (m.id === 'PE') {
        let valid = false;
        if (b.length >= 0x40) {
          const off = b[0x3C] | (b[0x3D] << 8) | (b[0x3E] << 16) | (b[0x3F] << 24);
          if (off > 0 && off + 4 <= b.length) {
            valid = b[off] === 0x50 && b[off + 1] === 0x45 && b[off + 2] === 0 && b[off + 3] === 0;
          } else {
            valid = null; // PE header lies beyond the inspected window
          }
        }
        res.validHeader = valid;
      }
      return res;
    }
    return null;
  }

  const hist = new Uint32Array(256);
  function entropy(v) {
    hist.fill(0);
    const n = v.length;
    for (let i = 0; i < n; i++) hist[v[i]]++;
    let e = 0;
    for (let i = 0; i < 256; i++) {
      const c = hist[i];
      if (c) { const p = c / n; e -= p * Math.log2(p); }
    }
    return { entropy: e, zeros: hist[0] };
  }

  /* ---------- String / import scanner ---------- */
  const PATTERNS = [
    { name: 'CryptUnprotectData', cat: 'credential access', danger: true },
    { name: 'SetWindowsHookEx', cat: 'input hooking / keylogging', danger: true },
    { name: 'VirtualAllocEx', cat: 'process injection', danger: true },
    { name: 'WriteProcessMemory', cat: 'process injection', danger: true },
    { name: 'CreateRemoteThread', cat: 'process injection', danger: true },
    { name: 'URLDownloadToFile', cat: 'remote payload downloader', danger: true },
    { name: 'powershell -enc', cat: 'encoded PowerShell command', danger: true, critical: true },
    { name: 'powershell.exe -enc', cat: 'encoded PowerShell command', danger: true, critical: true },
    { name: '-encodedcommand', cat: 'encoded PowerShell command', danger: true },
    { name: 'wallet.dat', cat: 'wallet file access', danger: true },
    { name: 'Login Data', cat: 'browser credential store access', danger: true },
    { name: 'd3d12', cat: 'graphics runtime library', danger: false },
    { name: 'd3d11', cat: 'graphics runtime library', danger: false },
    { name: 'xgameruntime', cat: 'game runtime library', danger: false }
  ];

  const LOWER = new Uint8Array(256);
  for (let i = 0; i < 256; i++) LOWER[i] = (i >= 65 && i <= 90) ? i + 32 : i;

  const OVERLAP = 128;

  class StringScanner {
    constructor() {
      this.found = new Map(); // pattern index -> pattern
      this.first = new Array(256);
      this.tail = new Uint8Array(OVERLAP - 1);
      this.tailLen = 0;
      this.joint = new Uint8Array(2 * (OVERLAP - 1));
      PATTERNS.forEach((p, pi) => {
        const ascii = Array.from(p.name.toLowerCase(), c => c.charCodeAt(0));
        const utf16 = [];
        for (const c of ascii) { utf16.push(c, 0); }
        for (const bytes of [ascii, utf16]) {
          // for UTF-16 the 2nd byte is 0x00, and LOWER[0]=0, so folding stays valid
          const entry = { pi, bytes: Uint8Array.from(bytes) };
          const fb = bytes[0];
          (this.first[fb] || (this.first[fb] = [])).push(entry);
        }
      });
    }

    _region(buf, newly) {
      const n = buf.length;
      const first = this.first;
      for (let i = 0; i < n; i++) {
        const cand = first[LOWER[buf[i]]];
        if (!cand) continue;
        for (let c = 0; c < cand.length; c++) {
          const e = cand[c];
          if (this.found.has(e.pi)) continue;
          const bl = e.bytes;
          if (i + bl.length > n) continue;
          let k = 1;
          while (k < bl.length && LOWER[buf[i + k]] === bl[k]) k++;
          if (k === bl.length) {
            this.found.set(e.pi, PATTERNS[e.pi]);
            newly.push(PATTERNS[e.pi]);
          }
        }
      }
    }

    /** Scan a block (continuing from the previous block). Returns newly-found patterns. */
    scan(view) {
      const newly = [];
      // boundary region: tail of previous block + head of this one
      if (this.tailLen > 0) {
        const head = Math.min(view.length, OVERLAP - 1);
        this.joint.set(this.tail.subarray(0, this.tailLen), 0);
        this.joint.set(view.subarray(0, head), this.tailLen);
        this._region(this.joint.subarray(0, this.tailLen + head), newly);
      }
      this._region(view, newly);
      const t = Math.min(view.length, OVERLAP - 1);
      this.tail.set(view.subarray(view.length - t), 0);
      this.tailLen = t;
      return newly;
    }

    results() {
      const all = Array.from(this.found.values());
      return {
        dangerous: all.filter(p => p.danger),
        libraries: all.filter(p => !p.danger)
      };
    }
  }

  root.Forensics = {
    BLOCK_SIZE, ENTROPY_HIGH, ENTROPY_LOW, MAGICS, EXT_FORMAT, PE_EXTS,
    detectMagic, entropy, StringScanner
  };
})(typeof globalThis !== 'undefined' ? globalThis : self);
