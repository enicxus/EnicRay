/*
 * EnicRay - Incremental SHA-256 (FIPS 180-4), pure JavaScript, zero dependencies.
 * Designed for streaming: update() can be called with arbitrarily sized chunks
 * and never retains a reference to the input. Supports inputs > 4 GiB
 * (length is tracked as a double, exact up to 2^53 bytes).
 */
(function (root) {
  'use strict';

  const K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ]);

  const W = new Uint32Array(64); // shared scratch (single-threaded use)

  class Sha256 {
    constructor() {
      this.h = new Uint32Array(8);
      this.buf = new Uint8Array(64);
      this.reset();
    }

    reset() {
      this.h.set([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
      this.bl = 0;   // bytes currently buffered
      this.len = 0;  // total bytes consumed
      return this;
    }

    _block(d, o) {
      const h = this.h;
      let i;
      for (i = 0; i < 16; i++, o += 4) {
        W[i] = (d[o] << 24) | (d[o + 1] << 16) | (d[o + 2] << 8) | d[o + 3];
      }
      for (i = 16; i < 64; i++) {
        const a = W[i - 15], b = W[i - 2];
        const s0 = ((a >>> 7) | (a << 25)) ^ ((a >>> 18) | (a << 14)) ^ (a >>> 3);
        const s1 = ((b >>> 17) | (b << 15)) ^ ((b >>> 19) | (b << 13)) ^ (b >>> 10);
        W[i] = (W[i - 16] + s0 + W[i - 7] + s1) | 0;
      }
      let a = h[0], b = h[1], c = h[2], dd = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
      for (i = 0; i < 64; i++) {
        const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
        const ch = (e & f) ^ (~e & g);
        const t1 = (hh + S1 + ch + K[i] + W[i]) | 0;
        const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
        const mj = (a & b) ^ (a & c) ^ (b & c);
        const t2 = (S0 + mj) | 0;
        hh = g; g = f; f = e; e = (dd + t1) | 0;
        dd = c; c = b; b = a; a = (t1 + t2) | 0;
      }
      h[0] = (h[0] + a) | 0; h[1] = (h[1] + b) | 0; h[2] = (h[2] + c) | 0; h[3] = (h[3] + dd) | 0;
      h[4] = (h[4] + e) | 0; h[5] = (h[5] + f) | 0; h[6] = (h[6] + g) | 0; h[7] = (h[7] + hh) | 0;
    }

    /** Feed a Uint8Array. The array is NOT retained. */
    update(data) {
      const n = data.length;
      let i = 0;
      this.len += n;
      if (this.bl > 0) {
        const take = Math.min(64 - this.bl, n);
        this.buf.set(data.subarray(0, take), this.bl);
        this.bl += take;
        i = take;
        if (this.bl === 64) {
          this._block(this.buf, 0);
          this.bl = 0;
        }
      }
      while (i + 64 <= n) {
        this._block(data, i);
        i += 64;
      }
      if (i < n) {
        this.buf.set(data.subarray(i, n), 0);
        this.bl = n - i;
      }
      return this;
    }

    clone() {
      const c = new Sha256();
      c.h.set(this.h);
      c.buf.set(this.buf);
      c.bl = this.bl;
      c.len = this.len;
      return c;
    }

    /** Hex digest of everything consumed so far; does not disturb the running state. */
    digest() {
      const c = this.clone();
      const bits = this.len * 8;
      const padLen = c.bl < 56 ? 56 - c.bl : 120 - c.bl;
      const pad = new Uint8Array(padLen + 8);
      pad[0] = 0x80;
      const hi = Math.floor(bits / 4294967296);
      const lo = bits >>> 0;
      const p = padLen;
      pad[p] = hi >>> 24; pad[p + 1] = hi >>> 16; pad[p + 2] = hi >>> 8; pad[p + 3] = hi;
      pad[p + 4] = lo >>> 24; pad[p + 5] = lo >>> 16; pad[p + 6] = lo >>> 8; pad[p + 7] = lo;
      c.update(pad);
      let out = '';
      for (let i = 0; i < 8; i++) out += (c.h[i] >>> 0).toString(16).padStart(8, '0');
      return out;
    }

    /** Known-answer self test (FIPS 180 vectors). */
    static selfTest() {
      const enc = new TextEncoder();
      const a = new Sha256().update(enc.encode('abc')).digest();
      const b = new Sha256().digest();
      return a === 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad' &&
             b === 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
    }
  }

  root.Sha256 = Sha256;
})(typeof globalThis !== 'undefined' ? globalThis : self);
