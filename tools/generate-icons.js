/*
 * Generates icons/icon16.png, icon48.png, icon128.png (shield + radar, cyan/green on dark).
 * Pure Node (zlib only), no dependencies.   Usage: node tools/generate-icons.js
 */
'use strict';
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const CYAN = [34, 211, 238], GREEN = [34, 197, 94], BG = [10, 14, 23], FILL = [12, 30, 46];

function inShield(x, y, s) {
  const xx = (x - 0.5) / s + 0.5, yy = (y - 0.52) / s + 0.52;
  if (yy < 0.14 || yy > 0.88) return false;
  const t = (yy - 0.14) / 0.74;
  const half = t < 0.45 ? 0.31 : 0.31 * Math.pow(Math.cos((t - 0.45) / 0.55 * Math.PI / 2), 0.9);
  return Math.abs(xx - 0.5) < half;
}

function shade(x, y, size) {
  // rounded-square background
  const r = 0.2, cx = Math.min(Math.max(x, r), 1 - r), cy = Math.min(Math.max(y, r), 1 - r);
  if ((x - cx) ** 2 + (y - cy) ** 2 > r * r) return [0, 0, 0, 0];
  let c = BG.slice();
  const stroke = Math.max(0.02, 1.3 / size);
  if (inShield(x, y, 1)) {
    c = inShield(x, y, 0.86) ? FILL.slice() : CYAN.slice();
    if (inShield(x, y, 0.86)) {
      const dx = x - 0.5, dy = y - 0.5, d = Math.hypot(dx, dy);
      const ring = (rad) => Math.abs(d - rad) < stroke / 2;
      if (ring(0.09) || (size > 20 && ring(0.17))) c = GREEN.map((v, i) => Math.round(v * 0.8 + FILL[i] * 0.2));
      let a = Math.atan2(dy, dx) * 180 / Math.PI; // -180..180
      if (d < 0.2 && a > -85 && a < -5) {
        const k = 0.15 + 0.5 * (a + 85) / 80; // brighter toward leading edge
        c = c.map((v, i) => Math.round(v * (1 - k) + GREEN[i] * k));
      }
      if (d < 0.035) c = CYAN.slice();
    }
  }
  return [c[0], c[1], c[2], 255];
}

function render(size) {
  const SS = 4, raw = Buffer.alloc((size * 4 + 1) * size);
  for (let py = 0; py < size; py++) {
    raw[py * (size * 4 + 1)] = 0;
    for (let px = 0; px < size; px++) {
      let R = 0, G = 0, B = 0, A = 0;
      for (let sy = 0; sy < SS; sy++) for (let sx = 0; sx < SS; sx++) {
        const p = shade((px + (sx + 0.5) / SS) / size, (py + (sy + 0.5) / SS) / size, size);
        R += p[0] * p[3]; G += p[1] * p[3]; B += p[2] * p[3]; A += p[3];
      }
      const o = py * (size * 4 + 1) + 1 + px * 4;
      if (A > 0) { raw[o] = R / A; raw[o + 1] = G / A; raw[o + 2] = B / A; }
      raw[o + 3] = A / (SS * SS);
    }
  }
  return raw;
}

const crcTable = new Uint32Array(256).map((_, n) => {
  let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; return c >>> 0;
});
function crc32(buf) { let c = 0xffffffff; for (const b of buf) c = crcTable[(c ^ b) & 255] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; }
function chunk(type, data) {
  const len = Buffer.alloc(4); len.writeUInt32BE(data.length);
  const td = Buffer.concat([Buffer.from(type), data]);
  const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(td));
  return Buffer.concat([len, td, crc]);
}
function png(size) {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0); ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8; ihdr[9] = 6; // 8-bit RGBA
  return Buffer.concat([
    Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]),
    chunk('IHDR', ihdr), chunk('IDAT', zlib.deflateSync(render(size), { level: 9 })), chunk('IEND', Buffer.alloc(0))
  ]);
}

const dir = path.join(__dirname, '..', 'icons');
fs.mkdirSync(dir, { recursive: true });
for (const s of [16, 48, 128]) {
  fs.writeFileSync(path.join(dir, `icon${s}.png`), png(s));
  console.log(`icons/icon${s}.png`);
}
