/*
 * EnicRay - Streaming ZIP inner-.exe inspector (zero-disk, low-RAM).
 * Parses ZIP Local File Headers on the fly and decompresses any internal .exe
 * using the browser's native DecompressionStream('deflate-raw') (or reads STORE
 * directly), feeding decompressed chunks straight into incremental Sha256.
 * No external libraries.
 */
(function (root) {
  'use strict';

  const MAX_ZIP_BYTES = 300 * 1024 * 1024;          // 300 MiB
  const MAX_UNCOMPRESSED_EXE = 1024 * 1024 * 1024;  // 1 GiB zip-bomb safety cap
  const MAX_EXES = 10;

  const SIG_LFH = 0x04034b50; // PK\x03\x04
  const SIG_DD  = 0x08074b50; // PK\x07\x08
  const SIG_CDH = 0x02014b50; // PK\x01\x02
  const SIG_EOCD = 0x06054b50; // PK\x05\x06

  function u16(b, o) { return b[o] | (b[o + 1] << 8); }
  function u32(b, o) { return (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0; }
  function u64(b, o) { return u32(b, o) + u32(b, o + 4) * 4294967296; }

  function parseZip64Extra(extra, comp32, uncomp32) {
    let comp = comp32, uncomp = uncomp32;
    let p = 0;
    while (p + 4 <= extra.length) {
      const id = u16(extra, p), sz = u16(extra, p + 2);
      p += 4;
      if (id === 0x0001 && p + sz <= extra.length) {
        let q = p;
        if (uncomp32 === 0xFFFFFFFF && q + 8 <= p + sz) { uncomp = u64(extra, q); q += 8; }
        if (comp32 === 0xFFFFFFFF && q + 8 <= p + sz) { comp = u64(extra, q); q += 8; }
        break;
      }
      p += sz;
    }
    return { comp, uncomp };
  }

  class ZipExeInspector {
    constructor(opts) {
      opts = opts || {};
      this.maxZipBytes = opts.maxZipBytes || MAX_ZIP_BYTES;
      this.totalIn = 0;
      this.aborted = false;
      this.abortReason = null;
      this.state = 'SIG'; // SIG | LFH | META | DATA_KNOWN | DATA_DESC | DONE
      this.need = 4;
      this.hdr = new Uint8Array(4);
      this.hdrLen = 0;
      this.lfh = null;
      this.rem = 0;
      this.cur = null; // active .exe decompression context
      this.ddBuf = new Uint8Array(0);
      this.ddCompRead = 0;
      this.exes = [];
      this.decoder = new TextDecoder('utf-8', { fatal: false });
    }

    _ensureHdr(n) {
      if (this.hdr.length < n) this.hdr = new Uint8Array(n);
      this.hdrLen = 0;
      this.need = n;
    }

    _startExe(name, method, flags, compSize, uncompSize) {
      const entry = {
        name, method,
        encrypted: (flags & 0x01) !== 0,
        compressedSize: compSize,
        uncompressedSize: uncompSize,
        bytesDecompressed: 0,
        sha256: null,
        error: null
      };
      this.exes.push(entry);

      if (entry.encrypted) { entry.error = 'encrypted'; return null; }
      if (this.exes.length > MAX_EXES) { entry.error = 'limit_exceeded'; return null; }

      if (method === 0) {
        return { entry, mode: 'store', hasher: new Sha256(), aborted: false };
      }
      if (method === 8) {
        if (typeof DecompressionStream !== 'function') {
          entry.error = 'DecompressionStream not available';
          return null;
        }
        const ds = new DecompressionStream('deflate-raw');
        const writer = ds.writable.getWriter();
        const reader = ds.readable.getReader();
        const hasher = new Sha256();
        const ctx = { entry, mode: 'deflate', ds, writer, reader, hasher, aborted: false, readDone: null };
        ctx.readDone = (async () => {
          try {
            for (;;) {
              const { done, value } = await reader.read();
              if (done) break;
              entry.bytesDecompressed += value.length;
              if (entry.bytesDecompressed > MAX_UNCOMPRESSED_EXE) {
                entry.error = 'zip_bomb_limit';
                ctx.aborted = true;
                try { await reader.cancel(); } catch (_) {}
                break;
              }
              hasher.update(value);
            }
          } catch (e) {
            if (!entry.error) entry.error = String((e && e.message) || e);
            ctx.aborted = true;
          }
        })();
        return ctx;
      }

      entry.error = 'unsupported_method_' + method;
      return null;
    }

    async _writeCur(slice) {
      if (!this.cur || this.cur.aborted || !slice.length) return;
      if (this.cur.mode === 'store') {
        this.cur.entry.bytesDecompressed += slice.length;
        if (this.cur.entry.bytesDecompressed > MAX_UNCOMPRESSED_EXE) {
          this.cur.entry.error = 'zip_bomb_limit';
          this.cur.aborted = true;
          return;
        }
        this.cur.hasher.update(slice);
      } else {
        try {
          await this.cur.writer.write(slice);
        } catch (e) {
          if (!this.cur.entry.error) this.cur.entry.error = String((e && e.message) || e);
          this.cur.aborted = true;
        }
      }
    }

    async _finishCur() {
      const ctx = this.cur;
      this.cur = null;
      if (!ctx) return;
      if (ctx.mode === 'deflate') {
        try {
          if (ctx.aborted) await ctx.writer.abort();
          else await ctx.writer.close();
        } catch (_) {}
        await ctx.readDone;
      }
      if (!ctx.aborted && !ctx.entry.error) {
        ctx.entry.sha256 = ctx.hasher.digest();
      }
    }

    async _abortCur(reason) {
      const ctx = this.cur;
      this.cur = null;
      if (!ctx) return;
      if (!ctx.entry.error) ctx.entry.error = reason;
      ctx.aborted = true;
      if (ctx.mode === 'deflate') {
        try { await ctx.writer.abort(); } catch (_) {}
        try { await ctx.readDone; } catch (_) {}
      }
    }

    /** Feed the next raw chunk from the ZIP stream. */
    async feed(chunk) {
      if (this.aborted || this.state === 'DONE' || !chunk.length) return;
      this.totalIn += chunk.length;
      if (this.totalIn > this.maxZipBytes) {
        this.aborted = true;
        this.abortReason = 'exceeds_300mb';
        await this._abortCur('zip_exceeds_300mb');
        return;
      }

      let off = 0;
      while (off < chunk.length && this.state !== 'DONE' && !this.aborted) {
        if (this.state === 'SIG' || this.state === 'LFH' || this.state === 'META') {
          const take = Math.min(chunk.length - off, this.need - this.hdrLen);
          this.hdr.set(chunk.subarray(off, off + take), this.hdrLen);
          this.hdrLen += take;
          off += take;
          if (this.hdrLen < this.need) break;

          if (this.state === 'SIG') {
            const sig = u32(this.hdr, 0);
            if (sig === SIG_LFH) {
              this.state = 'LFH';
              this._ensureHdr(26);
            } else {
              this.state = 'DONE';
              break;
            }
          } else if (this.state === 'LFH') {
            const h = this.hdr;
            const flags = u16(h, 2);
            const method = u16(h, 4);
            const comp32 = u32(h, 14);
            const uncomp32 = u32(h, 18);
            const nameLen = u16(h, 22);
            const extraLen = u16(h, 24);
            this.lfh = { flags, method, comp32, uncomp32, nameLen, extraLen };
            if (nameLen + extraLen === 0) {
              this._enterData(new Uint8Array(0));
            } else {
              this.state = 'META';
              this._ensureHdr(nameLen + extraLen);
            }
          } else if (this.state === 'META') {
            this._enterData(this.hdr.subarray(0, this.need));
          }
        } else if (this.state === 'DATA_KNOWN') {
          const take = Math.min(chunk.length - off, this.rem);
          if (this.cur && take > 0) {
            await this._writeCur(chunk.subarray(off, off + take));
          }
          off += take;
          this.rem -= take;
          if (this.rem === 0) {
            await this._finishCur();
            this.state = 'SIG';
            this._ensureHdr(4);
          }
        } else if (this.state === 'DATA_DESC') {
          off = await this._consumeDataDesc(chunk, off);
        }
      }
    }

    _enterData(meta) {
      const { flags, method, comp32, uncomp32, nameLen, extraLen } = this.lfh;
      const name = this.decoder.decode(meta.subarray(0, nameLen));
      const extra = meta.subarray(nameLen, nameLen + extraLen);
      const { comp, uncomp } = (comp32 === 0xFFFFFFFF || uncomp32 === 0xFFFFFFFF)
        ? parseZip64Extra(extra, comp32, uncomp32)
        : { comp: comp32, uncomp: uncomp32 };

      const isExe = !name.endsWith('/') && /\.exe$/i.test(name);
      this.cur = isExe ? this._startExe(name, method, flags, comp, uncomp) : null;

      if ((flags & 0x08) !== 0 && comp === 0) {
        this.state = 'DATA_DESC';
        this.ddBuf = new Uint8Array(0);
        this.ddCompRead = 0;
      } else if (comp === 0) {
        // 0-byte entry
        this.state = 'DATA_KNOWN';
        this.rem = 0;
        // Will finish on next loop or finalize; handle immediately for 0-byte
        if (this.cur && this.cur.mode === 'store') {
          this.cur.entry.sha256 = this.cur.hasher.digest();
          this.cur = null;
        }
        if (!this.cur) {
          this.state = 'SIG';
          this._ensureHdr(4);
        }
      } else {
        this.state = 'DATA_KNOWN';
        this.rem = comp;
      }
    }

    /**
     * Handles streaming entries with general-purpose bit 3 (Data Descriptor) set.
     * Holds a 16-byte sliding tail so descriptor bytes are not fed into the decompressor.
     */
    async _consumeDataDesc(chunk, off) {
      const incoming = chunk.subarray(off);
      const buf = new Uint8Array(this.ddBuf.length + incoming.length);
      buf.set(this.ddBuf, 0);
      buf.set(incoming, this.ddBuf.length);

      // Search for Data Descriptor:
      // 1) PK\x07\x08 + crc32(4) + compSize(4) + uncompSize(4)  [16 bytes]
      //    where compSize === (this.ddCompRead + pos) >>> 0
      // 2) crc32(4) + compSize(4) + uncompSize(4) + (PK\x03\x04 | PK\x01\x02 | PK\x05\x06) [16 bytes]
      //    where compSize === (this.ddCompRead + pos) >>> 0
      let foundPos = -1, descLen = 0;
      const limit = buf.length - 16;
      for (let i = 0; i <= limit; i++) {
        if (buf[i] === 0x50 && buf[i + 1] === 0x4b && buf[i + 2] === 0x07 && buf[i + 3] === 0x08) {
          const expectedComp = (this.ddCompRead + i) >>> 0;
          if (u32(buf, i + 8) === expectedComp) {
            foundPos = i;
            descLen = 16;
            break;
          }
        }
        if (buf[i + 12] === 0x50 && buf[i + 13] === 0x4b) {
          const nextSig = u32(buf, i + 12);
          if (nextSig === SIG_LFH || nextSig === SIG_CDH || nextSig === SIG_EOCD) {
            const expectedComp = (this.ddCompRead + i) >>> 0;
            if (u32(buf, i + 4) === expectedComp) {
              foundPos = i;
              descLen = 12;
              break;
            }
          }
        }
      }

      if (foundPos >= 0) {
        if (foundPos > 0) {
          await this._writeCur(buf.subarray(0, foundPos));
          this.ddCompRead += foundPos;
        }
        if (this.cur) this.cur.entry.compressedSize = this.ddCompRead;
        await this._finishCur();
        const consumedFromIncoming = foundPos + descLen - this.ddBuf.length;
        this.ddBuf = new Uint8Array(0);
        this.ddCompRead = 0;
        this.state = 'SIG';
        this._ensureHdr(4);
        return off + Math.max(0, consumedFromIncoming);
      }

      // Not found yet: flush everything except the last 16 bytes
      if (buf.length > 16) {
        const flushLen = buf.length - 16;
        await this._writeCur(buf.subarray(0, flushLen));
        this.ddCompRead += flushLen;
        this.ddBuf = buf.slice(flushLen);
      } else {
        this.ddBuf = buf;
      }
      return chunk.length;
    }

    async finalize() {
      if (this.cur) {
        if (this.state === 'DATA_KNOWN' && this.rem === 0) await this._finishCur();
        else await this._abortCur('truncated_zip_entry');
      }
      return {
        aborted: this.aborted,
        abortReason: this.abortReason,
        exes: this.exes
      };
    }
  }

  root.ZipExeInspector = ZipExeInspector;
  root.ZIP_MAX_INSPECT_BYTES = MAX_ZIP_BYTES;
})(typeof globalThis !== 'undefined' ? globalThis : self);
