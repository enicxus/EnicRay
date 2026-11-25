# EnicRay — Pre-Download Forensic Auditor

![Manifest V3](https://img.shields.io/badge/Manifest-V3-blue?logo=googlechrome&logoColor=white)
![Chrome | Edge | Brave](https://img.shields.io/badge/Chrome%20%7C%20Edge%20%7C%20Brave-supported-success)
![Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)
![Zero Disk](https://img.shields.io/badge/disk%20writes-0-informational)
![RAM](https://img.shields.io/badge/RAM-%3C50%20MB-orange)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

**EnicRay** is an open-source browser extension that audits a remote file **before** you download it. It streams the file through an in-memory pipeline, computes its SHA-256, inspects its real structure, and renders a live "X-Ray" map — all without writing a single byte to disk and while keeping memory flat, even for packages of 200 GB or more.

## Features

- **Zero-Disk Streaming** — `fetch()` + `ReadableStream`, 1 MiB blocks, no temp files.
- **Progressive SHA-256** — local, dependency-free implementation (`lib/sha256.js`), verified by a built-in known-answer test.
- **Quick X-Ray (HTTP Range)** — samples 0 %, 25 %, 50 %, 75 % and the tail in a few seconds to expose files artificially inflated with zeros or junk.
- **Magic-byte detection** — ZIP, 7z, PE (EXE/DLL), RPF containers, RAR, GZIP, PDF, ELF, PNG; flags extension spoofing.
- **Per-block Shannon entropy** — `> 7.5` packed/encrypted, `< 0.5` fake padding.
- **Malicious API / string scanner** — `CryptUnprotectData`, `SetWindowsHookEx`, `VirtualAllocEx`, `URLDownloadToFile`, `powershell -enc`, … (ASCII and UTF-16LE), plus runtime library checks (`d3d12`, `xgameruntime`).
- **Cascade verification** — after the SHA-256 is computed: (1) local allowlist hit → *Verified Intact Signature*, red alerts suppressed; (2) otherwise a **MalwareBazaar (abuse.ch)** lookup (`POST https://mb-api.abuse.ch/api/v1/`, `query=get_info`). `query_status: "ok"` → red **MALWARE CONFIRMED** with the family name and the download is blocked; `hash_not_found` → continue with local heuristics. The lookup has a 3-second timeout; on network errors it is skipped silently. Only the SHA-256 is sent. It needs a free abuse.ch Auth-Key in `config.js` (empty = lookup disabled; do not commit your key).
- **In-memory ZIP `.exe` inspection (< 300 MB)** — if a `.zip` under 300 MB contains `.exe` entries, EnicRay decompresses each internal `.exe` on the fly using native `DecompressionStream('deflate-raw')` (zero external libraries, zero disk), computes its SHA-256, and checks it against the allowlist and MalwareBazaar.
- **Known-signature auto-detection** — every full audit is compared against an allowlist of known SHA-256 signatures (a ZIP package and a console EXE binary). A match reports an intact, unmodified file (with a warning that the console binary is not Windows-compatible). An `.exe`/`.zip` that presents itself as a game installer/package (installer-like name, or size close to a known package) but matches no signature raises a red **Modified File / Possible Malware** alert. Signatures live in `lib/signatures.js`.
- **Custom hash** — optionally paste any SHA-256 under the collapsible "Hash personalizado".
- **DOM auto-detection** — finds 64-hex SHA-256 strings and deceptive download buttons on the current page.
- **Shareable forensic report** — one click, Markdown, ready for Discord or social media.

## How Zero-Disk Streaming Works

```
 Remote server ──HTTP──▶ fetch() ──▶ response.body.getReader()
                                          │ network chunks (~64 KB)
                                          ▼
                              reusable 1 MiB block buffer  ◀── the only large allocation
                                          │ (full block)
              ┌───────────────┬───────────┴───────────┬──────────────────┐
              ▼               ▼                       ▼                  ▼
        SHA-256 state   Shannon entropy     String/import scanner   Magic bytes (block 0)
        (incremental)   (256-bin histogram)  (cross-boundary)
                                          │
                                          ▼
                       X-Ray map (512 bins) + telemetry ──▶ popup
```

1. The engine runs in an **offscreen document** (`chrome.offscreen`). MV3 service workers are suspended after ~30 s of inactivity; the offscreen document is not, and it sends a heartbeat to keep the worker responsive. Scans survive closing the popup.
2. Data is read with `getReader()`. Each network chunk is copied into a single pre-allocated 1 MiB buffer; when full, the block is hashed, measured and scanned, then **overwritten** by the next one. Nothing is accumulated, so RAM stays flat regardless of file size.
3. The SHA-256 state is 32 bytes of chaining value plus a 64-byte buffer. Total length is tracked as a double (exact up to 2^53 bytes).
4. The scanner keeps a 127-byte tail between blocks so signatures split across block boundaries are still found.
5. An `AbortController` cancels the request at any moment.
6. In **Range mode** the engine issues `Range: bytes=a-b` requests for five 1 MiB windows. The server must answer `206 Partial Content`; otherwise EnicRay tells you to use Full Audit.

### X-Ray map colours

| Colour | Meaning |
|---|---|
| Blue | Valid header (recognised magic bytes) |
| Green | Clean data |
| Yellow | High entropy (> 7.5) |
| Red | Threat string, anomaly or fake padding (entropy < 0.5) |

### Interpreting results

High entropy is **normal** for ZIP/7z/RAR containers, so it is not penalised there. String scanning sees only plain (uncompressed) content: for archives it cannot look inside compressed members. A "clean" verdict means *no anomalies were found by these heuristics*, not that a file is safe. A matching SHA-256 against a trusted reference is the strongest signal available.

## Installation (3 steps)

1. **Download / clone** this repository and keep the folder (it must contain `manifest.json`).
2. Open `chrome://extensions` (Chrome), `edge://extensions` (Edge) or `brave://extensions` (Brave) and enable **Developer mode**.
3. Click **Load unpacked** and select the `EnicRay` folder. Pin the extension for quick access.

Requires Chrome/Chromium 116 or newer (offscreen documents and `runtime.getContexts`).

## Usage

- **Paste a direct URL** and press *Iniciar Análisis*, or
- Press **Interceptar Próxima Descarga**, then start any download — EnicRay cancels it and audits the URL instead (blob:/data: URLs cannot be re-fetched), or
- Click a SHA-256 or direct link detected on the current page.

Choose **Auditoría Completa 100%** (full hash + entropy map) or **Rayos X Rápidos** (seconds, Range-capable servers only; SHA-256 not computed). Use **Copiar Reporte Forense** to share the result.

## Demo Mode (for screenshots)

At the bottom-right of the popup, **Test Demo (Simular Archivo)** offers two buttons: *limpio* (clean) and *amenaza* (threat) — plus *firma conocida* (simulated known-signature match). They feed a synthetic 128 MiB stream through the real hashing/entropy/scanner pipeline with no network access, so the X-Ray map, telemetry, and green/red verdicts can be demonstrated instantly. Demo reports are labelled `DEMO (simulated data)` and the "download anyway" button is hidden.

## Icons

Icons live in `icons/`. Regenerate them with `node tools/generate-icons.js` (pure Node, no dependencies).

## Project Structure

```
EnicRay/
├── manifest.json
├── background.js        # service worker: orchestration, download interception, state
├── offscreen.html/.js   # streaming engine (anti-suspension)
├── content.js           # page hash / trap-button detector
├── popup.html/.css/.js  # Cyber-Forensic UI
├── lib/sha256.js        # local incremental SHA-256
├── lib/forensics.js     # magic bytes, entropy, string scanner
├── lib/signatures.js    # known-signature allowlist + installer-like heuristic
├── lib/zip-inspector.js # streaming ZIP inner-.exe decompressor (DecompressionStream)
└── README.md
```

## Privacy

EnicRay has no telemetry, no remote code and no external dependencies. Files are fetched directly from the URL you provide, analysed in memory, and discarded. Preferences are stored locally via `chrome.storage`.

## Legal & Security Disclaimer

EnicRay is a **generic file-auditing and malware-prevention tool**. It verifies integrity and inspects binary structure; it does not host, redistribute, circumvent protection of, or facilitate access to any copyrighted or restricted material. The preloaded hash profiles are neutral reference values supplied for convenience and carry no endorsement of any file or source.

Use it only on content you are legally entitled to access. Heuristic analysis can produce false positives and false negatives and **does not guarantee that a file is safe**; always combine it with up-to-date endpoint protection. The software is provided "as is", without warranty of any kind; the authors accept no liability for damages arising from its use. Trademarks belong to their respective owners and are not used here.

## License

MIT
