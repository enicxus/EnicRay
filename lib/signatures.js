/*
 * EnicRay - Known-signature allowlist (SHA-256) and "installer-like" heuristic.
 * Labels are intentionally neutral.
 */
(function (root) {
  'use strict';

  const LIST = [
    {
      sha: '7545a2f7fb4b399cf8850987f087ed9a4d8499ddb6d6c2d642fd60c27f569730',
      kind: 'zip', approx: 57e6, label: 'Paquete ZIP conocido (~57 MB)'
    },
    {
      sha: 'e95020b2fa4a721db3df59fdecf75621730ac559d8835252f6c3b658d5a08993',
      kind: 'exe', approx: 114e6, label: 'Binario EXE de consola conocido (~114 MB)'
    }
  ];

  const NAME_HINT = /(setup|install|game|launcher|crack|patch|repack|win64)/i;
  const MIN_HINT_SIZE = 10e6;
  const SIZE_TOLERANCE = 0.2;

  function find(sha) {
    return sha ? (LIST.find(s => s.sha === sha.toLowerCase()) || null) : null;
  }

  /** True for .exe/.zip payloads that present themselves as a game installer/package. */
  function looksLikeInstaller(o) {
    const isExe = o.fmt === 'PE' || o.ext === 'exe' || o.ext === 'msi';
    const isZip = o.fmt === 'ZIP' || o.ext === 'zip';
    if (!isExe && !isZip) return false;
    if (o.size >= MIN_HINT_SIZE && NAME_HINT.test(o.fileName || '')) return true;
    return LIST.some(s => ((isExe && s.kind === 'exe') || (isZip && s.kind === 'zip')) &&
      Math.abs(o.size - s.approx) / s.approx <= SIZE_TOLERANCE);
  }

  root.Signatures = { LIST, find, looksLikeInstaller };
})(typeof globalThis !== 'undefined' ? globalThis : self);
