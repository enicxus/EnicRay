/*
 * EnicRay - Reference allowlist (SHA-256) and campaign-impersonation keyword check.
 */
(function (root) {
  'use strict';

  const LIST = [
    {
      sha: '7545a2f7fb4b399cf8850987f087ed9a4d8499ddb6d6c2d642fd60c27f569730',
      kind: 'zip', approx: 57e6, label: 'Paquete ZIP original (~57 MB)'
    },
    {
      sha: 'e95020b2fa4a721db3df59fdecf75621730ac559d8835252f6c3b658d5a08993',
      kind: 'exe', approx: 114e6, label: 'Binario EXE original (~114 MB)'
    }
  ];

  const SUSPICIOUS_KW = /(cyberleek|leak|build|xbox-port)/i;

  function find(sha) {
    return sha ? (LIST.find(s => s.sha === sha.toLowerCase()) || null) : null;
  }

  function hasSuspiciousKeyword(fileName, url) {
    return SUSPICIOUS_KW.test(fileName || '') || SUSPICIOUS_KW.test(url || '');
  }

  root.Signatures = { LIST, find, hasSuspiciousKeyword };
})(typeof globalThis !== 'undefined' ? globalThis : self);
