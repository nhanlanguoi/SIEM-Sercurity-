const {
  searchRecentLogs,
  getPayloadParts,
  getIp,
  getActor,
  getStatus,
  getResponseBytes,
  incrementCounter
} = require('./ruleUtils');

const PATH_TRAVERSAL_SIGNATURES = [
  { name: 'directory traversal sequence', pattern: /(?:^|[/?=&\\])(?:\.\.[/\\])+?/i },
  { name: 'expanded traversal bypass', pattern: /\.\.(?:\.{2})?[/\\]{1,2}/i },
  { name: 'sensitive Unix file', pattern: /(?:^|[/\\])etc[/\\](?:passwd|shadow|hosts)\b/i },
  { name: 'sensitive Windows file', pattern: /(?:boot\.ini|win\.ini|windows[/\\]system32)/i },
  { name: 'PHP stream wrapper LFI', pattern: /\b(?:php|file|expect|zip|phar):\/\//i }
];

function normalizePathPayload(value) {
  return value
    .replace(/%c0%af/gi, '/')
    .replace(/%c1%9c/gi, '\\')
    .replace(/\.{4}[/\\]{2}/g, '../')
    .replace(/[/\\]{2,}/g, '/');
}

function evaluateSeverity(log) {
  const status = getStatus(log);
  const bytes = getResponseBytes(log);

  if (status === 200 && bytes > 0) return 'CRITICAL';
  if (status === 200) return 'HIGH';
  if (status === 403 || status === 404) return 'MEDIUM';
  return 'HIGH';
}

async function detectPathTraversal(esClient, config) {
  const threshold = config.PATH_TRAVERSAL_THRESHOLD || 1;
  const attackers = new Map();

  try {
    const logs = await searchRecentLogs(esClient, config.PATH_TRAVERSAL_TIME_WINDOW || '5m');

    for (const log of logs) {
      const parts = getPayloadParts(log);
      const payload = normalizePathPayload(`${parts.uri}\n${parts.body}`);
      const signature = PATH_TRAVERSAL_SIGNATURES.find(item => item.pattern.test(payload));

      if (!signature) continue;

      const ip = getIp(log);
      incrementCounter(attackers, ip, {
        ip,
        username: getActor(log),
        severity: evaluateSeverity(log),
        signature: signature.name,
        payload: payload.slice(0, 300)
      });
    }

    const results = Array.from(attackers.values()).filter(item => item.count >= threshold);
    if (results.length > 0) {
      console.log(`[detectPathTraversal] Phat hien ${results.length} IP co payload Path Traversal raw-log`);
    }
    return results;
  } catch (err) {
    if (err?.meta?.statusCode === 404) return [];
    console.error('[detectPathTraversal] Loi:', err.message || err);
    return [];
  }
}

module.exports = detectPathTraversal;
