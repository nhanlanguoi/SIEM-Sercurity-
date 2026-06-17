const {
  searchRecentLogs,
  getPayloadParts,
  getActor,
  getIp,
  getMethod,
  getStatus,
  incrementCounter
} = require('./ruleUtils');

const XSS_SIGNATURES = [
  { name: 'executable HTML tag', pattern: /<(?:script|iframe|object|embed|applet|svg|math)\b/i },
  { name: 'event handler injection', pattern: /\bon[a-z]+\s*=\s*(?:"|'|`|[^\s>]+)/i },
  { name: 'javascript pseudo-protocol', pattern: /\b(?:javascript|vbscript|data:text\/html)\s*:/i },
  { name: 'dangerous DOM sink', pattern: /\b(?:alert|prompt|confirm|document\.cookie|eval)\s*\(/i }
];

function classifyXss(log, parts) {
  const method = getMethod(log);
  const status = getStatus(log);
  const uriHasPayload = XSS_SIGNATURES.some(item => item.pattern.test(parts.uri));
  const bodyHasPayload = XSS_SIGNATURES.some(item => item.pattern.test(parts.body));

  if ((method === 'POST' || method === 'PUT' || method === 'PATCH') && bodyHasPayload && (status === 200 || status === 201 || status === 0)) {
    return { type: 'Stored XSS candidate', severity: 'CRITICAL' };
  }

  if ((method === 'GET' || uriHasPayload) && status < 400) {
    return { type: 'Reflected XSS candidate', severity: 'HIGH' };
  }

  return { type: 'XSS attempt', severity: status >= 400 ? 'MEDIUM' : 'HIGH' };
}

async function detectXss(esClient, config) {
  const threshold = config.XSS_THRESHOLD || 1;
  const results = new Map();

  try {
    const logs = await searchRecentLogs(esClient, config.XSS_TIME_WINDOW || '5m');

    for (const log of logs) {
      const parts = getPayloadParts(log);
      const payload = `${parts.uri}\n${parts.body}`;
      const signature = XSS_SIGNATURES.find(item => item.pattern.test(payload));

      if (!signature) continue;

      const actor = getActor(log);
      const context = classifyXss(log, parts);
      incrementCounter(results, actor, {
        username: actor,
        ip: getIp(log),
        severity: context.severity,
        xssType: context.type,
        signature: signature.name,
        payload: payload.slice(0, 300)
      });
    }

    const attackers = Array.from(results.values()).filter(item => item.count >= threshold);
    if (attackers.length > 0) {
      console.log(`[detectXss] Phat hien ${attackers.length} doi tuong co payload XSS raw-log`);
    }
    return attackers;
  } catch (error) {
    if (error?.meta?.statusCode === 404) return [];
    console.error('[detectXss] Loi:', error.message || error);
    return [];
  }
}

module.exports = detectXss;
