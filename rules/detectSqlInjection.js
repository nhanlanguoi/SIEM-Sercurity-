const {
  searchRecentLogs,
  getPayloadParts,
  getActor,
  getIp,
  getStatus,
  getResponseBytes,
  incrementCounter
} = require('./ruleUtils');

const SQLI_SIGNATURES = [
  { name: 'boolean-based SQLi', pattern: /(?:'|"|%27|%22)?\s*(?:or|and)\s+['"]?\d+['"]?\s*=\s*['"]?\d+/i },
  { name: 'UNION SELECT SQLi', pattern: /\bunion\s+(?:all\s+)?select\b/i },
  { name: 'time-based SQLi', pattern: /\b(?:sleep\s*\(|benchmark\s*\(|waitfor\s+delay|pg_sleep\s*\()/i },
  { name: 'stacked query SQLi', pattern: /;\s*(?:drop|insert|update|delete|select|exec)\b/i },
  { name: 'SQL comment injection', pattern: /(?:--|#|\/\*)\s*$/i },
  { name: 'metadata extraction', pattern: /\b(?:information_schema|sysobjects|sqlite_master)\b/i }
];

function evaluateSeverity(log) {
  const status = getStatus(log);
  const bytes = getResponseBytes(log);

  if (status >= 200 && status < 300 && bytes > 5000) return 'CRITICAL';
  if (status >= 500) return 'MEDIUM';
  if (status >= 200 && status < 300) return 'HIGH';
  return 'MEDIUM';
}

async function detectSqlInjection(esClient, config) {
  const threshold = config.SQLI_THRESHOLD || 1;
  const results = new Map();

  try {
    const logs = await searchRecentLogs(esClient, config.SQLI_TIME_WINDOW || '5m');

    for (const log of logs) {
      const parts = getPayloadParts(log);
      const payload = `${parts.uri}\n${parts.body}`;
      const signature = SQLI_SIGNATURES.find(item => item.pattern.test(payload));

      if (!signature) continue;

      const actor = getActor(log);
      const entry = incrementCounter(results, actor, {
        username: actor,
        ip: getIp(log),
        severity: evaluateSeverity(log),
        signature: signature.name,
        payload: payload.slice(0, 300)
      });

      if (entry.severity !== 'CRITICAL' && evaluateSeverity(log) === 'CRITICAL') {
        entry.severity = 'CRITICAL';
      }
    }

    const attackers = Array.from(results.values()).filter(item => item.count >= threshold);
    if (attackers.length > 0) {
      console.log(`[detectSqlInjection] Phat hien ${attackers.length} doi tuong co payload SQLi raw-log`);
    }
    return attackers;
  } catch (error) {
    if (error?.meta?.statusCode === 404) return [];
    console.error('[detectSqlInjection] Loi:', error.message || error);
    return [];
  }
}

module.exports = detectSqlInjection;
