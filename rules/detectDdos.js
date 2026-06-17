const {
  searchRecentLogs,
  getIp,
  firstPresent,
  normalizeKeyword
} = require('./ruleUtils');

function isHttpRequest(log) {
  const action = normalizeKeyword(log.action);
  return action === 'request' ||
    Boolean(firstPresent(log, ['request_uri', 'uri', 'path', 'url.path', 'http.request.method'], ''));
}

async function detectDdos(esClient, config) {
  const threshold = config.DDOS_THRESHOLD || 50;

  try {
    const logs = await searchRecentLogs(esClient, config.DDOS_TIME_WINDOW || '1m', 5000);
    const byIp = new Map();

    for (const log of logs) {
      if (!isHttpRequest(log)) continue;

      const ip = getIp(log);
      if (ip === 'unknown') continue;

      const current = byIp.get(ip) || {
        target: ip,
        ip,
        count: 0,
        severity: 'CRITICAL',
        sampleUri: firstPresent(log, ['request_uri', 'uri', 'path', 'url.path', 'payload'], '')
      };
      current.count += 1;
      byIp.set(ip, current);
    }

    const results = Array.from(byIp.values()).filter(item => item.count >= threshold);
    if (results.length > 0) {
      console.log(`[detectDdos] Phat hien ${results.length} IP flood request raw-log`);
    }
    return results;
  } catch (error) {
    if (error?.meta?.statusCode === 404) return [];
    console.error('[detectDdos] Loi:', error.message || error);
    return [];
  }
}

module.exports = detectDdos;
