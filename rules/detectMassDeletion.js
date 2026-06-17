const {
  searchRecentLogs,
  getActor,
  getMethod,
  getStatus,
  firstPresent,
  normalizeKeyword
} = require('./ruleUtils');

function isSuccessfulDelete(log) {
  const action = normalizeKeyword(log.action);
  const method = getMethod(log);
  const status = getStatus(log);

  if (action === 'resource_deleted') return true;
  return method === 'DELETE' && (status === 200 || status === 202 || status === 204 || status === 0);
}

async function detectMassDeletion(esClient, config) {
  const threshold = config.MASS_DELETION_THRESHOLD || 5;

  try {
    const logs = await searchRecentLogs(esClient, config.MASS_DELETION_TIME_WINDOW || '1m', 2000);
    const byUser = new Map();

    for (const log of logs) {
      if (!isSuccessfulDelete(log)) continue;

      const username = getActor(log);
      const current = byUser.get(username) || {
        username,
        count: 0,
        severity: 'CRITICAL',
        sampleTarget: firstPresent(log, ['request_uri', 'uri', 'path', 'url.path', 'payload'], '')
      };
      current.count += 1;
      byUser.set(username, current);
    }

    const results = Array.from(byUser.values()).filter(item => item.count >= threshold);
    if (results.length > 0) {
      console.log(`[detectMassDeletion] Phat hien ${results.length} tai khoan xoa hang loat`);
    }
    return results;
  } catch (err) {
    if (err?.meta?.statusCode === 404) return [];
    console.error('[detectMassDeletion] Loi:', err.message || err);
    return [];
  }
}

module.exports = detectMassDeletion;
