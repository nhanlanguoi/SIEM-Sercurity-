const {
  searchRecentLogs,
  getActor,
  getMethod,
  getStatus,
  getResponseBytes,
  firstPresent,
  normalizeKeyword
} = require('./ruleUtils');

const SENSITIVE_ENDPOINT = /\/api\/(?:users|customers|reports|exports?|files|backup|admin|orders|payments)/i;

function isReadLikeRequest(log) {
  const method = getMethod(log);
  const action = normalizeKeyword(log.action);
  const uri = firstPresent(log, ['request_uri', 'uri', 'path', 'url.path', 'payload'], '');

  return action === 'data_export' ||
    method === 'GET' ||
    (method === 'POST' && /search|export|download|report/i.test(uri));
}

async function detectDataExfil(esClient, config) {
  const byteThreshold = config.DATA_EXFIL_BYTES_THRESHOLD || (500 * 1024 * 1024);
  const countThreshold = config.DATA_EXFIL_THRESHOLD || 5;

  try {
    const logs = await searchRecentLogs(esClient, config.DATA_EXFIL_TIME_WINDOW || '5m', 3000);
    const byUser = new Map();

    for (const log of logs) {
      if (!isReadLikeRequest(log)) continue;

      const status = getStatus(log);
      if (status && status !== 200) continue;

      const username = getActor(log);
      if (!username || username === 'anonymous') continue;

      const uri = firstPresent(log, ['request_uri', 'uri', 'path', 'url.path', 'payload'], '');
      const bytes = getResponseBytes(log);
      const action = normalizeKeyword(log.action);
      const trackByCountFallback = action === 'data_export';

      if (bytes <= 0 && !trackByCountFallback) continue;
      if (bytes > 0 && uri && !SENSITIVE_ENDPOINT.test(uri)) continue;

      const current = byUser.get(username) || {
        username,
        count: 0,
        totalBytes: 0,
        severity: 'HIGH',
        sampleUri: uri
      };
      current.count += 1;
      current.totalBytes += bytes;
      byUser.set(username, current);
    }

    const results = Array.from(byUser.values())
      .filter(item => item.totalBytes >= byteThreshold || item.count >= countThreshold)
      .map(item => ({
        ...item,
        severity: item.totalBytes >= byteThreshold ? 'CRITICAL' : 'HIGH',
        downloadedMb: Number((item.totalBytes / (1024 * 1024)).toFixed(2))
      }));

    if (results.length > 0) {
      console.log(`[detectDataExfil] Phat hien ${results.length} tai khoan tai du lieu bat thuong`);
    }
    return results;
  } catch (error) {
    if (error?.meta?.statusCode === 404) return [];
    console.error('[detectDataExfil] Loi:', error.message || error);
    return [];
  }
}

module.exports = detectDataExfil;
