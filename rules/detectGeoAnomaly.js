const {
  searchRecentLogs,
  firstPresent,
  getActor,
  getIp,
  normalizeKeyword
} = require('./ruleUtils');

function isLoginSuccess(log) {
  const action = normalizeKeyword(log.action);
  return action === 'login_success' || action === 'auth_success';
}

async function detectGeoAnomaly(esClient, config) {
  try {
    const logs = await searchRecentLogs(esClient, config.GEO_ANOMALY_TIME_WINDOW || '30m', 2000);
    const byUser = new Map();

    for (const log of logs) {
      if (!isLoginSuccess(log)) continue;

      const username = getActor(log);
      const country = firstPresent(log, ['country', 'geo.country_name', 'source.geo.country_name'], '');
      if (!country) continue;

      const current = byUser.get(username) || { username, countries: new Set(), ips: new Set() };
      current.countries.add(country);
      current.ips.add(getIp(log));
      byUser.set(username, current);
    }

    const anomalies = Array.from(byUser.values())
      .filter(item => item.countries.size >= 2)
      .map(item => ({
        username: item.username,
        countries: Array.from(item.countries),
        ips: Array.from(item.ips),
        severity: 'CRITICAL'
      }));

    if (anomalies.length > 0) {
      console.log(`[detectGeoAnomaly] Phat hien ${anomalies.length} tai khoan dang nhap tu nhieu quoc gia`);
    }
    return anomalies;
  } catch (error) {
    if (error?.meta?.statusCode === 404) return [];
    console.error('[detectGeoAnomaly] Loi:', error.message || error);
    return [];
  }
}

module.exports = detectGeoAnomaly;
