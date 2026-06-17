const {
  searchRecentLogs,
  firstPresent,
  getActor,
  getIp,
  normalizeKeyword
} = require('./ruleUtils');

function isLoginFailure(log) {
  const action = normalizeKeyword(log.action);
  const status = Number(firstPresent(log, ['http_status', 'http.status_code', 'status'], 0));
  const uri = normalizeKeyword(firstPresent(log, ['request_uri', 'uri', 'path', 'url.path', 'payload'], ''));

  return action === 'login_failed' ||
    action === 'auth_failed' ||
    (uri.includes('/login') && (status === 401 || status === 403));
}

function isLoginSuccess(log) {
  const action = normalizeKeyword(log.action);
  const status = Number(firstPresent(log, ['http_status', 'http.status_code', 'status'], 0));
  const uri = normalizeKeyword(firstPresent(log, ['request_uri', 'uri', 'path', 'url.path', 'payload'], ''));

  return action === 'login_success' ||
    action === 'auth_success' ||
    (uri.includes('/login') && status >= 200 && status < 300);
}

async function detectBruteForce(esClient, config) {
  const threshold = config.BRUTE_FORCE_THRESHOLD || 5;

  try {
    const logs = await searchRecentLogs(esClient, config.BRUTE_FORCE_TIME_WINDOW || '1m', 2000);
    const byUser = new Map();
    const byIp = new Map();
    const successes = [];

    for (const log of logs) {
      const username = getActor(log);
      const ip = getIp(log);

      if (isLoginFailure(log)) {
        byUser.set(username, (byUser.get(username) || 0) + 1);
        byIp.set(ip, (byIp.get(ip) || { count: 0, users: new Set() }));
        byIp.get(ip).count += 1;
        byIp.get(ip).users.add(username);
      }

      if (isLoginSuccess(log)) {
        successes.push({ username, ip });
      }
    }

    const findings = [];

    for (const [username, count] of byUser.entries()) {
      if (count >= threshold) {
        const compromised = successes.some(item => item.username === username);
        findings.push({
          username,
          count,
          severity: compromised ? 'CRITICAL' : 'HIGH',
          attackType: compromised ? 'Compromised account after brute force' : 'Brute force by username'
        });
      }
    }

    for (const [ip, data] of byIp.entries()) {
      if (data.users.size >= threshold && data.count >= threshold) {
        findings.push({
          username: `ip:${ip}`,
          ip,
          count: data.count,
          severity: 'HIGH',
          attackType: 'Password spraying by source IP',
          affectedUsers: Array.from(data.users).slice(0, 10)
        });
      }
    }

    if (findings.length > 0) {
      console.log(`[detectBruteForce] Phat hien ${findings.length} brute force/password spraying raw-log`);
    }
    return findings;
  } catch (error) {
    if (error?.meta?.statusCode === 404) return [];
    console.error('[detectBruteForce] Loi:', error.message || error);
    return [];
  }
}

module.exports = detectBruteForce;
