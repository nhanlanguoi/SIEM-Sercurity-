const {
  searchRecentLogs,
  firstPresent,
  getActor,
  getIp,
  getStatus,
  incrementCounter,
  normalizeKeyword
} = require('./ruleUtils');

const ADMIN_ENDPOINT = /\/(?:api\/)?(?:admin|management|internal|actuator)\b/i;

function rolesContainAdmin(log) {
  const roles = firstPresent(log, ['roles', 'user.roles', 'authorities', 'role'], []);
  const roleText = Array.isArray(roles) ? roles.join(',') : String(roles || '');
  return /admin|root|superuser/i.test(roleText);
}

async function detectPrivEsc(esClient, config) {
  const threshold = config.PRIV_ESC_THRESHOLD || 2;
  const attackers = new Map();

  try {
    const logs = await searchRecentLogs(esClient, config.PRIV_ESC_TIME_WINDOW || '5m');

    for (const log of logs) {
      const action = normalizeKeyword(log.action);
      const uri = firstPresent(log, ['request_uri', 'uri', 'path', 'url.path', 'payload'], '');
      const isAdminTarget = ADMIN_ENDPOINT.test(uri);
      const unauthorizedAction = action === 'unauthorized_admin_access';

      if (!unauthorizedAction && (!isAdminTarget || rolesContainAdmin(log))) continue;

      const username = getActor(log);
      const status = getStatus(log);
      const severity = status >= 200 && status < 300 ? 'CRITICAL' : 'MEDIUM';
      incrementCounter(attackers, username, {
        username,
        ip: getIp(log),
        severity,
        uri,
        status
      });
    }

    const results = Array.from(attackers.values()).filter(item => item.count >= threshold);
    if (results.length > 0) {
      console.log(`[detectPrivEsc] Phat hien ${results.length} tai khoan co dau hieu leo thang dac quyen`);
    }
    return results;
  } catch (error) {
    if (error?.meta?.statusCode === 404) return [];
    console.error('[detectPrivEsc] Loi:', error.message || error);
    return [];
  }
}

module.exports = detectPrivEsc;
