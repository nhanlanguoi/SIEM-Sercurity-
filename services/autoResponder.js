const fs = require('fs');

const RESPONSE_ACTIONS = {
  brute_force: 'lock_account_temporarily',
  sqli: 'increase_waf_scrutiny',
  xss: 'increase_waf_scrutiny',
  ddos: 'block_or_rate_limit_ip',
  privilege_escalation: 'revoke_session',
  geo_anomaly: 'force_logout_and_require_mfa',
  data_exfiltration: 'disable_export_temporarily',
  path_traversal: 'block_ip_and_enable_path_rules',
  malicious_upload: 'quarantine_uploaded_file',
  mass_deletion: 'suspend_write_delete_permissions'
};

function writeResponseLog(config, response) {
  const logPath = config.RESPONSE_LOG_PATH || './responses.log';
  fs.appendFileSync(logPath, JSON.stringify(response) + '\n');
}

async function executeAutoResponse(config, incident) {
  const mode = config.AUTO_RESPONSE_MODE || 'simulate';
  if (mode === 'off') {
    return null;
  }

  const response = {
    '@timestamp': new Date().toISOString(),
    app: 'siem-engine',
    type: 'auto_response',
    mode,
    rule: incident.rule,
    target_type: incident.targetType,
    target: incident.target,
    alert_title: incident.title,
    response_action: incident.responseAction || RESPONSE_ACTIONS[incident.rule] || 'manual_review',
    status: mode === 'simulate' ? 'simulated' : 'pending_integration',
    detail: mode === 'simulate'
      ? 'Safe simulation only. No external account, firewall, or file operation was executed.'
      : 'Integration hook reached. Add firewall/backend connector before enabling real enforcement.'
  };

  writeResponseLog(config, response);
  console.log(`[autoResponder] ${response.status}: ${response.response_action} -> ${response.target}`);
  return response;
}

module.exports = {
  executeAutoResponse,
  RESPONSE_ACTIONS
};
