const SPECIFIC_ACTIONS = new Set([
  'login_failed',
  'login_success',
  'sqli_attempt',
  'xss_attempt',
  'request',
  'unauthorized_admin_access',
  'data_export',
  'path_traversal',
  'malicious_upload_attempt',
  'resource_deleted'
]);

const DANGEROUS_UPLOAD_EXTENSIONS = [
  'php',
  'php3',
  'php4',
  'php5',
  'phtml',
  'jsp',
  'jspx',
  'asp',
  'aspx',
  'sh',
  'bash',
  'exe',
  'dll',
  'war',
  'jar'
];

function fieldText(event) {
  const fields = [
    event.path,
    event.url,
    event.endpoint,
    event.query,
    event.payload,
    event.message,
    event.file,
    event.file_name,
    event.filename,
    event.user_agent,
    event.body && JSON.stringify(event.body)
  ];

  return fields.filter(Boolean).join(' ');
}

function hasSqlInjection(text) {
  return [
    /('|%27)\s*or\s+('|%27)?\d+('|%27)?\s*=\s*('|%27)?\d+/i,
    /\bunion\s+(all\s+)?select\b/i,
    /\bselect\b.+\bfrom\b/i,
    /\bdrop\s+table\b/i,
    /\binformation_schema\b/i,
    /(--|#|\/\*)/,
    /\b(sleep|benchmark)\s*\(/i
  ].some(pattern => pattern.test(text));
}

function hasXss(text) {
  return [
    /<\s*script\b/i,
    /javascript\s*:/i,
    /\bon(error|load|click|mouseover)\s*=/i,
    /<\s*iframe\b/i,
    /<\s*img\b[^>]+src\s*=/i,
    /\balert\s*\(/i,
    /\bdocument\.cookie\b/i
  ].some(pattern => pattern.test(text));
}

function hasPathTraversal(text) {
  return [
    /\.\.[/\\]/,
    /%2e%2e(%2f|\/|%5c|\\)/i,
    /\/etc\/passwd/i,
    /\/proc\/self\/environ/i,
    /boot\.ini/i,
    /win\.ini/i
  ].some(pattern => pattern.test(text));
}

function hasDangerousUpload(event, text) {
  const candidates = [
    event.file,
    event.file_name,
    event.filename,
    event.payload,
    event.path
  ].filter(Boolean);

  const extensionPattern = new RegExp(`\\.(${DANGEROUS_UPLOAD_EXTENSIONS.join('|')})(\\b|$)`, 'i');
  return candidates.some(value => extensionPattern.test(String(value))) ||
    /web\s*shell/i.test(text);
}

function isUnauthorizedAdminAccess(event, text) {
  const status = Number(event.status || event.status_code);
  const role = String(event.role || event.user_role || '').toLowerCase();
  const adminPath = /(^|\s|\/)(admin|api\/admin)(\/|\b)/i.test(text);
  const denied = status === 401 || status === 403 || role === 'user' || role === 'guest';

  return adminPath && denied;
}

function isDataExport(event, text) {
  const method = String(event.method || 'GET').toUpperCase();
  return method === 'GET' && /(\/export\b|\/download\b|backup|dump|\.csv\b|\.xlsx\b)/i.test(text);
}

function isMassDeletion(event) {
  return String(event.method || '').toUpperCase() === 'DELETE';
}

function inferAttackAction(event = {}) {
  const currentAction = event.action;
  if (currentAction && currentAction !== 'request' && SPECIFIC_ACTIONS.has(currentAction)) {
    return {
      action: currentAction,
      reason: 'explicit_action'
    };
  }

  const text = fieldText(event);

  if (hasDangerousUpload(event, text)) {
    return { action: 'malicious_upload_attempt', reason: 'dangerous_file_extension' };
  }

  if (hasPathTraversal(text)) {
    return { action: 'path_traversal', reason: 'path_traversal_signature' };
  }

  if (hasXss(text)) {
    return { action: 'xss_attempt', reason: 'xss_signature' };
  }

  if (hasSqlInjection(text)) {
    return { action: 'sqli_attempt', reason: 'sqli_signature' };
  }

  if (isUnauthorizedAdminAccess(event, text)) {
    return { action: 'unauthorized_admin_access', reason: 'denied_admin_endpoint' };
  }

  if (isMassDeletion(event)) {
    return { action: 'resource_deleted', reason: 'delete_method' };
  }

  if (isDataExport(event, text)) {
    return { action: 'data_export', reason: 'export_endpoint' };
  }

  return {
    action: currentAction || 'request',
    reason: currentAction ? 'explicit_action' : 'default_request'
  };
}

function normalizeSecurityEvent(event = {}) {
  const inferred = inferAttackAction(event);
  const normalized = {
    ...event,
    action: inferred.action,
    detection_reason: inferred.reason
  };

  if (event.action && event.action !== inferred.action) {
    normalized.raw_action = event.action;
  }

  return normalized;
}

module.exports = {
  inferAttackAction,
  normalizeSecurityEvent,
  DANGEROUS_UPLOAD_EXTENSIONS
};
