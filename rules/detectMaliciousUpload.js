const {
  searchRecentLogs,
  getPayloadParts,
  getActor,
  getIp,
  getResponseBytes,
  incrementCounter
} = require('./ruleUtils');

const DANGEROUS_EXTENSIONS = /\.(?:jsp|jspx|php|php[3457]?|phtml|asp|aspx|sh|bash|zsh|exe|bat|cmd|ps1|py|pl|cgi|dll|jar|war)$/i;
const DOUBLE_EXTENSION_TRICK = /\.(?:jsp|jspx|php|phtml|asp|aspx|sh|exe|bat|cmd|ps1|py|pl|cgi)\.[a-z0-9]{2,5}$/i;
const SCRIPT_MIME_TYPES = /(?:php|x-httpd-php|x-sh|x-shellscript|x-msdownload|javascript|java-archive|perl|python)/i;
const IMAGE_EXTENSION = /\.(?:jpg|jpeg|png|gif|webp|bmp)$/i;

function analyzeUpload(log) {
  const parts = getPayloadParts(log);
  const fileName = parts.filename;
  const contentType = parts.contentType;

  if (!fileName) return null;

  if (DANGEROUS_EXTENSIONS.test(fileName)) {
    return { reason: 'Executable file extension detected', fileName };
  }

  if (DOUBLE_EXTENSION_TRICK.test(fileName)) {
    return { reason: 'Double extension trick detected', fileName };
  }

  if (IMAGE_EXTENSION.test(fileName) && SCRIPT_MIME_TYPES.test(contentType)) {
    return { reason: 'MIME spoofing: image extension with script content-type', fileName };
  }

  if (SCRIPT_MIME_TYPES.test(contentType)) {
    return { reason: 'Dangerous script content-type detected', fileName };
  }

  return null;
}

async function detectMaliciousUpload(esClient, config) {
  const threshold = config.MALICIOUS_UPLOAD_THRESHOLD || 1;
  const attackers = new Map();

  try {
    const logs = await searchRecentLogs(esClient, config.MALICIOUS_UPLOAD_TIME_WINDOW || '5m');

    for (const log of logs) {
      const finding = analyzeUpload(log);
      if (!finding) continue;

      const username = getActor(log);
      incrementCounter(attackers, username, {
        username,
        ip: getIp(log),
        severity: 'CRITICAL',
        reason: finding.reason,
        fileName: finding.fileName,
        bytes: getResponseBytes(log)
      });
    }

    const results = Array.from(attackers.values()).filter(item => item.count >= threshold);
    if (results.length > 0) {
      console.log(`[detectMaliciousUpload] Phat hien ${results.length} tai khoan upload file nguy hiem`);
    }
    return results;
  } catch (err) {
    if (err?.meta?.statusCode === 404) return [];
    console.error('[detectMaliciousUpload] Loi:', err.message || err);
    return [];
  }
}

module.exports = detectMaliciousUpload;
