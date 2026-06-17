const { Client } = require('@elastic/elasticsearch');
const cron = require('node-cron');
const redis = require('redis');
const fs = require('fs');
const config = require('./config');

// Import tat ca 10 rule
const detectBruteForce = require('./rules/detectBruteForce');
const detectSqlInjection = require('./rules/detectSqlInjection');
const detectXss = require('./rules/detectXss');
const detectDdos = require('./rules/detectDdos');
const detectPrivEsc = require('./rules/detectPrivEsc');
const detectGeoAnomaly = require('./rules/detectGeoAnomaly');
const detectDataExfil = require('./rules/detectDataExfil');
const detectPathTraversal = require('./rules/detectPathTraversal');
const detectMaliciousUpload = require('./rules/detectMaliciousUpload');
const detectMassDeletion = require('./rules/detectMassDeletion');

const notifier = require('./services/notifier');
const { executeAutoResponse } = require('./services/autoResponder');

// Ghi alert ra file JSON de Filebeat doc va day len Kibana
function writeAlertLog(title, detail, recommendation, severity = 'HIGH') {
  const alert = {
    '@timestamp': new Date().toISOString(),
    app: 'siem-engine',
    type: 'siem_alert',
    severity: severity,
    alert_title: title,
    alert_detail: detail,
    recommendation: recommendation
  };
  fs.appendFileSync('./alerts.log', JSON.stringify(alert) + '\n');
}

// Khoi tao ket noi Elasticsearch
const esClient = new Client({ node: config.ELASTIC_URL });

// Khoi tao ket noi Redis
const redisClient = redis.createClient({ url: config.REDIS_URL });
redisClient.on('error', (err) => console.error('Redis Client Error', err));

// -------------------------------------------------------
// Ham gui canh bao (chi canh bao, KHONG block/khoa user)
// Redis duoc dung de chong spam canh bao (deduplication)
// SIEM hoan toan dung ngoai, khong can thiep vao he thong goc
// -------------------------------------------------------
async function sendAlert(key, title, detail, recommendation, severity = 'HIGH', incident = {}) {
  const dedupKey = `alerted:${key}`;
  const alreadyAlerted = await redisClient.get(dedupKey);

  if (!alreadyAlerted) {
    console.log(`\n🚨 [CANH BAO] ${title}`);
    console.log(`   Muc do   : ${severity}`);
    console.log(`   Chi tiet : ${detail}`);
    console.log(`   Khuyen nghi: ${recommendation}`);

    // Ghi vao alerts.log de Kibana hien thi
    writeAlertLog(title, detail, recommendation, severity);

    // Luu vao Redis de tranh gui canh bao trung lap trong 1 gio
    await redisClient.set(dedupKey, '1', { EX: 3600 });

    const message =
      `🚨 CANH BAO AN NINH: ${title}\n` +
      `⚠️ Muc do: ${severity}\n` +
      `📌 Chi tiet: ${detail}\n` +
      `🛡️ Khuyen nghi: ${recommendation}`;
    await notifier.sendTelegram(message, config);
    await executeAutoResponse(config, {
      ...incident,
      title,
      detail,
      recommendation
    });
  }
}

function asAlertObject(value, fallbackKey) {
  if (typeof value === 'string') {
    return { username: value, key: `${fallbackKey}:${value}`, count: 1, severity: 'HIGH' };
  }

  return {
    ...value,
    key: value?.key || `${fallbackKey}:${value?.username || value?.ip || value?.target || 'unknown'}`,
    severity: value?.severity || 'HIGH'
  };
}

async function runAllRules() {
  try {
    // ── Rule 1: Brute Force / Password Spraying ───────────────────────
    const bruteForceAttackers = await detectBruteForce(esClient, config);
    for (const item of bruteForceAttackers.map(value => asAlertObject(value, 'brute'))) {
      await sendAlert(
        item.key,
        item.attackType || 'Brute Force Attack',
        `Doi tuong "${item.username}" co ${item.count} su kien dang nhap bat thuong trong ${config.BRUTE_FORCE_TIME_WINDOW}.`,
        'Kiem tra IP/username lien quan, bat MFA, reset mat khau neu co login_success sau chuoi that bai.',
        item.severity,
        { rule: 'brute_force', targetType: 'username', target: item.username || item.ip }
      );
    }

    // ── Rule 2: SQL Injection tu raw payload ───────────────────────────
    const sqliAttackers = await detectSqlInjection(esClient, config);
    for (const item of sqliAttackers.map(value => asAlertObject(value, 'sqli'))) {
      await sendAlert(
        item.key,
        'SQL Injection Attempt',
        `Tai khoan/IP "${item.username || item.ip}" gui payload khop ${item.signature}: ${item.payload}`,
        'Dung prepared statement/ORM parameter binding, validate input va kiem tra endpoint tra HTTP 2xx voi response lon.',
        item.severity,
        { rule: 'sqli', targetType: item.username ? 'username' : 'ip', target: item.username || item.ip }
      );
    }

    // ── Rule 3: XSS tu raw payload ─────────────────────────────────────
    const xssAttackers = await detectXss(esClient, config);
    for (const item of xssAttackers.map(value => asAlertObject(value, 'xss'))) {
      await sendAlert(
        item.key,
        'Cross-Site Scripting (XSS)',
        `${item.xssType || 'XSS attempt'} tu "${item.username}" khop ${item.signature}: ${item.payload}`,
        'Encode output theo context HTML/JS/URL, sanitize rich text, va kiem tra Stored XSS neu payload nam trong body POST/PUT.',
        item.severity,
        { rule: 'xss', targetType: 'username', target: item.username }
      );
    }

    // ── Rule 4: DDoS / Flood theo IP ───────────────────────────────────
    const ddosDevices = await detectDdos(esClient, config);
    for (const item of ddosDevices.map(value => asAlertObject(value, 'ddos'))) {
      await sendAlert(
        item.key,
        'DDoS / Flood Attack',
        `IP "${item.target || item.ip}" da gui ${item.count} request trong ${config.DDOS_TIME_WINDOW}. Mau URI: ${item.sampleUri || 'N/A'}.`,
        'Bat rate limit tren CDN/WAF/API Gateway va dua IP vuot nguong vao danh sach chan tam thoi.',
        item.severity,
        { rule: 'ddos', targetType: 'ip', target: item.target || item.ip }
      );
    }

    // ── Rule 5: Privilege Escalation theo context ──────────────────────
    const privEscAttackers = await detectPrivEsc(esClient, config);
    for (const item of privEscAttackers.map(value => asAlertObject(value, 'privesc'))) {
      await sendAlert(
        item.key,
        'Privilege Escalation Attempt',
        `Tai khoan "${item.username}" truy cap endpoint dac quyen ${item.count} lan. URI: ${item.uri || 'N/A'}, HTTP ${item.status || 'N/A'}.`,
        'Kiem tra RBAC tren endpoint admin, thu hoi session/token nghi ngo va audit cac request 2xx.',
        item.severity,
        { rule: 'privilege_escalation', targetType: 'username', target: item.username }
      );
    }

    // ── Rule 6: Geo Anomaly (Impossible Travel) ────────────────────────
    const geoAnomalies = await detectGeoAnomaly(esClient, config);
    for (const item of geoAnomalies.map(value => asAlertObject(value, 'geo'))) {
      await sendAlert(
        item.key,
        'Impossible Travel / Geo Anomaly',
        `Tai khoan "${item.username}" dang nhap tu ${item.countries.join(' va ')} trong ${config.GEO_ANOMALY_TIME_WINDOW}.`,
        'Buoc dang xuat tat ca phien, yeu cau MFA va xac minh IP/country voi nguoi dung.',
        item.severity,
        { rule: 'geo_anomaly', targetType: 'username', target: item.username }
      );
    }

    // ── Rule 7: Data Exfiltration theo volume ──────────────────────────
    const exfilUsers = await detectDataExfil(esClient, config);
    for (const item of exfilUsers.map(value => asAlertObject(value, 'exfil'))) {
      await sendAlert(
        item.key,
        'Data Exfiltration Detected',
        `Tai khoan "${item.username}" tai/xuat du lieu ${item.count} lan, tong ${item.downloadedMb || 0} MB trong ${config.DATA_EXFIL_TIME_WINDOW}.`,
        'Kiem tra endpoint nhay cam, gioi han export/download va xac minh tai khoan co bi chiem doat khong.',
        item.severity,
        { rule: 'data_exfiltration', targetType: 'username', target: item.username }
      );
    }

    // ── Rule 8: Path Traversal tu raw payload ──────────────────────────
    const pathTraversalIPs = await detectPathTraversal(esClient, config);
    for (const item of pathTraversalIPs.map(value => asAlertObject(value, 'lfi'))) {
      await sendAlert(
        item.key,
        'LFI / Path Traversal Attempt',
        `IP "${item.ip}" gui payload path traversal ${item.count} lan, khop ${item.signature}: ${item.payload}`,
        'Canonicalize path truoc khi doc file, gioi han root directory va chan cac request ../ hoac file he thong.',
        item.severity,
        { rule: 'path_traversal', targetType: 'ip', target: item.ip }
      );
    }

    // ── Rule 9: Malicious Upload theo metadata ─────────────────────────
    const uploadAttackers = await detectMaliciousUpload(esClient, config);
    for (const item of uploadAttackers.map(value => asAlertObject(value, 'upload'))) {
      await sendAlert(
        item.key,
        'Malicious Upload Attempt',
        `Tai khoan "${item.username}" tai file nghi doc hai "${item.fileName}" (${item.reason}).`,
        'Quarantine/xoa file vua upload, kiem tra MIME/magic bytes va khong cho thuc thi trong thu muc upload.',
        item.severity,
        { rule: 'malicious_upload', targetType: 'username', target: item.username }
      );
    }

    // ── Rule 10: Mass Deletion ─────────────────────────────────────────
    const massDeleters = await detectMassDeletion(esClient, config);
    for (const item of massDeleters.map(value => asAlertObject(value, 'deletion'))) {
      await sendAlert(
        item.key,
        'Mass Deletion (Ransomware/Phá hoại)',
        `Tai khoan "${item.username}" da xoa ${item.count} tai nguyen trong ${config.MASS_DELETION_TIME_WINDOW}. Mau target: ${item.sampleTarget || 'N/A'}.`,
        'Tam khoa quyen WRITE/DELETE, kiem tra audit log va khoi phuc du lieu tu backup neu can.',
        item.severity,
        { rule: 'mass_deletion', targetType: 'username', target: item.username }
      );
    }

  } catch (error) {
    console.error('Loi khi chay SIEM scan:', error.message);
  }
}

async function startEngine() {
  await redisClient.connect();
  console.log('');
  console.log('╔══════════════════════════════════════════════════╗');
  console.log('║        🛡️  SIEM ENGINE v3.0 — STARTED            ║');
  console.log('║   Giam sat & Canh bao — Khong can thiep he thong  ║');
  console.log('╚══════════════════════════════════════════════════╝');
  console.log(`📡 Elasticsearch : ${config.ELASTIC_URL}`);
  console.log(`💾 Redis         : ${config.REDIS_URL}`);
  console.log(`⏱️  Quet log      : moi 5 giay`);
  console.log(`📋 Quy tac giam sat: 10 rules dang hoat dong`);
  console.log('');

  // Chay quet moi 5 giay
  cron.schedule('*/5 * * * * *', runAllRules);
}

startEngine();
