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
async function sendAlert(key, title, detail, recommendation) {
  const dedupKey = `alerted:${key}`;
  const alreadyAlerted = await redisClient.get(dedupKey);

  if (!alreadyAlerted) {
    console.log(`\n\ud83d\udea8 [CANH BAO] ${title}`);
    console.log(`   Chi tiet : ${detail}`);
    console.log(`   Khuyen nghi: ${recommendation}`);

    // Ghi vao alerts.log de Kibana hien thi
    writeAlertLog(title, detail, recommendation);

    // Luu vao Redis de tranh gui canh bao trung lap trong 1 gio
    await redisClient.set(dedupKey, '1', { EX: 3600 });

    const message =
      `\ud83d\udea8 *CANH BAO AN NINH: ${title}*\n` +
      `\ud83d\udccc Chi tiet: ${detail}\n` +
      `\ud83d\udee1\ufe0f Khuyen nghi: ${recommendation}`;
    await notifier.sendTelegram(message, config);
  }
}

async function runAllRules() {
  try {
    // ── Rule 1: Brute Force (dam nhap sai nhieu lan) ──────────────────
    const bruteForceAttackers = await detectBruteForce(esClient, config);
    for (const username of bruteForceAttackers) {
      await sendAlert(
        `brute:${username}`,
        'Brute Force Attack',
        `Tai khoan "${username}" dang nhap sai qua ${config.BRUTE_FORCE_THRESHOLD} lan trong ${config.BRUTE_FORCE_TIME_WINDOW}.`,
        `Khoa tai khoan "${username}" tren he thong cua ban va yeu cau doi mat khau ngay.`
      );
    }

    // ── Rule 2: SQL Injection ──────────────────────────────────────────
    const sqliAttackers = await detectSqlInjection(esClient, config);
    for (const username of sqliAttackers) {
      await sendAlert(
        `sqli:${username}`,
        'SQL Injection Attempt',
        `Tai khoan "${username}" gui payload SQL doc hai ${config.SQLI_THRESHOLD}+ lan.`,
        `Kiem tra va viec thi input validation/sanitization o moi endpoint nhan du lieu tu user. Xem xet cha${username}.`
      );
    }

    // ── Rule 3: XSS ────────────────────────────────────────────────────
    const xssAttackers = await detectXss(esClient, config);
    for (const username of xssAttackers) {
      await sendAlert(
        `xss:${username}`,
        'Cross-Site Scripting (XSS)',
        `Tai khoan "${username}" chen script doc hai ${config.XSS_THRESHOLD}+ lan.`,
        `Kiem tra va bat buoc encode tat ca output HTML. Xem xet vhoa tai khoan "${username}".`
      );
    }

    // ── Rule 4: DDoS / Flood ───────────────────────────────────────────
    const ddosDevices = await detectDdos(esClient, config);
    for (const { target, count } of ddosDevices) {
      await sendAlert(
        `ddos:${target}`,
        'DDoS / Flood Attack',
        `Thiet bi "${target}" da gui ${count} request trong ${config.DDOS_TIME_WINDOW} (nguong: ${config.DDOS_THRESHOLD}).`,
        `Bat Rate Limiting tren CDN/Firewall/API Gateway cua ban. Lien he ISP neu can block IP nguon.`
      );
    }

    // ── Rule 5: Privilege Escalation ──────────────────────────────────
    const privEscAttackers = await detectPrivEsc(esClient, config);
    for (const username of privEscAttackers) {
      await sendAlert(
        `privesc:${username}`,
        'Privilege Escalation Attempt',
        `Tai khoan "${username}" co truy cap vao API cua Admin nhieu lan.`,
        `Thu hoi token/session cua "${username}" ngay. Kiem tra quyen truy cap va audit log.`
      );
    }

    // ── Rule 6: Geo Anomaly (Impossible Travel) ────────────────────────
    const geoAnomalies = await detectGeoAnomaly(esClient, config);
    for (const { username, countries } of geoAnomalies) {
      await sendAlert(
        `geo:${username}`,
        'Impossible Travel / Geo Anomaly',
        `Tai khoan "${username}" dang nhap tu ${countries.join(' va ')} trong ${config.GEO_ANOMALY_TIME_WINDOW}. Khong the di chuyen nhanh nhu vay!`,
        `Buoc dang xuat tat ca phien cua "${username}" ngay. Yeu cau xac thuc 2 buoc (2FA). Co the tai khoan da bi chiem doat.`
      );
    }

    // ── Rule 7: Data Exfiltration ──────────────────────────────────────
    const exfilUsers = await detectDataExfil(esClient, config);
    for (const { username, count } of exfilUsers) {
      await sendAlert(
        `exfil:${username}`,
        'Data Exfiltration Detected',
        `Tai khoan "${username}" da export/download du lieu ${count} lan trong ${config.DATA_EXFIL_TIME_WINDOW}.`,
        `Kiem tra audit log ngay. Vo hieu hoa tinh nang export tam thoi. Xem xet tai khoan "${username}" co bi lo lo khong.`
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
  console.log(`📋 Quy tac giam sat: 7 rules dang hoat dong`);
  console.log('');

  // Chay quet moi 5 giay
  cron.schedule('*/5 * * * * *', runAllRules);
}

startEngine();
