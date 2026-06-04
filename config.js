require('dotenv').config();

module.exports = {
  ELASTIC_URL: process.env.ELASTIC_URL || 'http://localhost:9200',
  REDIS_URL: process.env.REDIS_URL || 'redis://localhost:6379',
  TELEGRAM_BOT_TOKEN: process.env.TELEGRAM_BOT_TOKEN || 'YOUR_BOT_TOKEN',
  TELEGRAM_CHAT_ID: process.env.TELEGRAM_CHAT_ID || 'YOUR_CHAT_ID',
  CHECK_INTERVAL_MS: 5000,
  
  // Ngưỡng báo động Brute Force (Theo Username/Device ID)
  BRUTE_FORCE_THRESHOLD: 5,
  BRUTE_FORCE_TIME_WINDOW: '1m',

  // Ngưỡng báo động SQLi (Thường chỉ cần 1-2 lần là báo động)
  SQLI_THRESHOLD: 2,
  SQLI_TIME_WINDOW: '5m',

  // Nguong bao dong XSS
  XSS_THRESHOLD: 2,
  XSS_TIME_WINDOW: '5m',

  // Nguong bao dong DDoS / Flood (theo Device ID)
  DDOS_THRESHOLD: 50,       // > 50 request tu 1 thiet bi
  DDOS_TIME_WINDOW: '1m',

  // Nguong bao dong Privilege Escalation (leo thang dac quyen)
  PRIV_ESC_THRESHOLD: 2,    // Truy cap Admin API tu 2 lan la bao dong
  PRIV_ESC_TIME_WINDOW: '5m',

  // Nguong bao dong Geo Anomaly (dang nhap tu nhieu quoc gia)
  GEO_ANOMALY_TIME_WINDOW: '30m',

  // Nguong bao dong Data Exfiltration (ro ri du lieu)
  DATA_EXFIL_THRESHOLD: 5,  // > 5 lan export du lieu
  DATA_EXFIL_TIME_WINDOW: '5m',

  // Nguong bao dong Path Traversal (LFI)
  PATH_TRAVERSAL_THRESHOLD: 2,
  PATH_TRAVERSAL_TIME_WINDOW: '5m',

  // Nguong bao dong Malicious File Upload
  MALICIOUS_UPLOAD_THRESHOLD: 1, // 1 lan la bao dong ngay
  MALICIOUS_UPLOAD_TIME_WINDOW: '5m',

  // Nguong bao dong Mass Deletion (Ransomware/Phá hoại)
  MASS_DELETION_THRESHOLD: 5, // Xoa >= 5 tai nguyen trong 1 phut
  MASS_DELETION_TIME_WINDOW: '1m'
};
