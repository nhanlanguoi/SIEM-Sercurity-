require('dotenv').config();

module.exports = {
  ELASTIC_URL: process.env.ELASTIC_URL || 'http://localhost:9200',
  REDIS_URL: process.env.REDIS_URL || 'redis://localhost:6379',
  TELEGRAM_BOT_TOKEN: process.env.TELEGRAM_BOT_TOKEN || 'YOUR_BOT_TOKEN',
  TELEGRAM_CHAT_ID: process.env.TELEGRAM_CHAT_ID || 'YOUR_CHAT_ID',
  CHECK_INTERVAL_MS: 5000,
  
  // Ngưỡng báo động Brute Force / Password Spraying
  BRUTE_FORCE_THRESHOLD: 5,
  BRUTE_FORCE_TIME_WINDOW: '1m',

  // SQLi raw payload matching: 1 payload ro rang la can canh bao
  SQLI_THRESHOLD: 1,
  SQLI_TIME_WINDOW: '5m',

  // XSS raw payload matching
  XSS_THRESHOLD: 1,
  XSS_TIME_WINDOW: '5m',

  // Nguong bao dong DDoS / Flood theo source IP
  DDOS_THRESHOLD: 50,
  DDOS_TIME_WINDOW: '1m',

  // Nguong bao dong Privilege Escalation (leo thang dac quyen)
  PRIV_ESC_THRESHOLD: 2,    // Truy cap Admin API tu 2 lan la bao dong
  PRIV_ESC_TIME_WINDOW: '5m',

  // Nguong bao dong Geo Anomaly (dang nhap tu nhieu quoc gia)
  GEO_ANOMALY_TIME_WINDOW: '30m',

  // Nguong bao dong Data Exfiltration: uu tien tong bytes, fallback theo so lan export
  DATA_EXFIL_THRESHOLD: 5,
  DATA_EXFIL_BYTES_THRESHOLD: 500 * 1024 * 1024,
  DATA_EXFIL_TIME_WINDOW: '5m',

  // Nguong bao dong Path Traversal (LFI/RFI) raw payload
  PATH_TRAVERSAL_THRESHOLD: 1,
  PATH_TRAVERSAL_TIME_WINDOW: '5m',

  // Nguong bao dong Malicious File Upload
  MALICIOUS_UPLOAD_THRESHOLD: 1, // 1 lan la bao dong ngay
  MALICIOUS_UPLOAD_TIME_WINDOW: '5m',

  // Nguong bao dong Mass Deletion (Ransomware/Phá hoại)
  MASS_DELETION_THRESHOLD: 5, // Xoa >= 5 tai nguyen trong 1 phut
  MASS_DELETION_TIME_WINDOW: '1m'
};
