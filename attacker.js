/**
 * attacker.js — Trình mô phỏng hệ thống (WAF/Application) ghi log bảo mật.
 * 
 * SIEM V4.0 (10 Kịch Bản Tấn Công)
 * Script này đóng vai trò là Web Application Firewall (WAF) hoặc Social Blog.
 * Nó mô phỏng việc hệ thống gặp phải các cuộc tấn công và tự động
 * sinh ra các dòng log JSON vào file security.log.
 * 
 * Chú ý: Script này KHÔNG tấn công thật vào Spring Boot để đảm bảo
 * tính ĐỘC LẬP tuyệt đối của hệ thống SIEM.
 */

const fs = require('fs');
const path = require('path');
const { normalizeSecurityEvent } = require('./services/payloadAnalyzer');

const SECURITY_LOG = path.join(__dirname, 'security.log');

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function writeLog(action, username, payload = null, ip = '123.45.67.89', country = 'Vietnam') {
  const logEntry = {
    "@timestamp": new Date().toISOString(),
    "app": "social-blog",
    "action": action,
    "username": username || "anonymous",
    "ip": ip,
    "device_id": "dev_" + Math.random().toString(36).substr(2, 9),
    "country": country,
  };
  if (payload) logEntry.payload = payload;

  fs.appendFileSync(SECURITY_LOG, JSON.stringify(normalizeSecurityEvent(logEntry)) + '\n');
}

// ─── Kịch bản 1: Brute Force Login ──────────────────────────────────────────
async function attackBruteForce() {
  console.log('【1/10】Brute Force — Đăng nhập sai nhiều lần...');
  const targets = ['admin', 'user1', 'test_user'];
  for (const user of targets) {
    for (let i = 0; i < 6; i++) {
      writeLog('login_failed', user);
      await sleep(100);
    }
  }
  console.log('  ➜ Ghi nhận 18 lần login_failed');
}

// ─── Kịch bản 2: SQL Injection ──────────────────────────────────────────────
async function attackSqlInjection() {
  console.log('\n【2/10】SQL Injection — Chèn SQL vào hệ thống...');
  for (let i = 0; i < 2; i++) {
    writeLog('sqli_attempt', 'anonymous', "Param: q=' OR 1=1 --");
    await sleep(100);
  }
  console.log('  ➜ Ghi nhận 2 lần sqli_attempt');
}

// ─── Kịch bản 3: XSS ────────────────────────────────────────────────────────
async function attackXss() {
  console.log('\n【3/10】XSS — Cố gắng chèn script độc hại...');
  for (let i = 0; i < 2; i++) {
    writeLog('xss_attempt', 'anonymous', "Param: q=<script>alert(1)</script>");
    await sleep(100);
  }
  console.log('  ➜ Ghi nhận 2 lần xss_attempt');
}

// ─── Kịch bản 4: Privilege Escalation ───────────────────────────────────────
async function attackPrivEsc() {
  console.log('\n【4/10】Privilege Escalation — Truy cập Admin trái phép...');
  for (let i = 0; i < 4; i++) {
    writeLog('unauthorized_admin_access', 'user_thuong', '/api/admin/users');
    await sleep(100);
  }
  console.log('  ➜ Ghi nhận 4 lần unauthorized_admin_access');
}

// ─── Kịch bản 5: Data Exfiltration ──────────────────────────────────────────
async function attackDataExfil() {
  console.log('\n【5/10】Data Exfiltration — Lấy trộm dữ liệu hàng loạt...');
  for (let i = 0; i < 6; i++) {
    writeLog('data_export', 'admin', 'export_users.csv');
    await sleep(50);
  }
  console.log('  ➜ Ghi nhận 6 lần data_export');
}

// ─── Kịch bản 6: DDoS / Flood ────────────────────────────────────────────────
async function attackDdos() {
  console.log('\n【6/10】DDoS — Flood 150 request liên tiếp từ botnet...');
  for (let i = 0; i < 150; i++) {
    writeLog('request', 'anonymous', 'GET /api/posts', '10.0.0.99');
  }
  console.log('  ➜ Ghi nhận 150 lần request từ cùng 1 IP');
}

// ─── Kịch bản 7: Geo Anomaly ─────────────────────────────────────────────────
async function attackGeoAnomaly() {
  console.log('\n【7/10】Geo Anomaly — Cùng tài khoản đăng nhập từ 2 quốc gia...');
  writeLog('login_success', 'admin', null, '11.22.33.44', 'Vietnam');
  await sleep(100);
  writeLog('login_success', 'admin', null, '55.66.77.88', 'Russia');
  console.log('  ➜ Ghi nhận login_success từ VN và Nga');
}

// ─── Kịch bản 8: Path Traversal / LFI ────────────────────────────────────────
async function attackPathTraversal() {
  console.log('\n【8/10】Path Traversal (LFI) — Cố đọc file hệ thống...');
  for (let i = 0; i < 3; i++) {
    writeLog('path_traversal', 'anonymous', '/api/files/download?file=../../../etc/passwd');
    await sleep(100);
  }
  console.log('  ➜ Ghi nhận 3 lần path_traversal');
}

// ─── Kịch bản 9: Malicious Upload ────────────────────────────────────────────
async function attackMaliciousUpload() {
  console.log('\n【9/10】Malicious Upload — Tải lên Web Shell (shell.php)...');
  writeLog('malicious_upload_attempt', 'hacker_007', 'shell.php');
  console.log('  ➜ Ghi nhận malicious_upload_attempt');
}

// ─── Kịch bản 10: Mass Deletion ──────────────────────────────────────────────
async function attackMassDeletion() {
  console.log('\n【10/10】Mass Deletion — Hành vi Ransomware/Xóa hàng loạt...');
  for (let i = 0; i < 6; i++) {
    writeLog('resource_deleted', 'angry_user', `Post ID: ${100 + i}`);
    await sleep(50);
  }
  console.log('  ➜ Ghi nhận 6 lần resource_deleted');
}

// ─── Main ────────────────────────────────────────────────────────────────────
async function main() {
  console.log('');
  console.log('╔══════════════════════════════════════════════════════════╗');
  console.log('║    🌐 SIEM WAF LOG SIMULATOR v4.0                        ║');
  console.log('║    Mô phỏng Hệ thống ghi log (Không đụng vào Backend)    ║');
  console.log('╚══════════════════════════════════════════════════════════╝');
  console.log('');

  // Xóa log cũ để test cho dễ
  if (fs.existsSync(SECURITY_LOG)) {
    fs.unlinkSync(SECURITY_LOG);
  }

  await attackBruteForce();
  await attackSqlInjection();
  await attackXss();
  await attackPrivEsc();
  await attackDataExfil();
  await attackPathTraversal();
  await attackMaliciousUpload();
  await attackMassDeletion();
  await attackDdos();
  await attackGeoAnomaly();

  console.log('');
  console.log('✅ Hoàn thành giả lập 10 kịch bản!');
  console.log('📋 Đã ghi log giả lập vào security.log');
  console.log('⏳ Đợi Filebeat đọc và SIEM Engine sẽ xử lý...');
}

main().catch(console.error);
