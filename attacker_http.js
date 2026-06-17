/**
 * attacker_http.js — Trình mô phỏng Tấn công HTTP & Tường lửa WAF (10 Kịch Bản)
 *
 * Ý TƯỞNG:
 * 1. Script này gửi các HTTP Request TẤN CÔNG THẬT vào Spring Boot (Cổng 8080).
 * 2. Ngay sau khi gửi, script giả lập một Tường lửa (WAF - Web Application Firewall)
 *    đứng trước hệ thống, tự động ghi nhận hành vi này vào file `security.log`.
 * 3. Bằng cách này: Spring Boot hoàn toàn KHÔNG BỊ ĐỤNG CHẠM (nguyên bản 100%),
 *    mà SIEM vẫn có file log JSON để phân tích và ra cảnh báo (recommendation).
 */

const fs = require('fs');
const path = require('path');
const { normalizeSecurityEvent } = require('./services/payloadAnalyzer');

const TARGET_BASE_URL = 'http://localhost:8080';
const SECURITY_LOG = path.join(__dirname, 'security.log');

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// ─── Hàm ghi log giả lập WAF ───────────────────────────────────────────────
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

// ─── HTTP Helpers (Tấn công thật vào Backend) ──────────────────────────────
async function post(path, body, headers = {}) {
  try {
    const response = await fetch(`${TARGET_BASE_URL}${path}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'SIEM-Attacker/4.0',
        ...headers
      },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(3000)
    });
    return { status: response.status };
  } catch (e) {
    return { status: 0, error: e.message };
  }
}

async function get(path, headers = {}) {
  try {
    const response = await fetch(`${TARGET_BASE_URL}${path}`, {
      method: 'GET',
      headers: {
        'User-Agent': 'SIEM-Attacker/4.0',
        ...headers
      },
      signal: AbortSignal.timeout(3000)
    });
    return { status: response.status };
  } catch (e) {
    return { status: 0, error: e.message };
  }
}

async function doDelete(path, headers = {}) {
  try {
    const response = await fetch(`${TARGET_BASE_URL}${path}`, {
      method: 'DELETE',
      headers: { 'User-Agent': 'SIEM-Attacker/4.0', ...headers },
      signal: AbortSignal.timeout(3000)
    });
    return { status: response.status };
  } catch (e) {
    return { status: 0, error: e.message };
  }
}

// ─── Kịch bản 1: Brute Force Login ──────────────────────────────────────────
async function attackBruteForce() {
  console.log('\n【1/10】Brute Force — Đăng nhập sai nhiều lần...');
  const targets = ['admin', 'user1'];
  for (const username of targets) {
    for (let i = 0; i < 6; i++) {
      // 1. Tấn công thật
      const res = await post('/api/auth/login', { username, password: `wrong_${i}` });
      // 2. WAF ghi log
      writeLog('login_failed', username);
      process.stdout.write(`  ➜ login_failed [${username}] → HTTP ${res.status}\n`);
      await sleep(100);
    }
  }
}

// ─── Kịch bản 2: SQL Injection ──────────────────────────────────────────────
async function attackSqlInjection() {
  console.log('\n【2/10】SQL Injection — Chèn SQL vào Query Params...');
  const payload = "' OR 1=1 --";
  for (let i = 0; i < 2; i++) {
    const res = await get('/api/posts/search?q=' + encodeURIComponent(payload));
    writeLog('sqli_attempt', 'anonymous', `Param: q=${payload}`);
    process.stdout.write(`  ➜ sqli_attempt [?q=' OR 1=1 --] → HTTP ${res.status}\n`);
    await sleep(100);
  }
}

// ─── Kịch bản 3: XSS ────────────────────────────────────────────────────────
async function attackXss() {
  console.log('\n【3/10】XSS — Gửi mã độc Javascript vào Query...');
  const payload = "<script>alert(1)</script>";
  for (let i = 0; i < 2; i++) {
    const res = await get('/api/posts/search?q=' + encodeURIComponent(payload));
    writeLog('xss_attempt', 'anonymous', `Param: q=${payload}`);
    process.stdout.write(`  ➜ xss_attempt [<script>] → HTTP ${res.status}\n`);
    await sleep(100);
  }
}

// ─── Kịch bản 4: Privilege Escalation ───────────────────────────────────────
async function attackPrivilegeEscalation() {
  console.log('\n【4/10】Privilege Escalation — Cố truy cập endpoint Admin...');
  for (let i = 0; i < 2; i++) {
    const res = await get('/api/admin/users', { 'Authorization': 'Bearer FAKE_TOKEN' });
    writeLog('unauthorized_admin_access', 'user_thuong', '/api/admin/users');
    process.stdout.write(`  ➜ unauthorized_admin_access [/api/admin/users] → HTTP ${res.status}\n`);
    await sleep(100);
  }
}

// ─── Kịch bản 5: Data Exfiltration ──────────────────────────────────────────
async function attackDataExfil() {
  console.log('\n【5/10】Data Exfiltration — Lấy trộm dữ liệu hàng loạt...');
  for (let i = 0; i < 6; i++) {
    const res = await get('/api/users/export');
    writeLog('data_export', 'admin', 'export_users.csv');
    process.stdout.write(`  ➜ data_export attempt → HTTP ${res.status}\n`);
    await sleep(50);
  }
}

// ─── Kịch bản 6: DDoS / Flood ────────────────────────────────────────────────
async function attackDdos() {
  console.log('\n【6/10】DDoS — Flood request liên tiếp từ botnet...');
  const promises = [];
  for (let i = 0; i < 60; i++) {
    // 1. Tấn công thật
    promises.push(get('/api/posts'));
    // 2. WAF ghi log (dùng chung 1 IP)
    writeLog('request', 'anonymous', 'GET /api/posts', '10.0.0.99');
  }
  const results = await Promise.all(promises);
  const success = results.filter(r => r.status > 0).length;
  console.log(`  ➜ DDoS flood: gửi 60 requests, ${success} phản hồi từ Backend`);
}

// ─── Kịch bản 7: Geo Anomaly ─────────────────────────────────────────────────
async function attackGeoAnomaly() {
  console.log('\n【7/10】Geo Anomaly — Cùng tài khoản đăng nhập từ 2 quốc gia...');
  // Không cần pass thật, ta giả lập WAF ghi log login thành công từ 2 IP
  writeLog('login_success', 'admin', null, '11.22.33.44', 'Vietnam');
  await sleep(100);
  writeLog('login_success', 'admin', null, '55.66.77.88', 'Russia');
  console.log(`  ➜ Ghi log login_success từ VN và Russia`);
}

// ─── Kịch bản 8: Path Traversal / LFI ────────────────────────────────────────
async function attackPathTraversal() {
  console.log('\n【8/10】Path Traversal (LFI) — Cố đọc file hệ thống...');
  for (let i = 0; i < 3; i++) {
    const res = await get('/api/files/download?file=../../../etc/passwd');
    writeLog('path_traversal', 'anonymous', '/api/files/download?file=../../../etc/passwd');
    process.stdout.write(`  ➜ path_traversal [../../../etc/passwd] → HTTP ${res.status}\n`);
    await sleep(100);
  }
}

// ─── Kịch bản 9: Malicious Upload ────────────────────────────────────────────
async function attackMaliciousUpload() {
  console.log('\n【9/10】Malicious Upload — Tải lên Web Shell (shell.php)...');
  // Fake WAF log
  writeLog('malicious_upload_attempt', 'hacker_007', 'shell.php');
  console.log(`  ➜ malicious_upload_attempt [shell.php] (Backend từ chối)`);
}

// ─── Kịch bản 10: Mass Deletion ──────────────────────────────────────────────
async function attackMassDeletion() {
  console.log('\n【10/10】Mass Deletion — Hành vi Ransomware/Xóa hàng loạt...');
  for (let i = 100; i < 106; i++) {
    const res = await doDelete(`/api/posts/${i}`);
    writeLog('resource_deleted', 'angry_user', `Post ID: ${i}`);
    process.stdout.write(`  ➜ mass_deletion_attempt (Post ID ${i}) → HTTP ${res.status}\n`);
    await sleep(50);
  }
}

// ─── Main ────────────────────────────────────────────────────────────────────
async function main() {
  console.log('');
  console.log('╔══════════════════════════════════════════════════════════╗');
  console.log('║    🌐 SIEM HTTP ATTACK & WAF SIMULATOR v4.0              ║');
  console.log('║    1. Gửi HTTP thật vào Backend (Không sửa Backend)      ║');
  console.log('║    2. Tự động ghi security.log như một Tường Lửa (WAF)   ║');
  console.log('╚══════════════════════════════════════════════════════════╝');
  console.log('');

  // Xóa log cũ
  if (fs.existsSync(SECURITY_LOG)) {
    fs.unlinkSync(SECURITY_LOG);
  }

  // Check Backend
  console.log('Kiểm tra Backend...');
  const check = await get('/api/posts');
  if (check.status === 0) {
    console.log('❌ LỖI: Backend (8080) chưa chạy! Hãy chạy Spring Boot trước.');
    process.exit(1);
  }

  await attackBruteForce();
  await attackSqlInjection();
  await attackXss();
  await attackPrivilegeEscalation();
  await attackDataExfil();
  await attackDdos();
  await attackGeoAnomaly();
  await attackPathTraversal();
  await attackMaliciousUpload();
  await attackMassDeletion();

  console.log('');
  console.log('✅ Hoàn thành 10 kịch bản!');
  console.log('⏳ SIEM Engine đang xử lý log, kiểm tra Telegram & Kibana...');
}

main().catch(console.error);
