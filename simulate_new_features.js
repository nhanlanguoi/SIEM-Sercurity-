/**
 * simulate_new_features.js
 * Ghi ra các raw request/log để kiểm tra payload analyzer và auto-response.
 * Chạy cùng SIEM Engine đang mở: node app.js
 */

const fs = require('fs');
const path = require('path');
const { normalizeSecurityEvent } = require('./services/payloadAnalyzer');

const SECURITY_LOG = path.join(__dirname, 'security.log');

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function writeRawLog(event) {
  const normalized = normalizeSecurityEvent({
    '@timestamp': new Date().toISOString(),
    app: 'social-blog',
    username: 'anonymous',
    ip: '10.0.0.5',
    country: 'Vietnam',
    ...event
  });

  fs.appendFileSync(SECURITY_LOG, JSON.stringify(normalized) + '\n');
  console.log(`[simulate] ${normalized.action} <- ${normalized.detection_reason}`);
}

async function main() {
  console.log('');
  console.log('╔══════════════════════════════════════════════════════════╗');
  console.log('║   SIEM RAW EVENT SIMULATOR                               ║');
  console.log('║   Test payload analyzer + auto-response                  ║');
  console.log('╚══════════════════════════════════════════════════════════╝');
  console.log('');

  if (fs.existsSync(SECURITY_LOG)) {
    fs.unlinkSync(SECURITY_LOG);
  }

  writeRawLog({
    action: 'request',
    method: 'GET',
    path: '/api/files/download?file=../../../../etc/passwd',
    payload: '../../../../etc/passwd'
  });
  await sleep(100);

  writeRawLog({
    action: 'request',
    method: 'GET',
    path: "/api/posts/search?q=' OR 1=1 --",
    query: "' OR 1=1 --"
  });
  await sleep(100);

  writeRawLog({
    action: 'request',
    method: 'GET',
    path: '/api/posts/search?q=<script>alert(1)</script>',
    query: '<script>alert(1)</script>'
  });
  await sleep(100);

  writeRawLog({
    action: 'request',
    method: 'GET',
    path: '/api/admin/users',
    status: 403,
    role: 'user'
  });
  await sleep(100);

  writeRawLog({
    action: 'request',
    method: 'GET',
    path: '/api/users/export',
    status: 200
  });
  await sleep(100);

  writeRawLog({
    action: 'request',
    method: 'DELETE',
    path: '/api/posts/123',
    status: 200
  });
  await sleep(100);

  writeRawLog({
    action: 'request',
    method: 'POST',
    path: '/upload',
    file_name: 'shell.jsp'
  });

  console.log('');
  console.log('✅ Da ghi cac raw event mau vao security.log');
  console.log('👉 Chay SIEM Engine neu chua chay: node app.js');
  console.log('👉 Xem alert: tail -f engine.log');
  console.log('👉 Xem response: tail -f responses.log');
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
