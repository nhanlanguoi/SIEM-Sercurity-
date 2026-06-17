const test = require('node:test');
const assert = require('node:assert/strict');
const { normalizeSecurityEvent, inferAttackAction } = require('../services/payloadAnalyzer');

test('normalizeSecurityEvent detects path traversal from raw request', () => {
  const event = normalizeSecurityEvent({
    '@timestamp': '2026-06-11T10:00:00.000Z',
    action: 'request',
    username: 'anonymous',
    ip: '10.0.0.5',
    path: '/api/files/download?file=../../../../etc/passwd',
    method: 'GET'
  });

  assert.equal(event.action, 'path_traversal');
  assert.equal(event.raw_action, 'request');
  assert.equal(event.detection_reason, 'path_traversal_signature');
});

test('inferAttackAction detects SQL injection payload', () => {
  const result = inferAttackAction({
    action: 'request',
    query: "q=' OR 1=1 --"
  });

  assert.equal(result.action, 'sqli_attempt');
  assert.equal(result.reason, 'sqli_signature');
});

test('normalizeSecurityEvent keeps explicit action intact', () => {
  const event = normalizeSecurityEvent({
    action: 'login_failed',
    username: 'admin'
  });

  assert.equal(event.action, 'login_failed');
  assert.equal(event.detection_reason, 'explicit_action');
  assert.equal(event.raw_action, undefined);
});
