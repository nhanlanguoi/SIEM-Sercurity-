const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { executeAutoResponse } = require('../services/autoResponder');

test('executeAutoResponse writes a simulated response log', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'siem-response-'));
  const logPath = path.join(dir, 'responses.log');

  const result = await executeAutoResponse(
    {
      AUTO_RESPONSE_MODE: 'simulate',
      RESPONSE_LOG_PATH: logPath
    },
    {
      rule: 'brute_force',
      targetType: 'username',
      target: 'admin',
      title: 'Brute Force Attack'
    }
  );

  assert.equal(result.status, 'simulated');
  assert.equal(result.response_action, 'lock_account_temporarily');
  assert.ok(fs.existsSync(logPath));

  const content = fs.readFileSync(logPath, 'utf8').trim().split('\n');
  assert.equal(content.length, 1);

  const parsed = JSON.parse(content[0]);
  assert.equal(parsed.rule, 'brute_force');
  assert.equal(parsed.target, 'admin');
});
