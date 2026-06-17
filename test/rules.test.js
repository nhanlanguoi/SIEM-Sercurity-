const test = require('node:test');
const assert = require('node:assert/strict');
const detectPathTraversal = require('../rules/detectPathTraversal');

test('detectPathTraversal reads Elasticsearch body wrapper responses', async () => {
  const esClient = {
    search: async () => ({
      body: {
        aggregations: {
          by_ip: {
            buckets: [
              { key: '10.0.0.5', doc_count: 3 }
            ]
          }
        }
      }
    })
  };

  const result = await detectPathTraversal(esClient, {
    PATH_TRAVERSAL_THRESHOLD: 2,
    PATH_TRAVERSAL_TIME_WINDOW: '5m'
  });

  assert.deepEqual(result, [
    {
      ip: '10.0.0.5',
      count: 3
    }
  ]);
});
