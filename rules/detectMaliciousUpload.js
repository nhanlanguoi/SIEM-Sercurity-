async function detectMaliciousUpload(esClient, config) {
  const timeWindowStr = config.MALICIOUS_UPLOAD_TIME_WINDOW || '5m';
  const threshold = config.MALICIOUS_UPLOAD_THRESHOLD || 1; 
  const attackers = [];

  const query = {
    query: {
      bool: {
        must: [
          { match: { action: "malicious_upload_attempt" } },
          { range: { "@timestamp": { gte: `now-${timeWindowStr}` } } }
        ]
      }
    },
    aggs: {
      by_user: {
        terms: { field: "username.keyword", size: 50 }
      }
    },
    size: 0
  };

  try {
    const { body } = await esClient.search({
      index: 'filebeat-*',
      body: query
    });

    const buckets = body.aggregations.by_user.buckets;

    for (const bucket of buckets) {
      if (bucket.doc_count >= threshold) {
        attackers.push({
          username: bucket.key,
          count: bucket.doc_count
        });
      }
    }
  } catch (err) {
    console.error('Lỗi khi phân tích Malicious Upload: ' + err.message);
  }
  return attackers;
}

module.exports = detectMaliciousUpload;
