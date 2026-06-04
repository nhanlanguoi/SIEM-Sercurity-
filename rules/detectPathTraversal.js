async function detectPathTraversal(esClient, config) {
  const timeWindowStr = config.PATH_TRAVERSAL_TIME_WINDOW || '5m';
  const threshold = config.PATH_TRAVERSAL_THRESHOLD || 2;
  const attackers = [];

  const query = {
    query: {
      bool: {
        must: [
          { match: { action: "path_traversal" } },
          { range: { "@timestamp": { gte: `now-${timeWindowStr}` } } }
        ]
      }
    },
    aggs: {
      by_ip: {
        terms: { field: "ip.keyword", size: 50 }
      }
    },
    size: 0
  };

  try {
    const { body } = await esClient.search({
      index: 'filebeat-*',
      body: query
    });

    const buckets = body.aggregations.by_ip.buckets;

    for (const bucket of buckets) {
      if (bucket.doc_count >= threshold) {
        attackers.push({
          ip: bucket.key,
          count: bucket.doc_count
        });
      }
    }
  } catch (err) {
    console.error('Lỗi khi phân tích Path Traversal: ' + err.message);
  }
  return attackers;
}

module.exports = detectPathTraversal;
