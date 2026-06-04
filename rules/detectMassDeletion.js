async function detectMassDeletion(esClient, config) {
  const timeWindowStr = config.MASS_DELETION_TIME_WINDOW || '1m';
  const threshold = config.MASS_DELETION_THRESHOLD || 5; 
  const attackers = [];

  const query = {
    query: {
      bool: {
        must: [
          { match: { action: "resource_deleted" } },
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
    console.error('Lỗi khi phân tích Mass Deletion: ' + err.message);
  }
  return attackers;
}

module.exports = detectMassDeletion;
