async function detectSqlInjection(esClient, config) {
  try {
    const response = await esClient.search({
      index: 'filebeat-*',
      size: 0,
      query: {
        bool: {
          must: [
            { match: { action: 'sqli_attempt' } },
            {
              range: {
                '@timestamp': {
                  gte: `now-${config.SQLI_TIME_WINDOW}`,
                  lte: 'now'
                }
              }
            }
          ]
        }
      },
      aggs: {
        attackers: {
          terms: { field: 'username', min_doc_count: config.SQLI_THRESHOLD }
        }
      }
    });

    const buckets = response?.aggregations?.attackers?.buckets || [];
    if (buckets.length > 0) {
      console.log(`[detectSqlInjection] Tìm thấy ${buckets.length} Tài khoản nghi ngờ SQLi`);
    }
    return buckets.map(bucket => bucket.key);
  } catch (error) {
    if (error?.meta?.statusCode === 404) {
      return [];
    }
    console.error('[detectSqlInjection] Lỗi:', error.message || error);
    return [];
  }
}

module.exports = detectSqlInjection;
