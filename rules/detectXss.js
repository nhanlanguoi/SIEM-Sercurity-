async function detectXss(esClient, config) {
  try {
    const response = await esClient.search({
      index: 'filebeat-*',
      size: 0,
      query: {
        bool: {
          must: [
            { match: { action: 'xss_attempt' } },
            {
              range: {
                '@timestamp': {
                  gte: `now-${config.XSS_TIME_WINDOW}`,
                  lte: 'now'
                }
              }
            }
          ]
        }
      },
      aggs: {
        attackers: {
          terms: { field: 'username', min_doc_count: config.XSS_THRESHOLD }
        }
      }
    });

    const buckets = response?.aggregations?.attackers?.buckets || [];
    if (buckets.length > 0) {
      console.log(`[detectXss] Tìm thấy ${buckets.length} Tài khoản nghi ngờ XSS`);
    }
    return buckets.map(bucket => bucket.key);
  } catch (error) {
    if (error?.meta?.statusCode === 404) {
      return [];
    }
    console.error('[detectXss] Lỗi:', error.message || error);
    return [];
  }
}

module.exports = detectXss;
