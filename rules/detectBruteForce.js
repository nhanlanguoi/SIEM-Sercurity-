async function detectBruteForce(esClient, config) {
  try {
    // @elastic/elasticsearch v8+ trả về response trực tiếp (không có wrapper { body })
    const response = await esClient.search({
      index: 'filebeat-*',
      size: 0,
      query: {
        bool: {
          must: [
            { match: { action: 'login_failed' } },
            {
              range: {
                '@timestamp': {
                  gte: `now-${config.BRUTE_FORCE_TIME_WINDOW}`,
                  lte: 'now'
                }
              }
            }
          ]
        }
      },
      aggs: {
        attackers: {
          terms: { field: 'username', min_doc_count: config.BRUTE_FORCE_THRESHOLD }
        }
      }
    });

    const buckets = response?.aggregations?.attackers?.buckets || [];
    if (buckets.length > 0) {
      console.log(`[detectBruteForce] Tìm thấy ${buckets.length} Tài khoản nghi ngờ`);
    }
    return buckets.map(bucket => bucket.key);
  } catch (error) {
    // Elasticsearch chưa có index nào (chưa có log) → bỏ qua bình thường
    if (error?.meta?.statusCode === 404) {
      return [];
    }
    // Lỗi kết nối hoặc lỗi khác
    console.error('[detectBruteForce] Lỗi:', error.message || error);
    return [];
  }
}

module.exports = detectBruteForce;
