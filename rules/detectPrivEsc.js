async function detectPrivEsc(esClient, config) {
  try {
    const response = await esClient.search({
      index: 'filebeat-*',
      size: 0,
      query: {
        bool: {
          must: [
            { match: { action: 'unauthorized_admin_access' } },
            {
              range: {
                '@timestamp': {
                  gte: `now-${config.PRIV_ESC_TIME_WINDOW}`,
                  lte: 'now'
                }
              }
            }
          ]
        }
      },
      aggs: {
        attackers: {
          terms: { field: 'username', min_doc_count: config.PRIV_ESC_THRESHOLD }
        }
      }
    });

    const buckets = response?.aggregations?.attackers?.buckets || [];
    if (buckets.length > 0) {
      console.log(`[detectPrivEsc] Phat hien ${buckets.length} tai khoan co leo thang dac quyen`);
    }
    return buckets.map(b => b.key);
  } catch (error) {
    if (error?.meta?.statusCode === 404) return [];
    console.error('[detectPrivEsc] Loi:', error.message || error);
    return [];
  }
}

module.exports = detectPrivEsc;
