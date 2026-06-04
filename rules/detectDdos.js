async function detectDdos(esClient, config) {
  try {
    const response = await esClient.search({
      index: 'filebeat-*',
      size: 0,
      query: {
        bool: {
          must: [
            { match: { action: 'request' } },
            {
              range: {
                '@timestamp': {
                  gte: `now-${config.DDOS_TIME_WINDOW}`,
                  lte: 'now'
                }
              }
            }
          ]
        }
      },
      aggs: {
        devices: {
          terms: { field: 'device_id', min_doc_count: config.DDOS_THRESHOLD }
        }
      }
    });

    const buckets = response?.aggregations?.devices?.buckets || [];
    if (buckets.length > 0) {
      console.log(`[detectDdos] Phat hien ${buckets.length} thiet bi co dau hieu DDoS`);
    }
    return buckets.map(b => ({ target: b.key, count: b.doc_count }));
  } catch (error) {
    if (error?.meta?.statusCode === 404) return [];
    console.error('[detectDdos] Loi:', error.message || error);
    return [];
  }
}

module.exports = detectDdos;
