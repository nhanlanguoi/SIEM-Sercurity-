async function detectDataExfil(esClient, config) {
  try {
    const response = await esClient.search({
      index: 'filebeat-*',
      size: 0,
      query: {
        bool: {
          must: [
            { match: { action: 'data_export' } },
            {
              range: {
                '@timestamp': {
                  gte: `now-${config.DATA_EXFIL_TIME_WINDOW}`,
                  lte: 'now'
                }
              }
            }
          ]
        }
      },
      aggs: {
        exporters: {
          terms: { field: 'username', min_doc_count: config.DATA_EXFIL_THRESHOLD }
        }
      }
    });

    const buckets = response?.aggregations?.exporters?.buckets || [];
    if (buckets.length > 0) {
      console.log(`[detectDataExfil] Phat hien ${buckets.length} tai khoan xuat du lieu bat thuong`);
    }
    return buckets.map(b => ({ username: b.key, count: b.doc_count }));
  } catch (error) {
    if (error?.meta?.statusCode === 404) return [];
    console.error('[detectDataExfil] Loi:', error.message || error);
    return [];
  }
}

module.exports = detectDataExfil;
