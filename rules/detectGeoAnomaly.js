async function detectGeoAnomaly(esClient, config) {
  try {
    // Tìm các tài khoản đăng nhập từ nhiều hơn 1 quốc gia trong khoảng thời gian ngắn
    const response = await esClient.search({
      index: 'filebeat-*',
      size: 0,
      query: {
        bool: {
          must: [
            { match: { action: 'login_success' } },
            {
              range: {
                '@timestamp': {
                  gte: `now-${config.GEO_ANOMALY_TIME_WINDOW}`,
                  lte: 'now'
                }
              }
            }
          ]
        }
      },
      aggs: {
        users: {
          terms: { field: 'username', min_doc_count: 2 },
          aggs: {
            countries: {
              cardinality: { field: 'country' }
            },
            country_list: {
              terms: { field: 'country' }
            }
          }
        }
      }
    });

    const buckets = response?.aggregations?.users?.buckets || [];
    // Chỉ cảnh báo khi 1 tài khoản đăng nhập từ >= 2 quốc gia khác nhau
    const anomalies = buckets
      .filter(b => b.countries?.value >= 2)
      .map(b => ({
        username: b.key,
        countries: b.country_list?.buckets?.map(c => c.key) || []
      }));

    if (anomalies.length > 0) {
      console.log(`[detectGeoAnomaly] Phat hien ${anomalies.length} tai khoan dang nhap bat thuong tu nhieu quoc gia`);
    }
    return anomalies;
  } catch (error) {
    if (error?.meta?.statusCode === 404) return [];
    console.error('[detectGeoAnomaly] Loi:', error.message || error);
    return [];
  }
}

module.exports = detectGeoAnomaly;
