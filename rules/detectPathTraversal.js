const Redis = require('ioredis');
const redis = new Redis();
const config = require('../config');

async function detectPathTraversal(logger) {
  const timeWindowStr = config.PATH_TRAVERSAL_TIME_WINDOW || '5m';
  const threshold = config.PATH_TRAVERSAL_THRESHOLD || 2;
  const timeWindowSec = 300; 

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
    const { body } = await global.esClient.search({
      index: 'filebeat-*',
      body: query
    });

    const buckets = body.aggregations.by_ip.buckets;

    for (const bucket of buckets) {
      if (bucket.doc_count >= threshold) {
        const ip = bucket.key;
        
        const redisKey = `alerted_path_traversal:${ip}`;
        const isAlerted = await redis.get(redisKey);

        if (!isAlerted) {
          const alertMsg = `Phát hiện LFI/Path Traversal! IP ${ip} cố truy cập file hệ thống ${bucket.doc_count} lần trong ${timeWindowStr}. Khuyến nghị: Bật WAF chặn chuỗi '../' và '/etc/passwd'.`;
          
          logger.warn(alertMsg);
          global.writeAlertLog('path_traversal_alert', ip, 'anonymous', alertMsg);

          await redis.set(redisKey, 'alerted', 'EX', timeWindowSec);
        }
      }
    }
  } catch (err) {
    logger.error('Lỗi khi phân tích Path Traversal: ' + err.message);
  }
}

module.exports = detectPathTraversal;
