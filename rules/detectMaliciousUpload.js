const Redis = require('ioredis');
const redis = new Redis();
const config = require('../config');

async function detectMaliciousUpload(logger) {
  const timeWindowStr = config.MALICIOUS_UPLOAD_TIME_WINDOW || '5m';
  const threshold = config.MALICIOUS_UPLOAD_THRESHOLD || 1; // 1 is enough for alert
  const timeWindowSec = 300; 

  const query = {
    query: {
      bool: {
        must: [
          { match: { action: "malicious_upload_attempt" } },
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
    const { body } = await global.esClient.search({
      index: 'filebeat-*',
      body: query
    });

    const buckets = body.aggregations.by_user.buckets;

    for (const bucket of buckets) {
      if (bucket.doc_count >= threshold) {
        const username = bucket.key;
        
        const redisKey = `alerted_malicious_upload:${username}`;
        const isAlerted = await redis.get(redisKey);

        if (!isAlerted) {
          const alertMsg = `Phát hiện tải lên file nguy hiểm (Web Shell)! Tài khoản ${username} cố gắng tải file không hợp lệ. Khuyến nghị: Cô lập ngay thư mục upload và kiểm tra mã độc.`;
          
          logger.warn(alertMsg);
          global.writeAlertLog('malicious_upload_alert', null, username, alertMsg);

          await redis.set(redisKey, 'alerted', 'EX', timeWindowSec);
        }
      }
    }
  } catch (err) {
    logger.error('Lỗi khi phân tích Malicious Upload: ' + err.message);
  }
}

module.exports = detectMaliciousUpload;
