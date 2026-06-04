const Redis = require('ioredis');
const redis = new Redis();
const config = require('../config');

async function detectMassDeletion(logger) {
  const timeWindowStr = config.MASS_DELETION_TIME_WINDOW || '1m';
  const threshold = config.MASS_DELETION_THRESHOLD || 5; 
  const timeWindowSec = 60; 

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
    const { body } = await global.esClient.search({
      index: 'filebeat-*',
      body: query
    });

    const buckets = body.aggregations.by_user.buckets;

    for (const bucket of buckets) {
      if (bucket.doc_count >= threshold) {
        const username = bucket.key;
        
        const redisKey = `alerted_mass_deletion:${username}`;
        const isAlerted = await redis.get(redisKey);

        if (!isAlerted) {
          const alertMsg = `Phát hiện hành vi Phá hoại/Ransomware! Tài khoản ${username} đã xóa ${bucket.doc_count} dữ liệu liên tiếp trong thời gian cực ngắn (${timeWindowStr}). Khuyến nghị: Tạm khóa ngay quyền WRITE/DELETE của user, kiểm tra audit log.`;
          
          logger.warn(alertMsg);
          global.writeAlertLog('mass_deletion_alert', null, username, alertMsg);

          await redis.set(redisKey, 'alerted', 'EX', timeWindowSec);
        }
      }
    }
  } catch (err) {
    logger.error('Lỗi khi phân tích Mass Deletion: ' + err.message);
  }
}

module.exports = detectMassDeletion;
