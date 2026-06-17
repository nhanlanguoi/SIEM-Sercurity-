const DEFAULT_INDEX = 'filebeat-*';

function unwrapHits(response) {
  const hits = response?.hits?.hits || response?.body?.hits?.hits || [];
  return hits.map(hit => ({
    id: hit._id,
    index: hit._index,
    ...(hit._source || {})
  }));
}

async function searchRecentLogs(esClient, timeWindow, size = 1000) {
  const response = await esClient.search({
    index: DEFAULT_INDEX,
    size,
    sort: [{ '@timestamp': { order: 'desc', unmapped_type: 'date' } }],
    query: {
      bool: {
        must: [
          {
            range: {
              '@timestamp': {
                gte: `now-${timeWindow}`,
                lte: 'now'
              }
            }
          }
        ],
        must_not: [
          { term: { 'type.keyword': 'siem_alert' } },
          { term: { 'log_type.keyword': 'siem_alert' } },
          { term: { 'app.keyword': 'siem-engine' } }
        ]
      }
    }
  });

  return unwrapHits(response).filter(log =>
    log.type !== 'siem_alert' &&
    log.log_type !== 'siem_alert' &&
    log.app !== 'siem-engine'
  );
}

function firstPresent(log, fields, fallback = '') {
  for (const field of fields) {
    const value = field.split('.').reduce((current, key) => current?.[key], log);
    if (value !== undefined && value !== null && value !== '') {
      return value;
    }
  }
  return fallback;
}

function asString(value) {
  if (value === undefined || value === null) return '';
  if (typeof value === 'string') return value;
  try {
    return JSON.stringify(value);
  } catch (_) {
    return String(value);
  }
}

function safeDecodeURIComponent(value) {
  try {
    return decodeURIComponent(value.replace(/\+/g, ' '));
  } catch (_) {
    return value;
  }
}

function decodeHtmlEntities(value) {
  return value
    .replace(/&#x([0-9a-f]+);?/gi, (_, hex) => String.fromCodePoint(parseInt(hex, 16)))
    .replace(/&#(\d+);?/g, (_, dec) => String.fromCodePoint(parseInt(dec, 10)))
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi, "'")
    .replace(/&apos;/gi, "'")
    .replace(/&amp;/gi, '&');
}

function decodeUnicodeEscapes(value) {
  return value.replace(/\\u([0-9a-f]{4})/gi, (_, hex) =>
    String.fromCharCode(parseInt(hex, 16))
  );
}

function multiDecode(value, rounds = 3) {
  let decoded = asString(value);

  for (let i = 0; i < rounds; i++) {
    const next = decodeUnicodeEscapes(decodeHtmlEntities(safeDecodeURIComponent(decoded)));
    if (next === decoded) break;
    decoded = next;
  }

  return decoded;
}

function getPayloadParts(log) {
  return {
    uri: multiDecode(firstPresent(log, [
      'request_uri',
      'url.path',
      'url.original',
      'uri',
      'path',
      'request',
      'http.request.referrer'
    ])),
    body: multiDecode(firstPresent(log, [
      'request_body',
      'body',
      'payload',
      'message',
      'event.original'
    ])),
    filename: multiDecode(firstPresent(log, [
      'originalFileName',
      'original_file_name',
      'file.name',
      'filename',
      'fileName',
      'payload'
    ])),
    contentType: asString(firstPresent(log, [
      'contentType',
      'content_type',
      'http.request.mime_type',
      'file.mime_type'
    ])).toLowerCase()
  };
}

function getActor(log) {
  return asString(firstPresent(log, ['username', 'user.name', 'user.id'], 'anonymous'));
}

function getIp(log) {
  return asString(firstPresent(log, ['client_ip', 'source.ip', 'ip', 'remote_addr'], 'unknown'));
}

function getMethod(log) {
  return asString(firstPresent(log, ['http_method', 'method', 'http.request.method'], '')).toUpperCase();
}

function getStatus(log) {
  const value = firstPresent(log, ['http_status', 'http.status_code', 'status', 'response.status_code'], 0);
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : 0;
}

function getResponseBytes(log) {
  const value = firstPresent(log, [
    'response_size_bytes',
    'body_bytes_sent',
    'bytes_sent',
    'response.bytes',
    'http.response.body.bytes',
    'fileSizeBytes',
    'file.size'
  ], 0);
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : 0;
}

function incrementCounter(map, key, patch = {}) {
  const current = map.get(key) || { count: 0 };
  map.set(key, { ...current, ...patch, count: current.count + 1 });
  return map.get(key);
}

function normalizeKeyword(value) {
  return asString(value).trim().toLowerCase();
}

module.exports = {
  searchRecentLogs,
  firstPresent,
  multiDecode,
  getPayloadParts,
  getActor,
  getIp,
  getMethod,
  getStatus,
  getResponseBytes,
  incrementCounter,
  normalizeKeyword
};
