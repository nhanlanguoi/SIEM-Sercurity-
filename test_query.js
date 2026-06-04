const { Client } = require('@elastic/elasticsearch');
const client = new Client({ node: 'http://localhost:9200' });

async function run() {
  const query = {
    index: 'filebeat-*',
    size: 0,
    query: {
      bool: {
        must: [
          { match: { action: 'login_failed' } },
          {
            range: {
              '@timestamp': {
                gte: 'now-15m',
                lte: 'now'
              }
            }
          }
        ]
      }
    },
    aggs: {
      ips: {
        terms: { field: 'ip', min_doc_count: 5 }
      }
    }
  };
  console.log("Running query:", JSON.stringify(query, null, 2));
  try {
    const res = await client.search(query);
    console.log("Result:", JSON.stringify(res, null, 2));
  } catch(e) {
    console.error(e);
  }
}
run();
