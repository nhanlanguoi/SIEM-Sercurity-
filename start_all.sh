#!/bin/bash
# Script khởi động toàn bộ SIEM Stack (Elasticsearch + Kibana + Redis + Node.js Engine)
# Chạy từ thư mục siem-engine:  bash start_all.sh

SIEM_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SIEM_DIR"

echo "============================================"
echo "  🚀 SIEM Stack Startup Script"
echo "  📁 Directory: $SIEM_DIR"
echo "============================================"

# 1. Dừng các tiến trình cũ nếu còn chạy
echo ""
echo "[1/5] Dọn dẹp tiến trình cũ..."
pkill -f "elasticsearch" 2>/dev/null
pkill -f "kibana" 2>/dev/null
sleep 2

# 2. Khởi động Redis
echo ""
echo "[2/5] Khởi động Redis..."
brew services start redis 2>/dev/null || true
echo "  ✅ Redis đang chạy tại localhost:6379"

# 3. Khởi động Elasticsearch
echo ""
echo "[3/5] Khởi động Elasticsearch..."
./elasticsearch-8.11.3/bin/elasticsearch -d -p elasticsearch.pid
echo "  ⏳ Chờ Elasticsearch khởi động (15 giây)..."
sleep 15

# Kiểm tra ES đã sẵn sàng chưa
ES_STATUS=$(curl -s "http://localhost:9200/_cluster/health" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('status','unknown'))" 2>/dev/null)
if [ "$ES_STATUS" = "green" ] || [ "$ES_STATUS" = "yellow" ]; then
  echo "  ✅ Elasticsearch đang chạy (status: $ES_STATUS)"
  
  # Đặt replica = 0 cho toàn bộ index (bằng API, không phải config file)
  echo "  ⚙️  Cài đặt replica=0 cho single-node cluster..."
  curl -s -X PUT "http://localhost:9200/_template/default_settings" \
    -H 'Content-Type: application/json' \
    -d '{"index_patterns":["*"],"settings":{"number_of_replicas":0}}' > /dev/null
  echo "  ✅ Index template đã được tạo (mọi index mới sẽ có replica=0)"
else
  echo "  ❌ Elasticsearch chưa sẵn sàng. Kiểm tra log tại: elasticsearch-8.11.3/logs/elasticsearch.log"
  exit 1
fi

# 4. Khởi động Kibana
echo ""
echo "[4/6] Khởi động Kibana..."
nohup ./kibana-8.11.3/bin/kibana > kibana.log 2>&1 &
echo "  ✅ Kibana đang khởi động (PID=$!)"
echo "  📊 Truy cập dashboard tại: http://localhost:5601 (sau ~2 phút)"

# 5. Khởi động Filebeat
echo ""
echo "[5/6] Khởi động Filebeat..."
nohup ./filebeat-8.11.3-darwin-aarch64/filebeat -e -c filebeat.yml > filebeat_run.log 2>&1 &
echo "  ✅ Filebeat đang thu thập log (PID=$!)"

# 6. Khởi động SIEM Engine
echo ""
echo "[6/6] Khởi động SIEM Engine (Node.js)..."
nohup node app.js > engine.log 2>&1 &
echo "  ✅ SIEM Engine đang chạy (PID=$!)"
echo "  📋 Xem log engine: tail -f $SIEM_DIR/engine.log"

echo ""
echo "============================================"
echo "  ✅ Tất cả dịch vụ đã khởi động!"
echo ""
echo "  🔍 Elasticsearch:  http://localhost:9200"
echo "  📊 Kibana:         http://localhost:5601 (~2 phút)"
echo "  🛡️  SIEM Engine:   tail -f engine.log"
echo "  💾 Redis:          localhost:6379"
echo ""
echo "  🧪 Test tấn công:  node attacker.js"
echo "============================================"
