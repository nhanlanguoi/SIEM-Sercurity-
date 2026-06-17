#!/bin/bash
cd /Users/nhannt/Desktop/desktop/project/siem-engine

echo "Downloading Elasticsearch..."
curl -L -O https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-8.11.3-darwin-aarch64.tar.gz
tar -xzf elasticsearch-8.11.3-darwin-aarch64.tar.gz
rm elasticsearch-8.11.3-darwin-aarch64.tar.gz

echo "Downloading Kibana..."
curl -L -O https://artifacts.elastic.co/downloads/kibana/kibana-8.11.3-darwin-aarch64.tar.gz
tar -xzf kibana-8.11.3-darwin-aarch64.tar.gz
rm kibana-8.11.3-darwin-aarch64.tar.gz

echo "Downloading Filebeat..."
curl -L -O https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-8.11.3-darwin-aarch64.tar.gz
tar -xzf filebeat-8.11.3-darwin-aarch64.tar.gz
rm filebeat-8.11.3-darwin-aarch64.tar.gz

echo "✅ Đã tải và giải nén xong ELK Stack!"
