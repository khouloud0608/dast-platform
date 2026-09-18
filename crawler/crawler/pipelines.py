import json
import os
from datetime import datetime
from elasticsearch import Elasticsearch

class JsonPipeline:
    def open_spider(self, spider):
        output_dir = spider.settings.get("OUTPUT_DIR", "/app/output")
        os.makedirs(output_dir, exist_ok=True)
        self.filepath = os.path.join(output_dir, "crawl_results.json")
        self.items = []

    def process_item(self, item, spider):
        self.items.append(dict(item))
        return item

    def close_spider(self, spider):
        with open(self.filepath, "w") as f:
            json.dump(self.items, f, indent=2, default=str)
        spider.logger.info(f"Saved {len(self.items)} items to {self.filepath}")

class ElasticsearchPipeline:
    def open_spider(self, spider):
        es_host = spider.settings.get("ES_HOST", "elasticsearch")
        es_port = spider.settings.get("ES_PORT", "9200")
        self.es = Elasticsearch(f"http://{es_host}:{es_port}")
        self.index = spider.settings.get("ES_INDEX", "dast-crawl")
        if not self.es.indices.exists(index=self.index):
            self.es.indices.create(index=self.index, body={
                "mappings": {
                    "properties": {
                        "url":         {"type": "keyword"},
                        "method":      {"type": "keyword"},
                        "status_code": {"type": "integer"},
                        "timestamp":   {"type": "date"},
                        "forms":       {"type": "object"},
                        "params":      {"type": "object"},
                        "cookies":     {"type": "object"},
                        "headers":     {"type": "object"},
                    }
                }
            })

    def process_item(self, item, spider):
        try:
            self.es.index(index=self.index, document=dict(item))
        except Exception as e:
            spider.logger.error(f"Failed to index item: {e}")
        return item
