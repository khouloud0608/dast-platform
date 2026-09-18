import os
BOT_NAME = "dast-crawler"
SPIDER_MODULES = ["crawler.spiders"]
NEWSPIDER_MODULE = "crawler.spiders"
DOWNLOAD_DELAY = 0.5
CONCURRENT_REQUESTS = 4
ROBOTSTXT_OBEY = False
COOKIES_ENABLED = True
ITEM_PIPELINES = {
    "crawler.pipelines.JsonPipeline": 100,
    "crawler.pipelines.ElasticsearchPipeline": 200,
}
OUTPUT_DIR = "/app/output"
LOG_LEVEL = "INFO"
ES_HOST = os.environ.get("ES_HOST", "elasticsearch")
ES_PORT = os.environ.get("ES_PORT", "9200")
ES_INDEX = "dast-crawl"
SPIDER_MIDDLEWARES = {
    'scrapy.spidermiddlewares.offsite.OffsiteMiddleware': None,
}
DUPEFILTER_CLASS = 'scrapy.dupefilters.RFPDupeFilter'
