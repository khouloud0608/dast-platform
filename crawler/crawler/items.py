import scrapy

class CrawlerItem(scrapy.Item):
    url         = scrapy.Field()   # full URL of the page
    method      = scrapy.Field()   # GET or POST
    forms       = scrapy.Field()   # list of forms found on the page
    params      = scrapy.Field()   # query string parameters in the URL
    cookies     = scrapy.Field()   # cookies present on this page
    status_code = scrapy.Field()   # HTTP response code
    headers     = scrapy.Field()   # response headers
    timestamp   = scrapy.Field()   # when the page was crawled
