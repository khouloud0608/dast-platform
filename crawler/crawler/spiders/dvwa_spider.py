import scrapy
import json
import os
from urllib.parse import urljoin, urlparse, parse_qs
from datetime import datetime
from crawler.items import CrawlerItem

def load_config():
    config_path = "/app/config.json"
    if os.path.exists(config_path) and os.path.isfile(config_path):
        with open(config_path) as f:
            return json.load(f)
    return {
        "target_url": os.environ.get("TARGET_URL", "http://dvwa:80"),
        "app_type": "dvwa",
        "credentials": {"username": "admin", "password": "password"}
    }

class DVWASpider(scrapy.Spider):
    name = "dvwa"
    BLACKLIST = ["logout", "setup.php", "logoff", "signout"]

    custom_settings = {
        'SPIDER_MIDDLEWARES': {
            'scrapy.spidermiddlewares.offsite.OffsiteMiddleware': None,
        }
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.config = load_config()
        self.target_url = self.config["target_url"].rstrip("/")
        self.app_type = self.config.get("app_type", "dvwa")
        self.username = self.config["credentials"].get("username", "admin")
        self.password = self.config["credentials"].get("password", "password")
        self.target_host = urlparse(self.target_url).hostname
        self.logger.info(f"Target: {self.target_url} | App: {self.app_type}")

    def start_requests(self):
        if self.app_type == "dvwa":
            yield scrapy.Request(
                url=f"{self.target_url}/setup.php",
                callback=self.dvwa_setup
            )
        elif self.app_type == "juiceshop":
            yield scrapy.Request(
                url=f"{self.target_url}/rest/user/login",
                callback=self.parse,
                method="POST",
                body=json.dumps({"email": self.username, "password": self.password}),
                headers={"Content-Type": "application/json"}
            )
        else:
            yield scrapy.Request(url=self.target_url, callback=self.parse)

    def dvwa_setup(self, response):
        token = response.css("input[name='user_token']::attr(value)").get()
        yield scrapy.FormRequest(
            url=f"{self.target_url}/setup.php",
            formdata={"create_db": "Create / Reset Database", "user_token": token or ""},
            callback=self.dvwa_setup_done,
            dont_filter=True
        )

    def dvwa_setup_done(self, response):
        self.logger.info("Database setup complete")
        yield scrapy.Request(
            url=f"{self.target_url}/login.php",
            callback=self.dvwa_get_token,
            dont_filter=True
        )

    def dvwa_get_token(self, response):
        token = response.css("input[name='user_token']::attr(value)").get()
        yield scrapy.FormRequest(
            url=f"{self.target_url}/login.php",
            formdata={
                "username": self.username,
                "password": self.password,
                "Login": "Login",
                "user_token": token or ""
            },
            callback=self.dvwa_after_login,
            dont_filter=True
        )

    def dvwa_after_login(self, response):
        self.logger.info(f"Login response status: {response.status} | URL: {response.url}")
        if "logout" in response.text.lower() or response.status in [200, 302]:
            self.logger.info("Login successful — starting crawl")
            yield scrapy.Request(
                url=f"{self.target_url}/index.php",
                callback=self.parse,
                #dont_filter=True
            )
        else:
            self.logger.error(f"Login failed! Status: {response.status}")

    def parse(self, response):
        if any(bl in response.url for bl in self.BLACKLIST):
            return
        content_type = response.headers.get(b"Content-Type", b"").decode(
            "utf-8", errors="ignore").lower()

        if not any(
            content_type.startswith(t)
            for t in ["text/html", "application/xhtml+xml"]
        ):
            self.logger.info(
                f"SKIPPING NON-TEXT: {response.url} | Content-Type: {content_type}"
            )
            return
        try:
            headers = {}
            for k, v in response.headers.items():
                key = k.decode("utf-8", errors="ignore") if isinstance(k, bytes) else str(k)
                if isinstance(v, list):
                    val = v[0].decode("utf-8", errors="ignore") if v and isinstance(v[0], bytes) else (str(v[0]) if v else "")
                else:
                    val = v.decode("utf-8", errors="ignore") if isinstance(v, bytes) else str(v)
                headers[key] = val

            item = CrawlerItem()
            item["url"]         = response.url
            item["method"]      = "GET"
            item["status_code"] = response.status
            item["timestamp"]   = datetime.utcnow().isoformat()
            item["params"]      = parse_qs(urlparse(response.url).query)
            item["cookies"]     = {}
            item["headers"]     = headers
            item["forms"]       = []

            forms = []
            for form in response.css("form"):
                action = form.attrib.get("action", response.url)
                method = form.attrib.get("method", "GET").upper()
                inputs = []
                for inp in form.css("input, select, textarea"):
                    inputs.append({
                        "name":  inp.attrib.get("name", ""),
                        "type":  inp.attrib.get("type", "text"),
                        "value": inp.attrib.get("value", "")
                    })
                forms.append({
                    "action": urljoin(response.url, action),
                    "method": method,
                    "inputs": inputs
                })
            item["forms"] = forms
            yield item

            for href in response.css("a::attr(href)").getall():
                self.logger.info(f"FOUND LINK: {href}")

                try:
                    full_url = urljoin(response.url, href)
                    parsed = urlparse(full_url)

                    if (parsed.scheme in ["http", "https"]
                            and parsed.hostname == self.target_host
                            and not any(bl in full_url for bl in self.BLACKLIST)):

                        self.logger.info(f"FOLLOWING: {full_url}")

                        yield scrapy.Request(
                            url=full_url,
                            callback=self.parse
                        )

                except Exception as e:
                    self.logger.warning(f"Skipping URL: {e}")

        except Exception as e:
            self.logger.error(f"Parse error on {response.url}: {e}")
