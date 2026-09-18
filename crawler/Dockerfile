FROM python:3.11-slim
WORKDIR /app
COPY wheels/ /wheels/
RUN pip install --no-cache-dir --no-index --find-links=/wheels \
    scrapy==2.11.2 \
    twisted==24.3.0 \
    elasticsearch==8.13.0 \
    python-dotenv==1.0.1
COPY . .
CMD ["scrapy", "crawl", "dvwa"]
