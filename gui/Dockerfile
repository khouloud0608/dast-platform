FROM python:3.11-slim

WORKDIR /app

COPY docker /usr/bin/docker
RUN mkdir -p /usr/local/lib/docker/cli-plugins
COPY docker-compose /usr/local/lib/docker/cli-plugins/docker-compose
RUN chmod +x /usr/bin/docker && \
    chmod +x /usr/local/lib/docker/cli-plugins/docker-compose

COPY wheels/ /wheels/
RUN pip install --no-cache-dir --no-index --find-links=/wheels flask==3.0.3 requests==2.31.0

COPY . .

CMD ["python", "app.py"]
