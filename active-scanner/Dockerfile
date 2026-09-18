FROM python:3.11-slim
WORKDIR /app
COPY wheels/ /wheels/
RUN pip install --no-cache-dir --no-index --find-links=/wheels \
    requests==2.31.0 \
    elasticsearch==8.13.0 \
    python-dotenv==1.0.1
COPY . .
CMD ["python", "scanner.py"]
