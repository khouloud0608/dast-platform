FROM python:3.11-slim
WORKDIR /app
COPY wheels/ /wheels/
RUN pip install --no-cache-dir --no-index --find-links=/wheels \
    fpdf2==2.7.9 \
    jinja2==3.1.3 \
    elasticsearch==8.13.0 \
    python-dotenv==1.0.1
COPY . .
CMD ["python", "report.py"]
