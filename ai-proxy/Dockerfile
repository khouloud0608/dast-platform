FROM python:3.11-slim
WORKDIR /app
 
# Wheels-based install to match the project's DNS-workaround pattern.
# Run on the VM first:  pip3 download flask requests -d ai-proxy/wheels
COPY wheels/ /wheels/
RUN pip install --no-cache-dir --no-index --find-links=/wheels \
    flask requests
 
COPY proxy.py .
CMD ["python", "proxy.py"]
