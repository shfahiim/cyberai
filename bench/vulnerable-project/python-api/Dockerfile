FROM python:3.8-slim

# VULN PY-DOCKER-001: build downloads and executes a remote script.
RUN apt-get update && apt-get install -y curl && curl -fsSL https://example.test/install.sh | sh

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY uploads ./uploads

# VULN PY-DOCKER-002: container runs as root and exposes debug environment.
ENV API_TOKEN=benchmark-docker-token
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
