FROM python:3.13-slim

RUN groupadd -r appuser && useradd -r -g appuser appuser

WORKDIR /app

ENV PYTHONPATH=/app
ENV PROMETHEUS_MULTIPROC_DIR=/app/prometheus_multiproc_dir

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
&& rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r requirements.txt

COPY app/ .

COPY app/jwt_public.pem .

# Create and set permissions for Prometheus multi-worker telemetry directory
RUN mkdir -p /app/prometheus_multiproc_dir && chown -R appuser:appuser /app

USER appuser

EXPOSE 7010

CMD ["gunicorn", "app:app", "-k", "uvicorn.workers.UvicornWorker", "--workers", "2", "--bind", "0.0.0.0:7010"]
