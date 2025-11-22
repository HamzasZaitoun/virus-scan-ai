FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install only essential packages
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py models.py config.py ./

RUN mkdir -p /app/uploads /app/migrations && \
    useradd -m -u 1000 appuser && \
    chown -R appuser:appuser /app

USER appuser
EXPOSE 8000

CMD ["sh", "-c", "sleep 10 && (flask db upgrade || (flask db init && flask db migrate -m 'Initial' && flask db upgrade)) && gunicorn --bind 0.0.0.0:8000 --workers 4 --timeout 120 --access-logfile - --error-logfile - app:app"]