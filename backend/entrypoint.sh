#!/bin/bash
set -e

echo "🚀 Starting ViruScan AI Backend..."

if ! command -v psql &> /dev/null ; then
  echo "❌ psql not found! Did you install postgresql-client?"
  exit 1
fi

echo "⏳ Waiting for PostgreSQL..."
until PGPASSWORD="$POSTGRES_PASSWORD" psql \
      -h db \
      -U "$POSTGRES_USER" \
      -d "$POSTGRES_DB" \
      -c '\q' 2>/dev/null; do
  echo "   Database not ready yet..."
  sleep 2
done

echo "✅ PostgreSQL ready!"

if [ ! -d "/app/migrations/versions" ]; then
    echo "📁 Initializing migrations..."
    flask db init
fi

echo "📝 Running database migrations..."
flask db migrate -m "auto" || true
flask db upgrade

echo "👤 Ensuring admin user exists..."
python create_admin.py || true

echo "🌐 Starting Gunicorn..."
exec gunicorn --bind 0.0.0.0:8000 --workers 4 app:app
