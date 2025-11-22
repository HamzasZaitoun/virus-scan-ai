#!/bin/bash
set -e

echo "🚀 Starting ViruScan AI Backend..."

echo "⏳ Waiting for PostgreSQL..."
until PGPASSWORD=$POSTGRES_PASSWORD psql -h db -U $POSTGRES_USER -d $POSTGRES_DB -c '\q' 2>/dev/null; do
  echo "   PostgreSQL unavailable - sleeping"
  sleep 2
done

echo "✅ PostgreSQL ready!"

if [ ! -d "migrations" ]; then
    echo "🔧 Initializing Flask-Migrate..."
    flask db init
fi

echo "📝 Running database migrations..."
flask db upgrade || {
    echo "⚠️  No migrations, creating initial..."
    flask db migrate -m "Initial migration"
    flask db upgrade
}

echo "✅ Migrations complete!"
echo "🌐 Starting Gunicorn..."

exec gunicorn \
    --bind 0.0.0.0:8000 \
    --workers ${WORKERS:-4} \
    --threads ${THREADS:-2} \
    --timeout ${TIMEOUT:-120} \
    --access-logfile - \
    --error-logfile - \
    --log-level info \
    app:app
```

---

## File 9: `backend/.dockerignore`
```
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
venv/
env/
ENV/
*.egg-info/
.pytest_cache/
*.db
*.sqlite
*.sqlite3
viruscan.db
.env.local
.vscode/
.idea/
*.swp
*.swo
*~
.DS_Store
.git/
.gitignore
*.md
docs/
tests/
*.log
logs/
migrations/
Dockerfile
.dockerignore
docker-compose*.yml
*.bak
*.backup
backup*.sql
```

---

## File 10: `backend/.gitignore`
```
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
venv/
env/
ENV/
build/
dist/
*.egg-info/
.pytest_cache/
*.db
*.sqlite
*.sqlite3
viruscan.db
.env
.env.local
.env.production
.vscode/
.idea/
*.swp
*.swo
*~
.DS_Store
*.log
logs/
docker-compose.override.yml
migrations/__pycache__/
migrations/versions/__pycache__/
*.bak
*.backup
backup.sql
uploads/*
!uploads/.gitkeep