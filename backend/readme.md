# ViruScan AI - Complete Installation Guide

## 📋 Files You Need

Place all these files in your `backend/` directory:

```
backend/
├── app.py                              # ✅ Main Flask application (NEW)
├── models.py                           # ✅ Database models (NEW)
├── config.py                           # ✅ Configuration (NEW)
├── requirements.txt                    # ✅ Python dependencies (NEW)
├── .env                                # ✅ Environment variables (NEW)
├── docker-compose.yml                  # ✅ Docker setup (NEW)
├── migrate_sqlite_to_postgres.py       # ✅ Data migration tool (NEW)
├── .gitignore                          # ✅ Git ignore rules (NEW)
└── (migrations/ folder will be created automatically)
```

Optional files (project root):

```
├── setup.sh                            # ✅ Linux/Mac setup script
├── setup.bat                           # ✅ Windows setup script
├── Makefile                            # ✅ Easy commands (optional)
├── README_POSTGRES.md                  # ✅ Detailed documentation
└── QUICK_REFERENCE.md                  # ✅ Quick command reference
```

---

## 🚀 Installation (Choose Your Method)

### Method 1: Automatic Setup (Recommended)

#### **Linux/Mac:**

```bash
chmod +x setup.sh
./setup.sh
```

#### **Windows:**

```cmd
setup.bat
```

#### **Using Makefile (Linux/Mac only):**

```bash
make setup
```

### Method 2: Manual Setup

#### Step 1: Start PostgreSQL

```bash
cd backend
docker-compose up -d
```

#### Step 2: Create Virtual Environment

```bash
# Linux/Mac
python3 -m venv venv
source venv/bin/activate

# Windows
python -m venv venv
venv\Scripts\activate
```

#### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

#### Step 4: Initialize Database

```bash
flask db init
flask db migrate -m "Initial migration"
flask db upgrade
```

#### Step 5: Start Flask App

```bash
python app.py
```

---

## ✅ Verify Installation

### 1. Check Services Running

```bash
docker ps
# Should see: viruscan_db and viruscan_adminer
```

### 2. Check Database Connection

```bash
curl http://localhost:8000/health
# Should return: {"status":"healthy","database":"connected"}
```

### 3. Test API

```bash
curl -X POST http://localhost:8000/api/scan/url \
  -H "Content-Type: application/json" \
  -d '{"url":"http://test.tk"}'
```

### 4. Open Adminer

Visit: http://localhost:8081

- Server: **db**
- Username: **viruscan_user**
- Password: **viruscan_pass_2024**
- Database: **viruscan_db**

---

## 🔄 Migrating Existing Data

If you have an old SQLite database (`viruscan.db`):

```bash
# Make sure PostgreSQL is running
docker-compose up -d

# Activate virtual environment
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

# Run migration script
python migrate_sqlite_to_postgres.py
```

This will:

- ✅ Read all scans from SQLite
- ✅ Convert and insert into PostgreSQL
- ✅ Verify the migration
- ✅ Show statistics

---

## 🎯 Quick Start Commands

### Using Makefile (Linux/Mac)

```bash
make start              # Start services
make stop               # Stop services
make logs               # View logs
make db-shell           # Open database shell
make migrate            # Create and apply migration
make backup             # Backup database
make test               # Test API
make help               # See all commands
```

### Manual Commands

```bash
# Start PostgreSQL
cd backend
docker-compose up -d

# Start Flask (in separate terminal)
cd backend
source venv/bin/activate  # or venv\Scripts\activate on Windows
python app.py

# Stop PostgreSQL
docker-compose down
```

---

## 📊 Accessing Your Data

### Web Interface (Adminer)

1. Open: http://localhost:8081
2. Login with credentials above
3. Browse tables, run queries, export data

### Command Line (psql)

```bash
docker exec -it viruscan_db psql -U viruscan_user -d viruscan_db

# Example queries:
SELECT COUNT(*) FROM scans;
SELECT * FROM scans ORDER BY created_at DESC LIMIT 10;
\dt          # List tables
\q           # Exit
```

### API Endpoints

```bash
# Get scan history
curl http://localhost:8000/api/history

# Get admin stats
curl http://localhost:8000/api/admin/stats

# Get feedback
curl http://localhost:8000/api/feedback
```

---

## 🔧 Configuration

### Change Database Password

Edit `docker-compose.yml` and `.env`:

```yaml
# docker-compose.yml
POSTGRES_PASSWORD: your_new_password

# .env
DATABASE_URL=postgresql://viruscan_user:your_new_password@localhost:5432/viruscan_db
```

Then restart:

```bash
docker-compose down -v
docker-compose up -d
flask db upgrade
```

### Change Port

Edit `docker-compose.yml`:

```yaml
ports:
  - "5433:5432" # Change 5432 to 5433
```

Update `.env`:

```bash
DATABASE_URL=postgresql://viruscan_user:pass@localhost:5433/viruscan_db
```

---

## 🐛 Troubleshooting

### Problem: "Port 5432 already in use"

**Solution:**

```bash
# Option 1: Stop other PostgreSQL
sudo systemctl stop postgresql

# Option 2: Change port (see Configuration section)
```

### Problem: "Cannot connect to database"

**Solution:**

```bash
# Check if container is running
docker ps

# Check logs
docker-compose logs db

# Restart container
docker-compose restart db

# Wait a few seconds and try again
```

### Problem: "Migration failed"

**Solution:**

```bash
# Reset migrations
rm -rf migrations/
flask db init
flask db migrate -m "Fresh start"
flask db upgrade
```

### Problem: "Module not found"

**Solution:**

```bash
# Make sure virtual environment is activated
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

# Reinstall dependencies
pip install -r requirements.txt
```

### Problem: "Docker not found"

**Solution:**

1. Install Docker Desktop: https://www.docker.com/products/docker-desktop
2. Start Docker Desktop
3. Wait for it to fully start
4. Try again

---

## 📦 What Changed from SQLite?

### Backend Changes

| Old (SQLite)        | New (PostgreSQL)     |
| ------------------- | -------------------- |
| `sqlite3.connect()` | SQLAlchemy ORM       |
| `cursor.execute()`  | `db.session.query()` |
| JSON as TEXT        | Native JSON type     |
| Manual schema       | Flask-Migrate        |
| File-based          | Docker container     |

### Frontend Changes

**Good news:** Frontend needs NO changes!

- API endpoints remain the same
- Response format is identical
- Just update the base URL if needed

### New Features

✅ Better concurrent access  
✅ JSON column type (faster queries)  
✅ Automatic migrations  
✅ Web-based database manager (Adminer)  
✅ Easy backup/restore  
✅ Better indexing  
✅ Support for production deployment

---

## 🚀 Next Steps

1. ✅ Verify installation works
2. ✅ Migrate old data (if any)
3. ✅ Test all API endpoints
4. ✅ Update frontend (if base URL changed)
5. ✅ Set up regular backups
6. ✅ Change default passwords
7. ✅ Read QUICK_REFERENCE.md for daily commands

---

## 📚 Additional Resources

- **Detailed Guide:** README_POSTGRES.md
- **Quick Commands:** QUICK_REFERENCE.md
- **Flask-SQLAlchemy:** https://flask-sqlalchemy.palletsprojects.com/
- **Flask-Migrate:** https://flask-migrate.readthedocs.io/
- **PostgreSQL:** https://www.postgresql.org/docs/

---

## 💡 Pro Tips

1. **Use Makefile** for easier management (Linux/Mac)
2. **Set up aliases** for common commands:
   ```bash
   alias vs-start="cd backend && docker-compose up -d"
   alias vs-stop="cd backend && docker-compose down"
   alias vs-logs="cd backend && docker-compose logs -f"
   ```
3. **Regular backups:** Run `make backup` daily
4. **Monitor logs:** Use `docker-compose logs -f` to debug issues
5. **Use Adminer:** Great for debugging and exploring data

---

## ✅ Installation Checklist

- [ ] Docker & Docker Compose installed
- [ ] Python 3.8+ installed
- [ ] All files placed in `backend/` directory
- [ ] Setup script executed successfully
- [ ] PostgreSQL container running (`docker ps`)
- [ ] Flask app starts without errors
- [ ] Health check returns "healthy"
- [ ] Adminer accessible at http://localhost:8081
- [ ] Can create and view scans
- [ ] Old data migrated (if applicable)

---

**🎉 You're all set! Your ViruScan AI is now running on PostgreSQL!**

For daily usage, see: **QUICK_REFERENCE.md**
