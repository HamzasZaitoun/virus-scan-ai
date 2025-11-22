#!/usr/bin/env python3
"""Migrate data from SQLite to PostgreSQL"""

import sqlite3
import json
from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import Scan
import os

SQLITE_DB = "viruscan.db"
POSTGRES_URL = os.getenv('DATABASE_URL', 'postgresql://viruscan_user:viruscan_pass_2024@localhost:5432/viruscan_db')

def migrate_scans():
    if not os.path.exists(SQLITE_DB):
        print(f"❌ SQLite database '{SQLITE_DB}' not found")
        return
    
    print(f"📂 Found SQLite database: {SQLITE_DB}")
    
    sqlite_conn = sqlite3.connect(SQLITE_DB)
    sqlite_conn.row_factory = sqlite3.Row
    cursor = sqlite_conn.cursor()
    
    engine = create_engine(POSTGRES_URL)
    Session = sessionmaker(bind=engine)
    pg_session = Session()
    
    try:
        cursor.execute("SELECT * FROM scans ORDER BY id")
        rows = cursor.fetchall()
        
        print(f"📊 Found {len(rows)} scans to migrate")
        
        migrated = 0
        
        for row in rows:
            try:
                reasons = json.loads(row['reasons']) if row['reasons'] else []
                solutions = json.loads(row['solutions']) if row['solutions'] else []
                created_at = datetime.fromisoformat(row['created_at'])
                
                scan = Scan(
                    target_type=row['target_type'],
                    target_value=row['target_value'],
                    label=row['label'],
                    risk_score=row['risk_score'],
                    reasons=reasons,
                    solutions=solutions,
                    created_at=created_at,
                    client_ip="migrated"
                )
                
                pg_session.add(scan)
                migrated += 1
                
                if migrated % 100 == 0:
                    pg_session.commit()
                    print(f"   ✅ Migrated {migrated} scans...")
                
            except Exception as e:
                print(f"   ⚠️  Skipped scan {row['id']}: {e}")
                continue
        
        pg_session.commit()
        print(f"\n✅ Migration Complete! Migrated {migrated} scans")
        
    except Exception as e:
        print(f"\n❌ Migration failed: {e}")
        pg_session.rollback()
        
    finally:
        sqlite_conn.close()
        pg_session.close()

if __name__ == "__main__":
    migrate_scans()