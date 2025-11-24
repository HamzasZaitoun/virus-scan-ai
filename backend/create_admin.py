#!/usr/bin/env python3
"""
Create an admin user for ViruScan AI
Run this script to create your first admin account
"""

import os
import sys
from werkzeug.security import generate_password_hash

# Set up Flask app context
os.environ.setdefault('DATABASE_URL', 
    'postgresql://viruscan_user:viruscan_pass_2024@db:5432/viruscan_db'
)
try:
    from app import app, db
    from models import User
except ImportError as e:
    print(f"❌ Error importing modules: {e}")
    print("Make sure you're in the project directory and dependencies are installed.")
    sys.exit(1)

def create_admin():
    """Create admin user"""
    with app.app_context():
        try:
            # Check if admin already exists
            admin = User.query.filter_by(email='admin@viruscan.com').first()
            
            if admin:
                print("⚠️  Admin user already exists!")
                print(f"   Email: admin@viruscan.com")
                print("\n   If you need to reset the password, delete the user first:")
                print("   1. Open Adminer at http://localhost:8081")
                print("   2. Login to database")
                print("   3. Delete admin user from 'users' table")
                print("   4. Run this script again")
                return
            
            # Create admin user
            admin = User(
                email='admin@viruscan.com',
                full_name='Admin User',
                phone='+962 7 XXX XXXX',
                password_hash=generate_password_hash('admin123'),
                is_admin=True
            )
            
            db.session.add(admin)
            db.session.commit()
            
            print("✅ Admin user created successfully!")
            print("=" * 60)
            print("Email:    admin@viruscan.com")
            print("Password: admin123")
            print("=" * 60)
            print("⚠️  IMPORTANT: Change this password after first login!")
            print("\n📌 To login:")
            print("   1. Open index.html in your browser")
            print("   2. Click the 'Admin' button")
            print("   3. Use the credentials above")
            print("\n🔒 To change password later:")
            print("   - Access admin dashboard")
            print("   - Or manually update in database")
            
        except Exception as e:
            print(f"❌ Error creating admin user: {e}")
            print("\nTroubleshooting:")
            print("1. Make sure PostgreSQL is running:")
            print("   docker-compose up -d db")
            print("2. Make sure database is migrated:")
            print("   flask db upgrade")
            print("3. Check DATABASE_URL environment variable")
            sys.exit(1)

if __name__ == "__main__":
    print("Creating admin user for ViruScan AI...")
    print("-" * 60)
    create_admin()